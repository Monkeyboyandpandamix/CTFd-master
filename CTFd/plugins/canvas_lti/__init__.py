import base64
import hashlib
import json
import secrets
import time
from pathlib import Path
from urllib.parse import urlencode

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from flask import Blueprint, abort, current_app, jsonify, redirect, render_template_string
from flask import request, session, url_for

from CTFd.cache import cache, clear_config, clear_team_session, clear_user_session
from CTFd.models import Teams, Users, db
from CTFd.plugins import bypass_csrf_protection, register_admin_plugin_menu_bar
from CTFd.utils import get_config, set_config
from CTFd.utils.config import is_teams_mode
from CTFd.utils.decorators import admins_only
from CTFd.utils.security.auth import login_user

PLUGIN_NAME = "canvas_lti"
PLUGIN_DIR = Path(__file__).resolve().parent
CONFIG_TEMPLATE = PLUGIN_DIR / "config.html"

LTI_DEPLOYMENT_CLAIM = "https://purl.imsglobal.org/spec/lti/claim/deployment_id"
LTI_VERSION_CLAIM = "https://purl.imsglobal.org/spec/lti/claim/version"
LTI_MESSAGE_TYPE_CLAIM = "https://purl.imsglobal.org/spec/lti/claim/message_type"
LTI_ROLES_CLAIM = "https://purl.imsglobal.org/spec/lti/claim/roles"
LTI_CONTEXT_CLAIM = "https://purl.imsglobal.org/spec/lti/claim/context"
LTI_DL_SETTINGS_CLAIM = (
    "https://purl.imsglobal.org/spec/lti-dl/claim/deep_linking_settings"
)
LTI_NRPS_CLAIM = "https://purl.imsglobal.org/spec/lti-nrps/claim/namesroleservice"
LTI_AGS_CLAIM = "https://purl.imsglobal.org/spec/lti-ags/claim/endpoint"
LTI_RESOURCE_LINK_REQUEST = "LtiResourceLinkRequest"
LTI_DEEP_LINKING_REQUEST = "LtiDeepLinkingRequest"
CANVAS_SCOPES = [
    "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem",
    "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem.readonly",
    "https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly",
    "https://purl.imsglobal.org/spec/lti-ags/scope/score",
    "https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly",
]


def _cfg(key, default=None):
    return get_config(f"canvas_lti_{key}", default=default)


def _set_cfg(key, value):
    return set_config(f"canvas_lti_{key}", value)


def _b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(value):
    value = value.encode() if isinstance(value, str) else value
    padding_size = (4 - (len(value) % 4)) % 4
    return base64.urlsafe_b64decode(value + (b"=" * padding_size))


def _json_b64(data):
    return _b64url_encode(json.dumps(data, separators=(",", ":"), sort_keys=True).encode())


def _now():
    return int(time.time())


def _plugin_base_url():
    configured = _cfg("tool_base_url")
    if configured:
        return configured.rstrip("/")
    return request.url_root.rstrip("/")


def _detected_request_base_url():
    return request.url_root.rstrip("/")


def _effective_base_url_details():
    configured = _cfg("tool_base_url")
    detected = _detected_request_base_url()
    effective = configured.rstrip("/") if configured else detected
    source = "configured public URL" if configured else "current request URL"
    return {
        "effective": effective,
        "detected": detected,
        "configured": configured,
        "source": source,
        "is_public_https": effective.startswith("https://") and "localhost" not in effective,
    }


def _tool_origin():
    return _plugin_base_url().split("://", 1)[-1]


def _launch_url():
    return f"{_plugin_base_url()}{url_for('canvas_lti.launch')}"


def _login_url():
    return f"{_plugin_base_url()}{url_for('canvas_lti.oidc_login')}"


def _jwks_url():
    return f"{_plugin_base_url()}{url_for('canvas_lti.jwks')}"


def _canvas_config_url():
    return f"{_plugin_base_url()}{url_for('canvas_lti.canvas_config')}"


def _load_private_key():
    private_pem = _cfg("private_key_pem")
    if not private_pem:
        return None
    return serialization.load_pem_private_key(private_pem.encode(), password=None)


def _load_public_key():
    public_pem = _cfg("public_key_pem")
    if not public_pem:
        return None
    return serialization.load_pem_public_key(public_pem.encode())


def _int_to_b64(number):
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big")
    return _b64url_encode(raw)


def _ensure_keypair():
    if _cfg("private_key_pem") and _cfg("public_key_pem") and _cfg("key_id"):
        return

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    key_id = secrets.token_hex(12)
    _set_cfg("private_key_pem", private_pem)
    _set_cfg("public_key_pem", public_pem)
    _set_cfg("key_id", key_id)


def _public_jwk():
    public_key = _load_public_key()
    key_id = _cfg("key_id")
    if public_key is None or key_id is None:
        return None
    numbers = public_key.public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": key_id,
        "n": _int_to_b64(numbers.n),
        "e": _int_to_b64(numbers.e),
    }


def _jwt_sign(payload, private_key=None, headers=None):
    private_key = private_key or _load_private_key()
    if private_key is None:
        raise ValueError("Canvas LTI private key is not configured")
    headers = {"alg": "RS256", "typ": "JWT", "kid": _cfg("key_id"), **(headers or {})}
    signing_input = f"{_json_b64(headers)}.{_json_b64(payload)}".encode()
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input.decode()}.{_b64url_encode(signature)}"


def _jwt_parts(token):
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    signature = _b64url_decode(parts[2])
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    return header, payload, signature, signing_input


def _jwk_to_public_key(jwk):
    n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
    e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
    return rsa.RSAPublicNumbers(e=e, n=n).public_key()


def _fetch_canvas_jwks():
    jwks_url = _cfg("jwks_url")
    if not jwks_url:
        raise ValueError("Canvas JWKS URL is not configured")
    cache_key = "canvas_lti_jwks_" + hashlib.sha256(jwks_url.encode()).hexdigest()
    cached = cache.get(cache_key)
    if cached:
        return cached
    response = requests.get(jwks_url, timeout=5)
    response.raise_for_status()
    payload = response.json()
    cache.set(cache_key, payload, timeout=300)
    return payload


def _verify_canvas_jwt(token, expected_nonce):
    header, payload, signature, signing_input = _jwt_parts(token)
    if header.get("alg") != "RS256":
        raise ValueError("Unsupported JWT algorithm")

    jwks = _fetch_canvas_jwks()
    keys = jwks.get("keys", [])
    key = None
    if header.get("kid"):
        for candidate in keys:
            if candidate.get("kid") == header["kid"]:
                key = candidate
                break
    if key is None and len(keys) == 1:
        key = keys[0]
    if key is None:
        raise ValueError("No matching Canvas JWKS key found")

    public_key = _jwk_to_public_key(key)
    public_key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())

    issuer = _cfg("issuer")
    if issuer and payload.get("iss") != issuer:
        raise ValueError("Invalid LTI issuer")

    client_id = _cfg("client_id")
    aud = payload.get("aud")
    if isinstance(aud, list):
        if client_id not in aud:
            raise ValueError("Client ID is not present in audience")
        if len(aud) > 1 and payload.get("azp") != client_id:
            raise ValueError("Authorized party does not match client ID")
    elif aud != client_id:
        raise ValueError("Audience does not match client ID")

    now = _now()
    exp = int(payload.get("exp", 0))
    iat = int(payload.get("iat", 0))
    if exp and exp < now - 60:
        raise ValueError("LTI token is expired")
    if iat and iat > now + 60:
        raise ValueError("LTI token issued in the future")

    if expected_nonce and payload.get("nonce") != expected_nonce:
        raise ValueError("LTI nonce mismatch")

    deployment_id = _cfg("deployment_id")
    token_deployment_id = payload.get(LTI_DEPLOYMENT_CLAIM)
    if deployment_id and token_deployment_id != deployment_id:
        raise ValueError("Deployment ID mismatch")

    if payload.get(LTI_VERSION_CLAIM) != "1.3.0":
        raise ValueError("Unsupported LTI version")

    return payload


def _canvas_user_email(claims):
    raw = f"{claims.get('iss','')}|{_cfg('client_id','')}|{claims.get('sub','')}"
    digest = hashlib.sha256(raw.encode()).hexdigest()[:24]
    return f"canvas-lti-{digest}@lti.local"


def _canvas_user_name(claims):
    return (
        claims.get("name")
        or claims.get("given_name")
        or claims.get("email")
        or f"Canvas User {claims.get('sub', 'unknown')[:12]}"
    )


def _find_or_create_user(claims):
    email = _canvas_user_email(claims)
    user = Users.query.filter_by(email=email).first()
    if user is not None:
        if user.name != _canvas_user_name(claims):
            user.name = _canvas_user_name(claims)
            db.session.commit()
            clear_user_session(user_id=user.id)
        return user

    user = Users(
        name=_canvas_user_name(claims),
        email=email,
        password=secrets.token_urlsafe(32),
        verified=True,
    )
    db.session.add(user)
    db.session.commit()

    if is_teams_mode() and user.team_id is None:
        team_slug = hashlib.sha256(email.encode()).hexdigest()[:8]
        team_name = f"Canvas {user.name[:40]} {team_slug}"
        team = Teams(name=team_name, captain_id=user.id)
        team.members.append(user)
        db.session.add(team)
        db.session.commit()
        clear_team_session(team_id=team.id)

    clear_user_session(user_id=user.id)
    return user


def _launch_summary(claims):
    context = claims.get(LTI_CONTEXT_CLAIM) or {}
    return {
        "sub": claims.get("sub"),
        "name": claims.get("name"),
        "email": claims.get("email"),
        "roles": claims.get(LTI_ROLES_CLAIM, []),
        "context_title": context.get("title"),
        "context_label": context.get("label"),
        "deployment_id": claims.get(LTI_DEPLOYMENT_CLAIM),
        "message_type": claims.get(LTI_MESSAGE_TYPE_CLAIM),
        "nrps": claims.get(LTI_NRPS_CLAIM),
        "ags": claims.get(LTI_AGS_CLAIM),
    }


def _deep_link_response(claims):
    settings = claims.get(LTI_DL_SETTINGS_CLAIM) or {}
    return_url = settings.get("deep_link_return_url")
    if not return_url:
        raise ValueError("Deep linking return URL is missing")

    now = _now()
    content_item = {
        "type": "ltiResourceLink",
        "title": _cfg("tool_title", "CTFd"),
        "text": "Launch the integrated CTFd experience",
        "url": _launch_url(),
    }
    payload = {
        "iss": _cfg("client_id"),
        "aud": claims.get("iss"),
        "iat": now,
        "exp": now + 300,
        "nonce": secrets.token_urlsafe(16),
        "https://purl.imsglobal.org/spec/lti/claim/message_type": "LtiDeepLinkingResponse",
        "https://purl.imsglobal.org/spec/lti/claim/version": "1.3.0",
        "https://purl.imsglobal.org/spec/lti/claim/deployment_id": claims.get(
            LTI_DEPLOYMENT_CLAIM
        ),
        "https://purl.imsglobal.org/spec/lti-dl/claim/content_items": [content_item],
        "https://purl.imsglobal.org/spec/lti-dl/claim/data": settings.get("data"),
    }
    response_jwt = _jwt_sign(payload)
    return return_url, response_jwt


def _canvas_developer_key_config():
    tool_title = _cfg("tool_title", "CTFd")
    launch_url = _launch_url()
    return {
        "title": tool_title,
        "description": "CTFd exposed as an LTI 1.3 / LTI Advantage tool for Canvas.",
        "oidc_initiation_url": _login_url(),
        "target_link_uri": launch_url,
        "public_jwk_url": _jwks_url(),
        "scopes": CANVAS_SCOPES,
        "extensions": [
            {
                "platform": "canvas.instructure.com",
                "domain": _tool_origin(),
                "tool_id": "ctfd-canvas-lti",
                "settings": {
                    "text": tool_title,
                    "icon_url": None,
                    "placements": [
                        {
                            "placement": "course_navigation",
                            "message_type": LTI_RESOURCE_LINK_REQUEST,
                            "target_link_uri": launch_url,
                            "text": tool_title,
                            "enabled": True,
                        },
                        {
                            "placement": "assignment_selection",
                            "message_type": LTI_DEEP_LINKING_REQUEST,
                            "target_link_uri": launch_url,
                            "text": f"{tool_title} Deep Link",
                            "enabled": True,
                        },
                    ],
                },
            }
        ],
        "custom_fields": {
            "canvas_course_id": "$Canvas.course.id",
            "canvas_user_id": "$Canvas.user.id",
        },
    }


def _setup_checks():
    url_details = _effective_base_url_details()
    base_url = url_details["effective"]
    checks = [
        {
            "label": "Effective tool URL is public HTTPS",
            "ok": bool(base_url and url_details["is_public_https"]),
            "value": base_url or "Not set",
        },
        {
            "label": "Canvas issuer is set",
            "ok": bool(_cfg("issuer")),
            "value": _cfg("issuer") or "Not set",
        },
        {
            "label": "Canvas client ID is set",
            "ok": bool(_cfg("client_id")),
            "value": _cfg("client_id") or "Not set",
        },
        {
            "label": "Canvas deployment ID is set",
            "ok": bool(_cfg("deployment_id")),
            "value": _cfg("deployment_id") or "Not set",
        },
        {
            "label": "Canvas auth login URL is set",
            "ok": bool(_cfg("auth_login_url")),
            "value": _cfg("auth_login_url") or "Not set",
        },
        {
            "label": "Canvas JWKS URL is set",
            "ok": bool(_cfg("jwks_url")),
            "value": _cfg("jwks_url") or "Not set",
        },
    ]
    return checks


def _setup_summary():
    checks = _setup_checks()
    url_details = _effective_base_url_details()
    return {
        "ready": all(item["ok"] for item in checks),
        "checks": checks,
        "url_details": url_details,
        "warnings": [
            "Canvas cannot launch a localhost-only tool. Use Public Tool Base URL to override the detected URL with a public HTTPS address."
            if not url_details["is_public_https"]
            else None,
            "Client ID and Deployment ID are created by Canvas after installation. Paste them back here after installing the app."
            if not (_cfg("client_id") and _cfg("deployment_id"))
            else None,
        ],
    }


def _setup_steps():
    details = _effective_base_url_details()
    return [
        {
            "title": "Confirm the tool URL Canvas will use",
            "body": (
                f"Effective tool URL: {details['effective']}. "
                f"This page is currently using the {details['source']} for all Canvas instructions."
            ),
        },
        {
            "title": "Make the tool publicly reachable over HTTPS",
            "body": (
                "If the effective URL above is localhost or plain HTTP, publish this app behind a public HTTPS URL "
                "and put that value into Public Tool Base URL. The Canvas JSON and all endpoint instructions below update automatically."
            ),
        },
        {
            "title": "Create the Canvas Developer Key",
            "body": (
                f"In Canvas, create or edit a Developer Key and use this JSON config URL: {_canvas_config_url()}"
            ),
        },
        {
            "title": "Install the app in Canvas",
            "body": (
                "Install the LTI app in the target Canvas account or course. Canvas will generate the Client ID, "
                "and the installation flow will provide a Deployment ID."
            ),
        },
        {
            "title": "Paste the Canvas values back here",
            "body": (
                "Fill in Canvas Client ID and Canvas Deployment ID in this page, then save. "
                f"Keep issuer, auth login URL, and Canvas JWKS aligned with the same Canvas environment."
            ),
        },
        {
            "title": "Launch and verify",
            "body": (
                f"Launch the tool from Canvas. Canvas should initiate OIDC login at {_login_url()} and post the final launch to {_launch_url()}. "
                "After a successful launch, this admin page will show the latest launch details."
            ),
        },
    ]


canvas_lti = Blueprint("canvas_lti", __name__)


@canvas_lti.route("/admin/canvas-lti", methods=["GET", "POST"])
@admins_only
@bypass_csrf_protection
def admin_panel():
    if request.method == "POST":
        if request.form.get("rotate_keys") == "1":
            _set_cfg("private_key_pem", None)
            _set_cfg("public_key_pem", None)
            _set_cfg("key_id", None)
            _ensure_keypair()

        for key in [
            "tool_title",
            "tool_base_url",
            "issuer",
            "client_id",
            "deployment_id",
            "auth_login_url",
            "jwks_url",
        ]:
            _set_cfg(key, request.form.get(key, "").strip() or None)
        clear_config()
        cache.delete("canvas_lti_last_launch")
        return redirect(url_for("canvas_lti.admin_panel"))

    _ensure_keypair()
    launch = cache.get("canvas_lti_last_launch")
    setup = _setup_summary()
    canvas_json = json.dumps(_canvas_developer_key_config(), indent=2)
    steps = _setup_steps()
    template = CONFIG_TEMPLATE.read_text(encoding="utf-8")
    return render_template_string(
        template,
        tool_title=_cfg("tool_title", "CTFd"),
        tool_base_url=_cfg("tool_base_url", ""),
        issuer=_cfg("issuer", "https://canvas.instructure.com"),
        client_id=_cfg("client_id", ""),
        deployment_id=_cfg("deployment_id", ""),
        auth_login_url=_cfg("auth_login_url", "https://sso.canvaslms.com/api/lti/authorize_redirect"),
        jwks_url=_cfg("jwks_url", "https://sso.canvaslms.com/api/lti/security/jwks"),
        key_id=_cfg("key_id", ""),
        login_url=_login_url(),
        launch_url=_launch_url(),
        jwks_url_public=_jwks_url(),
        canvas_config_url=_canvas_config_url(),
        last_launch=launch,
        setup=setup,
        steps=steps,
        canvas_json=canvas_json,
    )


@canvas_lti.route("/plugins/canvas_lti/.well-known/jwks.json", methods=["GET"])
def jwks():
    _ensure_keypair()
    return jsonify({"keys": [_public_jwk()]})


@canvas_lti.route("/plugins/canvas_lti/canvas-config.json", methods=["GET"])
def canvas_config():
    _ensure_keypair()
    return jsonify(_canvas_developer_key_config())


@canvas_lti.route("/plugins/canvas_lti/status", methods=["GET"])
def status():
    return jsonify(
        {
            "configured": bool(_cfg("client_id") and _cfg("issuer") and _cfg("deployment_id")),
            "login_url": _login_url(),
            "launch_url": _launch_url(),
            "jwks_url": _jwks_url(),
            "canvas_config_url": _canvas_config_url(),
            "setup": _setup_summary(),
        }
    )


@canvas_lti.route("/plugins/canvas_lti/login", methods=["GET", "POST"])
@bypass_csrf_protection
def oidc_login():
    if not _cfg("client_id") or not _cfg("auth_login_url") or not _cfg("issuer"):
        abort(503, description="Canvas LTI plugin is not configured")

    login_hint = request.values.get("login_hint")
    if not login_hint:
        abort(400, description="Missing login_hint")

    target_link_uri = request.values.get("target_link_uri") or _launch_url()
    if target_link_uri != _launch_url():
        abort(400, description="Unexpected target_link_uri")

    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    session["canvas_lti_state"] = state
    session["canvas_lti_nonce"] = nonce
    session["canvas_lti_target_link_uri"] = target_link_uri

    params = {
        "scope": "openid",
        "response_type": "id_token",
        "response_mode": "form_post",
        "prompt": "none",
        "client_id": _cfg("client_id"),
        "redirect_uri": _launch_url(),
        "login_hint": login_hint,
        "state": state,
        "nonce": nonce,
    }
    if request.values.get("lti_message_hint"):
        params["lti_message_hint"] = request.values["lti_message_hint"]
    return redirect(f"{_cfg('auth_login_url')}?{urlencode(params)}")


@canvas_lti.route("/plugins/canvas_lti/launch", methods=["POST"])
@bypass_csrf_protection
def launch():
    if session.get("canvas_lti_state") != request.form.get("state"):
        abort(400, description="Canvas LTI state mismatch")

    id_token = request.form.get("id_token")
    if not id_token:
        abort(400, description="Missing id_token")

    claims = _verify_canvas_jwt(id_token, expected_nonce=session.get("canvas_lti_nonce"))
    cache.set("canvas_lti_last_launch", _launch_summary(claims), timeout=86400)

    session["canvas_lti_claims"] = _launch_summary(claims)
    session.pop("canvas_lti_state", None)
    session.pop("canvas_lti_nonce", None)

    message_type = claims.get(LTI_MESSAGE_TYPE_CLAIM)
    if message_type == LTI_DEEP_LINKING_REQUEST:
        return_url, response_jwt = _deep_link_response(claims)
        return render_template_string(
            """
            <!doctype html>
            <html>
            <body onload="document.forms[0].submit()">
              <form method="POST" action="{{ return_url }}">
                <input type="hidden" name="JWT" value="{{ response_jwt }}">
                <noscript><button type="submit">Continue back to Canvas</button></noscript>
              </form>
            </body>
            </html>
            """,
            return_url=return_url,
            response_jwt=response_jwt,
        )

    user = _find_or_create_user(claims)
    login_user(user)
    return redirect(url_for("challenges.listing"))


def load(app):
    _ensure_keypair()
    app.register_blueprint(canvas_lti)
    register_admin_plugin_menu_bar("Canvas LTI", "/admin/canvas-lti")
