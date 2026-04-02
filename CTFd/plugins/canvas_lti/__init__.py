import base64
import hashlib
import json
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode, urlsplit

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from flask import Blueprint, abort, current_app, jsonify, redirect, render_template_string
from flask import request, session, url_for
from sqlalchemy import and_

from CTFd.cache import cache, clear_config, clear_team_session, clear_user_session
from CTFd.models import Brackets, Challenges, Teams, Users, db
from CTFd.plugins import bypass_csrf_protection, register_admin_plugin_menu_bar
from CTFd.plugins.challenges import BaseChallenge
from CTFd.utils import get_config, set_config
from CTFd.utils.config import is_teams_mode
from CTFd.utils.decorators import admins_only
from CTFd.utils.security.auth import login_user
from CTFd.utils.user import authed, get_current_user

PLUGIN_NAME = "canvas_lti"
PLUGIN_DIR = Path(__file__).resolve().parent
CONFIG_TEMPLATE = PLUGIN_DIR / "config.html"

LTI_DEPLOYMENT_CLAIM = "https://purl.imsglobal.org/spec/lti/claim/deployment_id"
LTI_VERSION_CLAIM = "https://purl.imsglobal.org/spec/lti/claim/version"
LTI_MESSAGE_TYPE_CLAIM = "https://purl.imsglobal.org/spec/lti/claim/message_type"
LTI_ROLES_CLAIM = "https://purl.imsglobal.org/spec/lti/claim/roles"
LTI_CONTEXT_CLAIM = "https://purl.imsglobal.org/spec/lti/claim/context"
LTI_CUSTOM_CLAIM = "https://purl.imsglobal.org/spec/lti/claim/custom"
LTI_RESOURCE_LINK_CLAIM = "https://purl.imsglobal.org/spec/lti/claim/resource_link"
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


class CanvasLTILaunch(db.Model):
    __tablename__ = "canvas_lti_launches"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"))
    team_id = db.Column(db.Integer, db.ForeignKey("teams.id", ondelete="SET NULL"))
    issuer = db.Column(db.String(255))
    deployment_id = db.Column(db.String(255))
    lti_user_id = db.Column(db.String(255))
    canvas_user_id = db.Column(db.String(255))
    course_id = db.Column(db.String(255), index=True)
    context_title = db.Column(db.String(255))
    resource_link_id = db.Column(db.String(255))
    ags_endpoint_json = db.Column(db.Text)
    nrps_claim_json = db.Column(db.Text)
    lineitem_url = db.Column(db.Text)
    lineitems_url = db.Column(db.Text)
    last_grade_sync = db.Column(db.DateTime)
    last_grade_error = db.Column(db.Text)
    last_login_at = db.Column(db.DateTime)
    created = db.Column(db.DateTime, default=datetime.utcnow)
    updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


def _cfg(key, default=None):
    return get_config(f"canvas_lti_{key}", default=default)


def _set_cfg(key, value):
    return set_config(f"canvas_lti_{key}", value)


def _cfg_bool(key, default=False):
    value = _cfg(key)
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(value):
    value = value.encode() if isinstance(value, str) else value
    padding_size = (4 - (len(value) % 4)) % 4
    return base64.urlsafe_b64decode(value + (b"=" * padding_size))


def _json_b64(data):
    return _b64url_encode(json.dumps(data, separators=(",", ":"), sort_keys=True).encode())


def _safe_json_loads(raw, default):
    if not raw:
        return default
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return default


def _json_dump(data):
    return json.dumps(data, separators=(",", ":"), sort_keys=True)


def _parse_lines(raw):
    values = []
    for part in (raw or "").replace(",", "\n").splitlines():
        part = part.strip()
        if part:
            values.append(part)
    return values


def _normalize_text(value):
    return str(value or "").strip().lower()


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
        "hostname": urlsplit(effective).hostname or "localhost",
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


def _token_url():
    return _cfg("token_url", "https://sso.canvaslms.com/login/oauth2/token")


def _issuer():
    return _cfg("issuer", "https://canvas.instructure.com")


def _auth_login_url():
    return _cfg(
        "auth_login_url",
        "https://sso.canvaslms.com/api/lti/authorize_redirect",
    )


def _canvas_jwks_url():
    return _cfg("jwks_url", "https://sso.canvaslms.com/api/lti/security/jwks")


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
    jwks_url = _canvas_jwks_url()
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

    issuer = _issuer()
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


def _canvas_custom_fields(claims):
    return claims.get(LTI_CUSTOM_CLAIM) or {}


def _course_id_from_claims(claims):
    context = claims.get(LTI_CONTEXT_CLAIM) or {}
    custom = _canvas_custom_fields(claims)
    return (
        custom.get("canvas_course_id")
        or context.get("id")
        or context.get("label")
        or None
    )


def _canvas_user_id_from_claims(claims):
    custom = _canvas_custom_fields(claims)
    return custom.get("canvas_user_id") or claims.get("sub")


def _context_title_from_claims(claims):
    context = claims.get(LTI_CONTEXT_CLAIM) or {}
    return context.get("title") or context.get("label") or None


def _resource_link_id_from_claims(claims):
    resource_link = claims.get(LTI_RESOURCE_LINK_CLAIM) or {}
    return resource_link.get("id")


def _allowed_courses():
    return set(_parse_lines(_cfg("allowed_course_ids", "")))


def _blocked_courses():
    return set(_parse_lines(_cfg("blocked_course_ids", "")))


def _course_allowed(course_id):
    if not course_id:
        return True
    allowed = _allowed_courses()
    blocked = _blocked_courses()
    if allowed and course_id not in allowed:
        return False
    if course_id in blocked:
        return False
    return True


def _course_rules():
    rules = _safe_json_loads(_cfg("course_rules_json"), {})
    return rules if isinstance(rules, dict) else {}


def _course_rule_bundle(course_id):
    rules = _course_rules()
    bundle = {}
    for key in ("default", "*", course_id):
        rule = rules.get(key)
        if isinstance(rule, dict):
            bundle.update(rule)
    return bundle


def _match_any(rule_values, candidate):
    normalized = {_normalize_text(value) for value in (rule_values or []) if str(value).strip()}
    if not normalized:
        return False
    return _normalize_text(candidate) in normalized


def _challenge_allowed_for_course_row(challenge_id, name, category, course_id):
    if not course_id:
        return True
    rule = _course_rule_bundle(course_id)
    if not rule:
        return True

    allowed_ids = {str(value).strip() for value in rule.get("allowed_challenge_ids", [])}
    allowed_names = {_normalize_text(value) for value in rule.get("allowed_challenge_names", [])}
    allowed_categories = {_normalize_text(value) for value in rule.get("allowed_categories", [])}
    disabled_ids = {str(value).strip() for value in rule.get("disabled_challenge_ids", [])}
    disabled_names = {_normalize_text(value) for value in rule.get("disabled_challenge_names", [])}
    disabled_categories = {_normalize_text(value) for value in rule.get("disabled_categories", [])}

    challenge_id = str(challenge_id)
    name = _normalize_text(name)
    category = _normalize_text(category)

    allow_rules_present = any([allowed_ids, allowed_names, allowed_categories])
    if allow_rules_present and not (
        challenge_id in allowed_ids or name in allowed_names or category in allowed_categories
    ):
        return False

    if challenge_id in disabled_ids or name in disabled_names or category in disabled_categories:
        return False

    return True


def _challenge_allowed_for_course(challenge, course_id):
    return _challenge_allowed_for_course_row(
        challenge.id,
        getattr(challenge, "name", ""),
        getattr(challenge, "category", ""),
        course_id,
    )


def _current_course_id():
    launch_claims = session.get("canvas_lti_claims") or {}
    course_id = launch_claims.get("course_id")
    if course_id:
        return course_id
    if authed():
        user = get_current_user()
        if user:
            launch = (
                CanvasLTILaunch.query.filter_by(user_id=user.id)
                .order_by(CanvasLTILaunch.updated.desc())
                .first()
            )
            if launch:
                return launch.course_id
    return None


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


def _ensure_course_bracket(user, course_id, context_title):
    if not _cfg_bool("auto_brackets_enabled", True) or not course_id:
        return

    bracket_type = "teams" if is_teams_mode() else "users"
    bracket_name = f"Canvas Course {course_id}"
    bracket = Brackets.query.filter_by(name=bracket_name, type=bracket_type).first()
    if bracket is None:
        bracket = Brackets(
            name=bracket_name,
            type=bracket_type,
            description=context_title or f"Canvas LTI synced course {course_id}",
        )
        db.session.add(bracket)
        db.session.commit()

    if bracket.description != (context_title or bracket.description):
        bracket.description = context_title or bracket.description
        db.session.commit()

    if is_teams_mode() and user.team_id:
        team = Teams.query.filter_by(id=user.team_id).first()
        if team and team.bracket_id != bracket.id:
            team.bracket_id = bracket.id
            db.session.commit()
            clear_team_session(team_id=team.id)
    elif user.bracket_id != bracket.id:
        user.bracket_id = bracket.id
        db.session.commit()
        clear_user_session(user_id=user.id)


def _launch_summary(claims):
    context = claims.get(LTI_CONTEXT_CLAIM) or {}
    ags = claims.get(LTI_AGS_CLAIM) or {}
    return {
        "sub": claims.get("sub"),
        "name": claims.get("name"),
        "email": claims.get("email"),
        "roles": claims.get(LTI_ROLES_CLAIM, []),
        "context_title": context.get("title"),
        "context_label": context.get("label"),
        "course_id": _course_id_from_claims(claims),
        "canvas_user_id": _canvas_user_id_from_claims(claims),
        "deployment_id": claims.get(LTI_DEPLOYMENT_CLAIM),
        "message_type": claims.get(LTI_MESSAGE_TYPE_CLAIM),
        "nrps": claims.get(LTI_NRPS_CLAIM),
        "ags": ags,
        "lineitem": ags.get("lineitem"),
        "lineitems": ags.get("lineitems"),
    }


def _save_launch(claims, user):
    course_id = _course_id_from_claims(claims)
    launch = (
        CanvasLTILaunch.query.filter_by(
            user_id=user.id,
            deployment_id=claims.get(LTI_DEPLOYMENT_CLAIM),
            course_id=course_id,
        )
        .order_by(CanvasLTILaunch.updated.desc())
        .first()
    )
    if launch is None:
        launch = CanvasLTILaunch(
            user_id=user.id,
            team_id=user.team_id,
            deployment_id=claims.get(LTI_DEPLOYMENT_CLAIM),
            course_id=course_id,
        )
        db.session.add(launch)

    ags = claims.get(LTI_AGS_CLAIM) or {}
    launch.team_id = user.team_id
    launch.issuer = claims.get("iss")
    launch.lti_user_id = claims.get("sub")
    launch.canvas_user_id = _canvas_user_id_from_claims(claims)
    launch.context_title = _context_title_from_claims(claims)
    launch.resource_link_id = _resource_link_id_from_claims(claims)
    launch.ags_endpoint_json = _json_dump(ags)
    launch.nrps_claim_json = _json_dump(claims.get(LTI_NRPS_CLAIM) or {})
    launch.lineitem_url = ags.get("lineitem") or launch.lineitem_url
    launch.lineitems_url = ags.get("lineitems") or launch.lineitems_url
    launch.last_login_at = datetime.utcnow()
    launch.updated = datetime.utcnow()
    db.session.commit()
    return launch


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
            "ok": bool(_issuer()),
            "value": _issuer() or "Not set",
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
            "ok": bool(_auth_login_url()),
            "value": _auth_login_url() or "Not set",
        },
        {
            "label": "Canvas token URL is set",
            "ok": bool(_token_url()),
            "value": _token_url() or "Not set",
        },
        {
            "label": "Canvas JWKS URL is set",
            "ok": bool(_canvas_jwks_url()),
            "value": _canvas_jwks_url() or "Not set",
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
            "Canvas AGS score sync is disabled. Enable it only after token URL, client ID, and deployment details are confirmed."
            if not _cfg_bool("ags_enabled")
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
                "Fill in Canvas Client ID, Canvas Deployment ID, issuer, auth login URL, token URL, and Canvas JWKS URL in this page, then save."
            ),
        },
        {
            "title": "Choose course/session controls",
            "body": (
                "Optionally restrict launches to specific Canvas course IDs, enable auto-bracket creation per course, "
                "and define course-specific challenge deactivation rules in JSON."
            ),
        },
        {
            "title": "Enable grade sync only if you want Canvas updated",
            "body": (
                "When AGS is enabled, the plugin can create or reuse a Canvas line item and push the user or team score after each solve."
            ),
        },
        {
            "title": "Launch and verify",
            "body": (
                f"Launch the tool from Canvas. Canvas should initiate OIDC login at {_login_url()} and post the final launch to {_launch_url()}. "
                "After a successful launch, this admin page will show the latest launch details and the latest grade-sync result."
            ),
        },
    ]


def _service_access_examples():
    host = _effective_base_url_details()["hostname"]
    scheme = "https" if _effective_base_url_details()["is_public_https"] else "http"
    return {
        "ctfd": f"{_plugin_base_url()}",
        "juice_shop": _cfg("service_juice_shop_url", f"{scheme}://{host}:3001"),
        "wrongsecrets": _cfg("service_wrongsecrets_url", f"{scheme}://{host}:8081"),
        "pico_web_css": _cfg("service_pico_web_css_url", f"{scheme}://{host}:8083"),
        "pico_artifacts": _cfg("service_pico_artifacts_url", f"{scheme}://{host}:8084/start-problem-dev"),
        "pico_ssh": f"ssh -p 2222 ctf-player@{host}",
        "pico_reversing": f"nc {host} 2223",
        "pico_perceptron": f"nc {host} 2224",
    }


def _ags_claim(launch):
    return _safe_json_loads(launch.ags_endpoint_json, {})


def _canvas_client_assertion():
    now = _now()
    payload = {
        "iss": _cfg("client_id"),
        "sub": _cfg("client_id"),
        "aud": _token_url(),
        "iat": now,
        "exp": now + 300,
        "jti": secrets.token_urlsafe(24),
    }
    return _jwt_sign(payload)


def _canvas_access_token():
    response = requests.post(
        _token_url(),
        data={
            "grant_type": "client_credentials",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": _canvas_client_assertion(),
            "scope": " ".join(CANVAS_SCOPES),
        },
        timeout=8,
    )
    response.raise_for_status()
    payload = response.json()
    token = payload.get("access_token")
    if not token:
        raise ValueError("Canvas token endpoint returned no access_token")
    return token


def _visible_challenge_total(course_id):
    challenges = Challenges.query.filter(
        and_(Challenges.state != "hidden", Challenges.state != "locked")
    ).all()
    total = 0
    for challenge in challenges:
        if _challenge_allowed_for_course(challenge, course_id):
            total += int(challenge.value or 0)
    return max(total, 1)


def _visible_challenge_count(course_id=None):
    challenges = Challenges.query.filter(
        and_(Challenges.state != "hidden", Challenges.state != "locked")
    ).all()
    return sum(1 for challenge in challenges if _challenge_allowed_for_course(challenge, course_id))


def _recent_launch_rows(limit=20):
    launches = (
        CanvasLTILaunch.query.order_by(CanvasLTILaunch.updated.desc()).limit(limit).all()
    )
    rows = []
    for launch in launches:
        user = Users.query.filter_by(id=launch.user_id).first()
        rows.append(
            {
                "user_id": launch.user_id,
                "user_name": user.name if user else "Unknown user",
                "user_email": user.email if user else "Unknown email",
                "course_id": launch.course_id,
                "context_title": launch.context_title,
                "canvas_user_id": launch.canvas_user_id,
                "deployment_id": launch.deployment_id,
                "last_login_at": launch.last_login_at.isoformat() if launch.last_login_at else None,
                "last_grade_sync": launch.last_grade_sync.isoformat() if launch.last_grade_sync else None,
                "last_grade_error": launch.last_grade_error,
                "lineitem_url": launch.lineitem_url,
            }
        )
    return rows


def _admin_control_summary():
    global_visible = _visible_challenge_count()
    allowed_courses = sorted(_allowed_courses())
    blocked_courses = sorted(_blocked_courses())
    sample_course_id = allowed_courses[0] if allowed_courses else None
    return {
        "global_visible_count": global_visible,
        "sample_course_id": sample_course_id,
        "sample_course_visible_count": _visible_challenge_count(sample_course_id)
        if sample_course_id
        else global_visible,
        "allowed_courses": allowed_courses,
        "blocked_courses": blocked_courses,
        "ags_enabled": _cfg_bool("ags_enabled"),
        "ags_sync_on_solve": _cfg_bool("ags_sync_on_solve"),
        "auto_brackets_enabled": _cfg_bool("auto_brackets_enabled", True),
        "respects_admin_visibility": True,
    }


def _score_for_account(user, team):
    if team is not None:
        return int(team.get_score(admin=True))
    return int(user.get_score(admin=True))


def _ensure_canvas_lineitem(launch, token):
    ags = _ags_claim(launch)
    if ags.get("lineitem"):
        if launch.lineitem_url != ags.get("lineitem"):
            launch.lineitem_url = ags.get("lineitem")
            db.session.commit()
        return launch.lineitem_url

    if launch.lineitem_url:
        return launch.lineitem_url

    lineitems_url = ags.get("lineitems") or launch.lineitems_url
    if not lineitems_url:
        raise ValueError("Canvas launch did not provide a lineitems endpoint")

    score_maximum = float(_visible_challenge_total(launch.course_id))
    response = requests.post(
        lineitems_url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.ims.lis.v2.lineitem+json",
            "Content-Type": "application/vnd.ims.lis.v2.lineitem+json",
        },
        json={
            "label": f"{_cfg('tool_title', 'CTFd')} Total Score",
            "tag": "ctfd-total-score",
            "resourceId": f"ctfd-course-{launch.course_id or 'default'}",
            "scoreMaximum": score_maximum,
        },
        timeout=8,
    )
    response.raise_for_status()
    body = response.json() if response.content else {}
    launch.lineitems_url = lineitems_url
    launch.lineitem_url = body.get("id") or response.headers.get("Location")
    db.session.commit()
    if not launch.lineitem_url:
        raise ValueError("Canvas line item creation did not return a line item URL")
    return launch.lineitem_url


def _post_canvas_score(launch, token, challenge, score_given, score_maximum):
    lineitem_url = _ensure_canvas_lineitem(launch, token)
    response = requests.post(
        f"{lineitem_url.rstrip('/')}/scores",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.ims.lis.v1.score+json",
            "Content-Type": "application/vnd.ims.lis.v1.score+json",
        },
        json={
            "userId": launch.lti_user_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scoreGiven": float(score_given),
            "scoreMaximum": float(score_maximum),
            "comment": f"CTFd updated after solving {challenge.name}",
            "activityProgress": "Completed",
            "gradingProgress": "FullyGraded",
        },
        timeout=8,
    )
    response.raise_for_status()
    launch.last_grade_sync = datetime.utcnow()
    launch.last_grade_error = None
    db.session.commit()


def _maybe_sync_canvas_grade(user, team, challenge):
    if not (_cfg_bool("ags_enabled") and _cfg_bool("ags_sync_on_solve")):
        return

    launch = (
        CanvasLTILaunch.query.filter_by(user_id=user.id)
        .order_by(CanvasLTILaunch.updated.desc())
        .first()
    )
    if launch is None:
        return

    try:
        token = _canvas_access_token()
        score_maximum = _visible_challenge_total(launch.course_id)
        score_given = _score_for_account(user, team)
        _post_canvas_score(launch, token, challenge, score_given, score_maximum)
    except Exception as exc:
        current_app.logger.exception("Canvas LTI AGS sync failed")
        if launch:
            launch.last_grade_error = str(exc)
            db.session.commit()


def sync_solve_to_canvas(user, team, challenge):
    _maybe_sync_canvas_grade(user=user, team=team, challenge=challenge)


def _wrap_challenge_api():
    import CTFd.api.v1.challenges as challenge_api

    if getattr(challenge_api, "_canvas_lti_patched", False):
        return

    original_list_get = challenge_api.ChallengeList.get
    original_get = challenge_api.Challenge.get
    original_attempt = challenge_api.ChallengeAttempt.post

    def wrapped_list_get(self, *args, **kwargs):
        response = original_list_get(self, *args, **kwargs)
        payload, status = (response[0], response[1]) if isinstance(response, tuple) else (response, None)
        if isinstance(payload, dict) and isinstance(payload.get("data"), list):
            course_id = _current_course_id()
            payload["data"] = [
                row
                for row in payload["data"]
                if _challenge_allowed_for_course_row(
                    row.get("id"), row.get("name"), row.get("category"), course_id
                )
            ]
        return (payload, status) if status else payload

    def wrapped_get(self, challenge_id):
        course_id = _current_course_id()
        if course_id:
            challenge = Challenges.query.filter_by(id=challenge_id).first()
            if challenge and not _challenge_allowed_for_course(challenge, course_id):
                abort(404)
        return original_get(self, challenge_id)

    def wrapped_attempt(self):
        request_data = request.get_json() if request.is_json else request.form
        challenge_id = request_data.get("challenge_id")
        course_id = _current_course_id()
        if course_id and challenge_id:
            challenge = Challenges.query.filter_by(id=challenge_id).first()
            if challenge and not _challenge_allowed_for_course(challenge, course_id):
                abort(403, description="This challenge is disabled for the current Canvas course")
        return original_attempt(self)

    challenge_api.ChallengeList.get = wrapped_list_get
    challenge_api.Challenge.get = wrapped_get
    challenge_api.ChallengeAttempt.post = wrapped_attempt
    challenge_api._canvas_lti_patched = True


def _wrap_challenge_solve():
    if getattr(BaseChallenge, "_canvas_lti_patched", False):
        return

    original_solve = BaseChallenge.solve.__func__

    def wrapped_solve(cls, user, team, challenge, request):
        result = original_solve(cls, user, team, challenge, request)
        sync_solve_to_canvas(user=user, team=team, challenge=challenge)
        return result

    BaseChallenge.solve = classmethod(wrapped_solve)
    BaseChallenge._canvas_lti_patched = True


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
            "token_url",
            "jwks_url",
            "allowed_course_ids",
            "blocked_course_ids",
            "course_rules_json",
        ]:
            _set_cfg(key, request.form.get(key, "").strip() or None)

        for key in ["ags_enabled", "ags_sync_on_solve", "auto_brackets_enabled"]:
            _set_cfg(key, request.form.get(key) == "1")

        clear_config()
        return redirect(url_for("canvas_lti.admin_panel"))

    _ensure_keypair()
    launch = cache.get("canvas_lti_last_launch")
    setup = _setup_summary()
    canvas_json = json.dumps(_canvas_developer_key_config(), indent=2)
    steps = _setup_steps()
    services = _service_access_examples()
    template = CONFIG_TEMPLATE.read_text(encoding="utf-8")
    latest_sync = (
        CanvasLTILaunch.query.order_by(CanvasLTILaunch.updated.desc()).first()
        if CanvasLTILaunch.query.count()
        else None
    )
    admin_summary = _admin_control_summary()
    recent_launches = _recent_launch_rows()
    return render_template_string(
        template,
        tool_title=_cfg("tool_title", "CTFd"),
        tool_base_url=_cfg("tool_base_url", ""),
        issuer=_cfg("issuer", "https://canvas.instructure.com"),
        client_id=_cfg("client_id", ""),
        deployment_id=_cfg("deployment_id", ""),
        auth_login_url=_cfg("auth_login_url", "https://sso.canvaslms.com/api/lti/authorize_redirect"),
        token_url=_token_url(),
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
        ags_enabled=_cfg_bool("ags_enabled"),
        ags_sync_on_solve=_cfg_bool("ags_sync_on_solve"),
        auto_brackets_enabled=_cfg_bool("auto_brackets_enabled", True),
        allowed_course_ids=_cfg("allowed_course_ids", ""),
        blocked_course_ids=_cfg("blocked_course_ids", ""),
        course_rules_json=_cfg("course_rules_json", json.dumps({"default": {"disabled_categories": []}}, indent=2)),
        latest_sync=latest_sync,
        services=services,
        admin_summary=admin_summary,
        recent_launches=recent_launches,
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
    latest_launch = CanvasLTILaunch.query.order_by(CanvasLTILaunch.updated.desc()).first()
    return jsonify(
        {
            "configured": bool(
                _cfg("client_id")
                and _cfg("deployment_id")
                and _effective_base_url_details()["is_public_https"]
            ),
            "login_url": _login_url(),
            "launch_url": _launch_url(),
            "jwks_url": _jwks_url(),
            "canvas_config_url": _canvas_config_url(),
            "ags_enabled": _cfg_bool("ags_enabled"),
            "ags_sync_on_solve": _cfg_bool("ags_sync_on_solve"),
            "auto_brackets_enabled": _cfg_bool("auto_brackets_enabled", True),
            "allowed_courses": sorted(_allowed_courses()),
            "blocked_courses": sorted(_blocked_courses()),
            "setup": _setup_summary(),
            "latest_launch": {
                "course_id": latest_launch.course_id,
                "context_title": latest_launch.context_title,
                "user_id": latest_launch.user_id,
                "canvas_user_id": latest_launch.canvas_user_id,
                "last_login_at": latest_launch.last_login_at.isoformat() if latest_launch and latest_launch.last_login_at else None,
                "lineitem_url": latest_launch.lineitem_url,
                "last_grade_sync": latest_launch.last_grade_sync.isoformat() if latest_launch and latest_launch.last_grade_sync else None,
                "last_grade_error": latest_launch.last_grade_error,
            }
            if latest_launch
            else None,
            "controls": _admin_control_summary(),
        }
    )


@canvas_lti.route("/plugins/canvas_lti/login", methods=["GET", "POST"])
@bypass_csrf_protection
def oidc_login():
    if not _cfg("client_id"):
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
    return redirect(f"{_auth_login_url()}?{urlencode(params)}")


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

    course_id = _course_id_from_claims(claims)
    if not _course_allowed(course_id):
        abort(403, description="This Canvas course is not allowed to use the tool")

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
    _ensure_course_bracket(user, course_id, _context_title_from_claims(claims))
    _save_launch(claims, user)
    login_user(user)
    return redirect(url_for("challenges.listing"))


def load(app):
    _ensure_keypair()
    with app.app_context():
        db.create_all()
    _wrap_challenge_api()
    _wrap_challenge_solve()
    app.register_blueprint(canvas_lti)
    register_admin_plugin_menu_bar("Canvas LTI", "/admin/canvas-lti")
