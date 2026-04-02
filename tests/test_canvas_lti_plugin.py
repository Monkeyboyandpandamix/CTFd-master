import json
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from CTFd.plugins.canvas_lti import (
    LTI_DEPLOYMENT_CLAIM,
    LTI_MESSAGE_TYPE_CLAIM,
    LTI_RESOURCE_LINK_REQUEST,
    LTI_VERSION_CLAIM,
    _canvas_developer_key_config,
    _b64url_decode,
    _b64url_encode,
    _int_to_b64,
    _jwk_to_public_key,
    _jwt_parts,
    _jwt_sign,
)


def test_b64url_roundtrip():
    raw = b"canvas-lti-test"
    assert _b64url_decode(_b64url_encode(raw)) == raw


def test_jwt_sign_and_verify_with_generated_key():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    payload = {"sub": "123", "iat": int(time.time()), "exp": int(time.time()) + 60}
    token = _jwt_sign(payload, private_key=private_key, headers={"kid": "unit-test"})
    header, parsed_payload, signature, signing_input = _jwt_parts(token)

    assert header["kid"] == "unit-test"
    assert parsed_payload["sub"] == "123"
    public_key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())


def test_jwk_conversion_roundtrip():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    numbers = public_key.public_numbers()
    jwk = {"kty": "RSA", "n": _int_to_b64(numbers.n), "e": _int_to_b64(numbers.e)}
    rebuilt = _jwk_to_public_key(jwk)
    assert rebuilt.public_numbers().n == numbers.n
    assert rebuilt.public_numbers().e == numbers.e


def test_canvas_config_shape(app):
    from CTFd.plugins import init_plugins

    app.config["SAFE_MODE"] = False
    with app.app_context():
        init_plugins(app)
        config = _canvas_developer_key_config()
    assert "oidc_initiation_url" in config
    assert "target_link_uri" in config
    assert "public_jwk_url" in config
    assert config["extensions"][0]["settings"]["placements"]
