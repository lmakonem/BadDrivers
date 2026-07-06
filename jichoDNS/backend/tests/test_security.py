# backend/tests/test_security.py
"""JWT round-trip, forgery/expiry rejection, and API-key hashing."""
from datetime import timedelta

from jose import jwt

from app.core import security
from app.core.config import settings


def test_access_token_roundtrip():
    token = security.create_access_token({"sub": "42"})
    payload = security.decode_token(token)
    assert payload is not None
    assert payload["sub"] == "42"
    assert payload["type"] == "access"
    assert "exp" in payload


def test_refresh_token_type():
    payload = security.decode_token(security.create_refresh_token({"sub": "7"}))
    assert payload is not None
    assert payload["type"] == "refresh"


def test_forged_token_wrong_secret_rejected():
    # Signed with a secret the server does not hold -> must not validate.
    forged = jwt.encode(
        {"sub": "42", "type": "access"},
        "attacker-controlled-secret",
        algorithm=settings.JWT_ALGORITHM,
    )
    assert security.decode_token(forged) is None


def test_tampered_token_rejected():
    token = security.create_access_token({"sub": "42"})
    tampered = token[:-2] + ("aa" if not token.endswith("aa") else "bb")
    assert security.decode_token(tampered) is None


def test_expired_token_rejected():
    token = security.create_access_token(
        {"sub": "42"}, expires_delta=timedelta(seconds=-1)
    )
    assert security.decode_token(token) is None


def test_garbage_token_rejected():
    assert security.decode_token("not.a.jwt") is None
    assert security.decode_token("") is None


def test_api_key_shape_and_hash():
    full, prefix, key_hash = security.generate_api_key()
    assert full.startswith("jdns_live_")
    assert prefix == full[:12]
    assert len(prefix) == 12
    # key_hash is the deterministic sha256 of the full key.
    assert security.hash_api_key(full) == key_hash
    assert len(key_hash) == 64
    assert security.get_api_key_prefix(full) == full[:12]


def test_api_keys_are_unique():
    a, _, ha = security.generate_api_key()
    b, _, hb = security.generate_api_key()
    assert a != b
    assert ha != hb
