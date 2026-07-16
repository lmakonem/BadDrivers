# backend/tests/test_auth_flow.py
"""
End-to-end tests for the registration → verification → login flow.

Runs against a throwaway in-memory SQLite database (never the real one) with
the Redis-backed rate limiters monkeypatched to allow-all, and the email
sender captured in-process so tests can extract the verification token.
"""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.core.database import get_db
from app.core.security import decode_token
from app.models.base import Base
from app.models.user import APIKey, User
from app.api.v1.endpoints import auth as auth_ep
from app.api import deps as auth_deps


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture()
def sent_emails(monkeypatch):
    """Capture outbound verification emails instead of sending them."""
    captured = []

    async def _capture(to_email, name, token):
        captured.append({"to": to_email, "name": name, "token": token})
        return True

    monkeypatch.setattr(auth_ep, "send_verification_email", _capture)
    return captured


@pytest.fixture()
def client(monkeypatch, sent_emails):
    """TestClient over a minimal app with the auth router + SQLite session."""
    engine = create_async_engine(
        "sqlite+aiosqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    maker = async_sessionmaker(engine, expire_on_commit=False)

    app = FastAPI()
    app.include_router(auth_ep.router, prefix="/api/v1/auth")

    # Create the schema inside the SAME event loop TestClient runs requests in
    # (an aiosqlite connection is bound to the loop that created it).
    # Only the auth tables — other models use Postgres-specific column types
    # (e.g. ARRAY) that SQLite cannot compile.
    @app.on_event("startup")
    async def _create_tables():
        async with engine.begin() as conn:
            await conn.run_sync(
                lambda sync_conn: Base.metadata.create_all(
                    sync_conn, tables=[User.__table__, APIKey.__table__]
                )
            )

    async def _override_get_db():
        async with maker() as session:
            yield session
            await session.commit()

    app.dependency_overrides[get_db] = _override_get_db

    # Rate limiters: allow-all (their counting logic is unit-tested separately).
    async def _allow(*args, **kwargs):
        return None

    monkeypatch.setattr(auth_ep, "check_register_allowed", _allow)
    monkeypatch.setattr(auth_ep, "check_email_resend_allowed", _allow)
    monkeypatch.setattr(auth_ep, "check_login_allowed", _allow)

    async def _noop(*args, **kwargs):
        return None

    monkeypatch.setattr(auth_ep, "record_login_failure", _noop)
    monkeypatch.setattr(auth_ep, "clear_login_failures", _noop)

    # JWT revocation denylist: in-memory stand-in for the Redis-backed one, so
    # the logout→revoke→reject flow is exercised end-to-end without Redis.
    denied: set = set()

    async def _deny(jti, ttl):
        if jti and ttl and ttl > 0:
            denied.add(jti)
            return True
        return False

    async def _is_denied(jti):
        return bool(jti) and jti in denied

    monkeypatch.setattr(auth_ep, "deny_token", _deny)
    monkeypatch.setattr(auth_ep, "is_token_denied", _is_denied)
    monkeypatch.setattr(auth_deps, "is_token_denied", _is_denied)

    with TestClient(app) as c:
        yield c


REGISTER = "/api/v1/auth/register"
LOGIN = "/api/v1/auth/login"
VERIFY = "/api/v1/auth/verify-email"
RESEND = "/api/v1/auth/resend-verification"
ME = "/api/v1/auth/me"
REFRESH = "/api/v1/auth/refresh"
LOGOUT = "/api/v1/auth/logout"


def _login_tokens(client, email, password="s3cret-pass!"):
    r = client.post(LOGIN, json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return r.json()


def _register(client, email="User.One@Example.COM", password="s3cret-pass!", **kw):
    return client.post(
        REGISTER, json={"email": email, "password": password, "name": "User One", **kw}
    )


# ── Registration ──────────────────────────────────────────────────────────────

def test_register_returns_202_and_sends_verification(client, sent_emails):
    r = _register(client)
    assert r.status_code == 202
    assert len(sent_emails) == 1
    assert sent_emails[0]["to"] == "user.one@example.com"  # normalized
    payload = decode_token(sent_emails[0]["token"], require_type="email_verify")
    assert payload is not None
    assert payload["email"] == "user.one@example.com"


def test_register_normalizes_email_case_and_whitespace(client, sent_emails):
    _register(client, email="  MixedCase@Example.Com ")
    r = client.post(
        LOGIN, json={"email": "mixedcase@example.com", "password": "s3cret-pass!"}
    )
    assert r.status_code == 200, r.text


def test_duplicate_register_same_202_no_second_email(client, sent_emails):
    _register(client, email="dup@example.com")
    assert len(sent_emails) == 1
    r = _register(client, email="DUP@example.com")  # same account, other case
    assert r.status_code == 202  # anti-enumeration: identical response
    assert len(sent_emails) == 1  # but no second verification email


# ── Login ─────────────────────────────────────────────────────────────────────

def test_login_case_insensitive(client, sent_emails):
    _register(client, email="Casey@Example.com")
    for attempt in ("casey@example.com", "CASEY@EXAMPLE.COM", "Casey@Example.com"):
        r = client.post(LOGIN, json={"email": attempt, "password": "s3cret-pass!"})
        assert r.status_code == 200, f"{attempt}: {r.text}"


def test_login_wrong_password_401(client, sent_emails):
    _register(client, email="w@example.com")
    r = client.post(LOGIN, json={"email": "w@example.com", "password": "wrong-pass!"})
    assert r.status_code == 401


def test_login_unknown_user_401(client):
    r = client.post(LOGIN, json={"email": "ghost@example.com", "password": "whatever1"})
    assert r.status_code == 401


# ── Email verification ────────────────────────────────────────────────────────

def test_verify_email_flow(client, sent_emails):
    _register(client, email="v@example.com")
    token = sent_emails[0]["token"]

    r = client.post(VERIFY, json={"token": token})
    assert r.status_code == 200, r.text

    # /me reflects is_verified after login
    login = client.post(LOGIN, json={"email": "v@example.com", "password": "s3cret-pass!"})
    me = client.get(ME, headers={"Authorization": f"Bearer {login.json()['access_token']}"})
    assert me.status_code == 200
    assert me.json()["is_verified"] is True

    # Idempotent
    r2 = client.post(VERIFY, json={"token": token})
    assert r2.status_code == 200


def test_verify_email_garbage_token_400(client):
    r = client.post(VERIFY, json={"token": "not-a-jwt"})
    assert r.status_code == 400


def test_verify_email_rejects_access_token(client, sent_emails):
    """An access JWT must not pass as a verification token (type confusion)."""
    _register(client, email="t@example.com")
    login = client.post(LOGIN, json={"email": "t@example.com", "password": "s3cret-pass!"})
    access = login.json()["access_token"]
    r = client.post(VERIFY, json={"token": access})
    assert r.status_code == 400


def test_verify_email_stale_after_email_change(client, sent_emails):
    """A token issued for an old address must not verify a changed one."""
    _register(client, email="old@example.com")
    token = sent_emails[0]["token"]
    # Forge the mismatch by issuing a token for the right user id but a
    # different email claim.
    payload = decode_token(token, require_type="email_verify")
    from app.core.security import create_email_verification_token

    stale = create_email_verification_token(int(payload["sub"]), "other@example.com")
    r = client.post(VERIFY, json={"token": stale})
    assert r.status_code == 400


# ── Resend verification ───────────────────────────────────────────────────────

def test_resend_sends_for_unverified(client, sent_emails):
    _register(client, email="r@example.com")
    r = client.post(RESEND, json={"email": "R@Example.com"})  # case-insensitive
    assert r.status_code == 202
    assert len(sent_emails) == 2
    assert sent_emails[1]["to"] == "r@example.com"


def test_resend_generic_for_unknown_and_verified(client, sent_emails):
    # Unknown address: 202, nothing sent
    r = client.post(RESEND, json={"email": "nobody@example.com"})
    assert r.status_code == 202
    assert len(sent_emails) == 0

    # Verified account: 202, nothing sent
    _register(client, email="done@example.com")
    client.post(VERIFY, json={"token": sent_emails[0]["token"]})
    before = len(sent_emails)
    r = client.post(RESEND, json={"email": "done@example.com"})
    assert r.status_code == 202
    assert len(sent_emails) == before


# ── Optional verification gate ────────────────────────────────────────────────

def test_login_gate_when_verification_required(client, sent_emails, monkeypatch):
    from app.core.config import settings

    _register(client, email="gated@example.com")
    monkeypatch.setattr(settings, "REQUIRE_EMAIL_VERIFICATION", True)
    r = client.post(LOGIN, json={"email": "gated@example.com", "password": "s3cret-pass!"})
    assert r.status_code == 403

    client.post(VERIFY, json={"token": sent_emails[0]["token"]})
    r2 = client.post(LOGIN, json={"email": "gated@example.com", "password": "s3cret-pass!"})
    assert r2.status_code == 200


# ── Token revocation / logout ─────────────────────────────────────────────────

def test_tokens_carry_unique_jti(client, sent_emails):
    from app.core.security import decode_token

    _register(client, email="jti@example.com")
    t = _login_tokens(client, "jti@example.com")
    a = decode_token(t["access_token"], require_type="access")
    r = decode_token(t["refresh_token"], require_type="refresh")
    assert a.get("jti") and r.get("jti")
    assert a["jti"] != r["jti"]


def test_logout_revokes_access_and_refresh(client, sent_emails):
    _register(client, email="lo@example.com")
    t = _login_tokens(client, "lo@example.com")
    access, refresh = t["access_token"], t["refresh_token"]
    auth = {"Authorization": f"Bearer {access}"}

    # Works before logout
    assert client.get(ME, headers=auth).status_code == 200

    # Logout revokes both tokens
    assert client.post(LOGOUT, headers=auth, json={"refresh_token": refresh}).status_code == 200

    # Access token now rejected (denylisted)
    r = client.get(ME, headers=auth)
    assert r.status_code == 401 and "revoked" in r.text.lower()

    # Refresh token now rejected too
    r = client.post(REFRESH, json={"refresh_token": refresh})
    assert r.status_code == 401 and "revoked" in r.text.lower()


def test_refresh_works_until_logout(client, sent_emails):
    _register(client, email="rf@example.com")
    t = _login_tokens(client, "rf@example.com")
    # Refresh is fine before logout
    assert client.post(REFRESH, json={"refresh_token": t["refresh_token"]}).status_code == 200
    # After logging out the ORIGINAL refresh, that original is dead
    client.post(LOGOUT, json={"refresh_token": t["refresh_token"]})
    assert client.post(REFRESH, json={"refresh_token": t["refresh_token"]}).status_code == 401


def test_logout_is_idempotent_and_tokenless_ok(client):
    # No tokens at all → still 200 (nothing to reveal, nothing to revoke)
    assert client.post(LOGOUT, json={}).status_code == 200
    # Garbage refresh token → 200 (decode fails, nothing denylisted, no error)
    assert client.post(LOGOUT, json={"refresh_token": "not-a-jwt"}).status_code == 200


def test_other_sessions_unaffected_by_logout(client, sent_emails):
    """Logging out one device must not kill a different device's token."""
    _register(client, email="multi@example.com")
    dev1 = _login_tokens(client, "multi@example.com")
    dev2 = _login_tokens(client, "multi@example.com")
    # Log out device 1
    client.post(LOGOUT, headers={"Authorization": f"Bearer {dev1['access_token']}"},
                json={"refresh_token": dev1["refresh_token"]})
    # Device 2's tokens still work
    assert client.get(ME, headers={"Authorization": f"Bearer {dev2['access_token']}"}).status_code == 200
    assert client.post(REFRESH, json={"refresh_token": dev2["refresh_token"]}).status_code == 200


# ── normalize_email unit ──────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "raw,expected",
    [
        ("User@Example.COM", "user@example.com"),
        ("  padded@example.com  ", "padded@example.com"),
        ("already@example.com", "already@example.com"),
    ],
)
def test_normalize_email(raw, expected):
    assert auth_ep.normalize_email(raw) == expected
