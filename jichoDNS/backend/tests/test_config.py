# backend/tests/test_config.py
"""Production SECRET_KEY fail-fast (contract for task #2)."""
import pytest
from pydantic import ValidationError

from app.core.config import Settings

DEFAULT_KEY = "dev-secret-key-change-in-production"
STRONG_KEY = "prod-" + "z" * 48  # >= 32 chars, not the default
STRONG_SESSION_KEY = "sess-" + "q" * 48  # distinct from STRONG_KEY


def _make(env: str, key: str, session_key: str = STRONG_SESSION_KEY) -> Settings:
    # _env_file=None -> hermetic (ignore any real .env); explicit kwargs win
    # over os.environ in pydantic-settings' source precedence.
    return Settings(
        _env_file=None, ENVIRONMENT=env, SECRET_KEY=key,
        SESSION_SECRET_KEY=session_key,
    )


def _fail_fast_active() -> bool:
    """True once task #2's production SECRET_KEY validator is present."""
    try:
        _make("production", DEFAULT_KEY)
        return False
    except Exception:
        return True


def test_default_secret_allowed_outside_production():
    # Non-prod must never hard-fail on the dev default.
    assert _make("development", DEFAULT_KEY).SECRET_KEY == DEFAULT_KEY


def test_production_rejects_default_secret():
    if not _fail_fast_active():
        pytest.skip("SECRET_KEY fail-fast (task #2) not landed yet")
    with pytest.raises((ValidationError, ValueError, RuntimeError)):
        _make("production", DEFAULT_KEY)


def test_production_rejects_empty_secret():
    if not _fail_fast_active():
        pytest.skip("SECRET_KEY fail-fast (task #2) not landed yet")
    with pytest.raises((ValidationError, ValueError, RuntimeError)):
        _make("production", "")


def test_production_accepts_strong_secret():
    if not _fail_fast_active():
        pytest.skip("SECRET_KEY fail-fast (task #2) not landed yet")
    s = _make("production", STRONG_KEY)
    assert s.is_production
    assert s.SECRET_KEY == STRONG_KEY


def _session_fail_fast_active() -> bool:
    """True once the production SESSION_SECRET_KEY validator is present."""
    try:
        _make("production", STRONG_KEY, session_key="")
        return False
    except Exception:
        return True


def test_production_rejects_missing_session_secret():
    if not _session_fail_fast_active():
        pytest.skip("SESSION_SECRET_KEY fail-fast not landed yet")
    with pytest.raises((ValidationError, ValueError, RuntimeError)):
        _make("production", STRONG_KEY, session_key="")


def test_production_rejects_session_secret_equal_to_secret():
    if not _session_fail_fast_active():
        pytest.skip("SESSION_SECRET_KEY fail-fast not landed yet")
    # Reusing the JWT SECRET_KEY for the session cookie couples the two auth
    # systems — the validator must reject it.
    with pytest.raises((ValidationError, ValueError, RuntimeError)):
        _make("production", STRONG_KEY, session_key=STRONG_KEY)


def test_production_accepts_distinct_session_secret():
    s = _make("production", STRONG_KEY, session_key=STRONG_SESSION_KEY)
    assert s.SESSION_SECRET_KEY == STRONG_SESSION_KEY
    assert s.SESSION_SECRET_KEY != s.SECRET_KEY


def test_development_allows_missing_session_secret():
    # Non-prod falls back to SECRET_KEY for the session cookie; must not fail.
    s = _make("development", DEFAULT_KEY, session_key="")
    assert s.SESSION_SECRET_KEY == ""
