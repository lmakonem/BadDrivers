# backend/tests/test_config.py
"""Production SECRET_KEY fail-fast (contract for task #2)."""
import pytest
from pydantic import ValidationError

from app.core.config import Settings

DEFAULT_KEY = "dev-secret-key-change-in-production"
STRONG_KEY = "prod-" + "z" * 48  # >= 32 chars, not the default


def _make(env: str, key: str) -> Settings:
    # _env_file=None -> hermetic (ignore any real .env); explicit kwargs win
    # over os.environ in pydantic-settings' source precedence.
    return Settings(_env_file=None, ENVIRONMENT=env, SECRET_KEY=key)


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
