# backend/tests/conftest.py
"""Shared pytest fixtures and deterministic test environment.

IMPORTANT: the os.environ writes below run at conftest import — which pytest
does before importing any test module — so app.core.config.Settings (cached
via lru_cache) is constructed with these values. Do not import `app.*` above
this block.
"""
import os

os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault(
    "SECRET_KEY", "unit-test-secret-key-not-for-production-0123456789abcdef"
)
os.environ.setdefault(
    "DATABASE_URL", "postgresql://test:test@localhost:5432/test"
)
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("ELASTICSEARCH_URL", "http://localhost:9200")

import pytest  # noqa: E402


class _FakeRequest:
    """Minimal stand-in for starlette Request used by webhook tests."""

    def __init__(self, body: bytes = b"{}", headers=None):
        self._body = body
        self.headers = headers or {}

    async def body(self) -> bytes:
        return self._body


@pytest.fixture
def make_request():
    """Factory: make_request(body=b'...', headers={'stripe-signature': '...'})."""

    def _factory(body: bytes = b"{}", headers=None) -> _FakeRequest:
        return _FakeRequest(body=body, headers=headers)

    return _factory
