# backend/tests/test_email_and_ratelimit.py
"""Unit tests for the email service and the register/resend IP throttles."""
import asyncio

import pytest

from app.core import ratelimit
from app.services import email_service


# ── Fake redis for the fixed-window counters ──────────────────────────────────

class _FakeRedis:
    def __init__(self):
        self.store: dict[str, int] = {}
        self.ttls: dict[str, int] = {}

    async def incr(self, key):
        self.store[key] = self.store.get(key, 0) + 1
        return self.store[key]

    async def expire(self, key, seconds):
        self.ttls[key] = seconds

    async def ttl(self, key):
        return self.ttls.get(key, 60)


@pytest.fixture()
def fake_redis(monkeypatch):
    fake = _FakeRedis()
    monkeypatch.setattr(ratelimit, "_get_redis", lambda: fake)
    return fake


def test_register_throttle_caps_per_ip(fake_redis):
    async def run():
        for _ in range(ratelimit.MAX_REGISTRATIONS_PER_IP):
            assert await ratelimit.check_register_allowed("1.2.3.4") is None
        retry = await ratelimit.check_register_allowed("1.2.3.4")
        assert isinstance(retry, int) and retry >= 1
        # Other IPs unaffected
        assert await ratelimit.check_register_allowed("5.6.7.8") is None

    asyncio.run(run())


def test_resend_throttle_caps_per_ip(fake_redis):
    async def run():
        for _ in range(ratelimit.MAX_RESENDS_PER_IP):
            assert await ratelimit.check_email_resend_allowed("1.2.3.4") is None
        retry = await ratelimit.check_email_resend_allowed("1.2.3.4")
        assert isinstance(retry, int) and retry >= 1

    asyncio.run(run())


def test_throttles_fail_open_without_redis(monkeypatch):
    monkeypatch.setattr(ratelimit, "_get_redis", lambda: None)

    async def run():
        assert await ratelimit.check_register_allowed("1.2.3.4") is None
        assert await ratelimit.check_email_resend_allowed("1.2.3.4") is None

    asyncio.run(run())


# ── Email service ─────────────────────────────────────────────────────────────

def test_console_mode_succeeds_and_logs_link(monkeypatch, caplog):
    monkeypatch.setattr(email_service.settings, "SMTP_HOST", "")

    async def run():
        with caplog.at_level("INFO", logger="app.services.email_service"):
            ok = await email_service.send_verification_email(
                "x@example.com", "X", "tok-123"
            )
        assert ok is True
        assert "console mode" in caplog.text
        assert "/verify-email?token=tok-123" in caplog.text

    asyncio.run(run())


def test_smtp_failure_returns_false_never_raises(monkeypatch):
    monkeypatch.setattr(email_service.settings, "SMTP_HOST", "smtp.invalid")

    def _boom(msg):
        raise ConnectionError("relay down")

    monkeypatch.setattr(email_service, "_smtp_send", _boom)

    async def run():
        ok = await email_service.send_email("x@example.com", "s", "b")
        assert ok is False

    asyncio.run(run())


def test_smtp_success_path(monkeypatch):
    monkeypatch.setattr(email_service.settings, "SMTP_HOST", "smtp.example.com")
    sent = {}

    def _capture(msg):
        sent["to"] = msg["To"]
        sent["subject"] = msg["Subject"]

    monkeypatch.setattr(email_service, "_smtp_send", _capture)

    async def run():
        ok = await email_service.send_verification_email(
            "y@example.com", None, "tok-9"
        )
        assert ok is True
        assert sent["to"] == "y@example.com"
        assert "Verify" in sent["subject"]

    asyncio.run(run())


def test_hostile_display_name_neutralized(monkeypatch):
    """Registration `name` is attacker-controlled and the recipient may be a
    victim's address — HTML must be escaped and newlines collapsed."""
    monkeypatch.setattr(email_service.settings, "SMTP_HOST", "smtp.example.com")
    captured = {}

    def _capture(msg):
        body = msg.get_body(("html",))
        captured["html"] = body.get_content() if body else ""
        captured["text"] = msg.get_body(("plain",)).get_content()

    monkeypatch.setattr(email_service, "_smtp_send", _capture)

    hostile = '<a href="https://evil.example">Reset your bank password</a>\r\nX' * 20

    async def run():
        ok = await email_service.send_verification_email(
            "victim@example.com", hostile, "tok"
        )
        assert ok is True
        assert "<a href=\"https://evil.example\"" not in captured["html"]
        assert "&lt;a href=" in captured["html"]
        # collapsed + capped in both bodies
        first_text_line = next(
            l for l in captured["text"].splitlines() if l.startswith("Hi ")
        )
        assert "\r" not in first_text_line and len(first_text_line) < 100
        # URLs in display names are stripped (mail clients linkify plain text)
        assert "evil.example" not in first_text_line

    asyncio.run(run())


def test_verification_token_urlencoded():
    assert (
        "?token=a%2Fb%3Dc" in email_service._verification_link("a/b=c")
    )


def test_verification_link_uses_public_base_url(monkeypatch):
    monkeypatch.setattr(
        email_service.settings, "PUBLIC_BASE_URL", "https://example.org/"
    )
    assert (
        email_service._verification_link("abc")
        == "https://example.org/verify-email?token=abc"
    )
