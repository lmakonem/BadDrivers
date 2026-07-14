# backend/tests/test_review_fixes.py
"""Regression tests for the code/platform-review fixes."""
import asyncio

import pytest

from app.services import report_generator
from app.services import asm_enterprise
from app.core.ownership import bare_domain


# ── Report HTML XSS escaping ──────────────────────────────────────────────────

def test_report_title_and_focus_area_escaped():
    """User-supplied title/focus_area must be HTML-escaped in generated report HTML."""
    result = report_generator._build_result(
        report_type="threat_intelligence",
        title='<script>alert(1)</script>',
        now=__import__("datetime").datetime(2026, 1, 1),
        date_range="7d",
        ioc_stats={"total": 5, "by_source": {"x": 1}, "by_type": {}, "by_country": {}},
        dw_stats={}, cred_stats={}, top_iocs=[], darkweb_posts=[],
        focus_area='<img src=x onerror=alert(2)>',
    )
    html = result["html"]
    # Reports are no-JS, so a raw <script or an executable <img tag must never
    # appear; the payloads must be present only in neutralized/escaped form.
    assert "<script" not in html.lower()
    assert "&lt;script&gt;" in html
    assert "<img src=x onerror" not in html
    assert "&lt;img src=x onerror=alert(2)&gt;" in html


# ── ASM webhook SSRF guard ────────────────────────────────────────────────────

def test_send_webhook_blocks_internal_targets():
    async def run():
        for bad in [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:8000/",
            "http://10.0.0.5/hook",
            "http://localhost/",
            "file:///etc/passwd",
            "ftp://example.com/",
        ]:
            ok = await asm_enterprise.send_webhook(bad, {"x": 1})
            assert ok is False, f"{bad} should be blocked"

    asyncio.run(run())


def test_webhook_url_validator_rejects_and_accepts():
    from app.api.v1.endpoints.asm import _validate_webhook_url

    with pytest.raises(ValueError):
        _validate_webhook_url("http://169.254.169.254/")
    with pytest.raises(ValueError):
        _validate_webhook_url("http://10.1.2.3/hook")
    with pytest.raises(ValueError):
        _validate_webhook_url("notaurl")
    # A resolvable public URL passes through unchanged (trimmed). example.com
    # has stable public A records.
    assert _validate_webhook_url("  https://example.com/x  ") == "https://example.com/x"
    assert _validate_webhook_url(None) is None
    assert _validate_webhook_url("") == ""


# ── bare_domain (brand.py www-strip bug) ──────────────────────────────────────

@pytest.mark.parametrize(
    "raw,expected",
    [
        ("www.wise.com", "wise.com"),
        ("wise.com", "wise.com"),        # lstrip("www.") would have made "ise.com"
        ("web.example", "web.example"),  # lstrip("www.") would have made "eb.example"
        ("https://www.foo.co.zw/path", "foo.co.zw"),
        ("user@www.bar.com", "bar.com"),
    ],
)
def test_bare_domain_strips_www_prefix_only(raw, expected):
    assert bare_domain(raw) == expected
