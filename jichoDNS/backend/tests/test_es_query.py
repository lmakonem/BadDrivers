# backend/tests/test_es_query.py
"""ES query builder escapes user input / no leading-wildcard injection (task #7)."""
import pytest

es_safe = pytest.importorskip(
    "app.core.es_safe",
    reason="ES query hardening (task #7) not landed yet",
)


def _wildcard_values(node):
    """Yield every wildcard clause 'value' anywhere in a query dict/list tree."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "wildcard" and isinstance(v, dict):
                for spec in v.values():
                    yield spec["value"] if isinstance(spec, dict) else spec
            else:
                yield from _wildcard_values(v)
    elif isinstance(node, list):
        for item in node:
            yield from _wildcard_values(item)


def test_escape_neutralizes_user_wildcards():
    assert "*" not in es_safe.escape_wildcard("ac*me").replace("\\*", "")
    assert "?" not in es_safe.escape_wildcard("a?b").replace("\\?", "")


def test_escape_is_idempotent_on_plain_text():
    assert es_safe.escape_wildcard("acme.co") == "acme.co"


def test_build_contains_query_escapes_user_metacharacters():
    vals = list(_wildcard_values(es_safe.build_contains_query(["email"], "a*b")))
    assert vals, "expected at least one wildcard clause"
    for v in vals:
        assert "\\*" in v          # user star is escaped
        assert "a*b" not in v      # raw unescaped user glob is gone


def test_no_user_injected_leading_wildcard():
    # A leading '*' typed by the user must be escaped, not honored as a glob
    # (leading wildcards are unindexed full scans / a DoS vector).
    for v in _wildcard_values(es_safe.build_contains_query(["email"], "*evil")):
        assert v.startswith("*") and v.endswith("*")   # builder's own globs
        inner = v[1:-1]
        assert not inner.startswith("*")               # user '*' not honored
        assert inner.startswith("\\*")                 # it was escaped


def test_build_contains_query_targets_requested_fields():
    r = repr(es_safe.build_contains_query(["email", "domain"], "acme"))
    assert "email" in r and "domain" in r
