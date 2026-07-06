"""
Elasticsearch query-safety helpers.

User-supplied text must never be spliced raw into a `wildcard` / `query_string`
clause. A user `*` or `?` becomes an unbounded glob — and a *leading* wildcard
forces an unindexed full-index scan, which is both a correctness footgun and a
denial-of-service vector. `escape_wildcard()` neutralizes the ES wildcard
metacharacters; `build_contains_query()` produces a safe case-insensitive
"contains" match across the requested fields where only the builder controls
the surrounding globs.

stdlib-only so it is safe to import anywhere without an import cycle.
"""

from __future__ import annotations

from typing import List


def escape_wildcard(value: str) -> str:
    """
    Escape Elasticsearch wildcard metacharacters (``\\``, ``*``, ``?``) so the
    value is matched literally. Idempotent-looking on plain text (text with no
    metacharacters is returned unchanged).
    """
    out: List[str] = []
    for ch in str(value):
        if ch == "\\":
            out.append("\\\\")
        elif ch == "*":
            out.append("\\*")
        elif ch == "?":
            out.append("\\?")
        else:
            out.append(ch)
    return "".join(out)


def build_contains_query(fields: List[str], term: str) -> dict:
    """
    Build a safe case-insensitive "contains" query for ``term`` across ``fields``.

    The user term is wildcard-escaped, then wrapped in the builder's OWN
    ``*...*`` globs — so a user-typed ``*`` / ``?`` (including a leading one) is
    matched literally and can never turn into an attacker-controlled glob.
    """
    pattern = f"*{escape_wildcard(term)}*"
    return {
        "bool": {
            "should": [
                {"wildcard": {field: {"value": pattern, "case_insensitive": True}}}
                for field in fields
            ],
            "minimum_should_match": 1,
        }
    }
