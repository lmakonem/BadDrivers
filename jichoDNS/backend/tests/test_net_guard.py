# backend/tests/test_net_guard.py
"""SSRF guard: block internal targets, allow public (contract for task #4)."""
import pytest

net_guard = pytest.importorskip(
    "app.core.net_guard",
    reason="SSRF guard (task #4) not landed yet",
)

BLOCKED_IPS = [
    "127.0.0.1", "127.5.5.5", "::1",
    "10.0.0.1", "10.255.255.255",
    "172.16.0.1", "172.31.255.255",
    "192.168.1.1",
    "169.254.169.254",   # cloud metadata / IPv4 link-local
    "fe80::1",           # IPv6 link-local
    "0.0.0.0",           # unspecified
    "100.64.0.1",        # CGNAT / RFC 6598 shared space
    "::ffff:127.0.0.1",  # IPv4-mapped loopback (classic bypass)
]

PUBLIC_IPS = [
    "8.8.8.8", "1.1.1.1", "23.150.68.201", "2606:4700:4700::1111",
]


@pytest.mark.parametrize("ip", BLOCKED_IPS)
def test_blocks_private_loopback_linklocal(ip):
    assert net_guard.is_blocked_ip(ip) is True
    assert net_guard.is_public_ip(ip) is False


@pytest.mark.parametrize("ip", PUBLIC_IPS)
def test_allows_public(ip):
    assert net_guard.is_public_ip(ip) is True
    assert net_guard.is_blocked_ip(ip) is False


@pytest.mark.parametrize(
    "bad_url",
    [
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/",
        "ftp://internal/",
        "http://127.0.0.1/",
        "http://169.254.169.254/latest/meta-data/",
        "https://[::1]/",
    ],
)
def test_assert_public_url_rejects_unsafe(bad_url):
    with pytest.raises((ValueError, Exception)):
        net_guard.assert_public_url(bad_url)


def test_assert_public_url_allows_public_literal():
    # A legitimately public literal IP must not be rejected as internal.
    net_guard.assert_public_url("http://8.8.8.8/")
