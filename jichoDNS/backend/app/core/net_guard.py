"""
SSRF / internal-scan guard.

Resolve a user-supplied host and reject it if any resolved address is
loopback / private (RFC1918 + ULA fc00::/7) / link-local (incl. the
169.254.169.254 cloud-metadata endpoint) / reserved / multicast /
unspecified / otherwise non-globally-routable.

Follows the OWASP "Server Side Request Forgery Prevention" cheat sheet:
pre-resolve the hostname, validate *every* A/AAAA answer against the block
rules, and fail closed on a mixed public/private answer (DNS-rebinding).
IPv4-mapped / 6to4 / Teredo IPv6 forms are collapsed to their embedded
IPv4 first so ::ffff:169.254.169.254 and friends cannot smuggle past the
IPv4 checks.

stdlib-only on purpose (no `app.*` imports) so it is safe to import from
core/services without creating an import cycle.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import List, Optional, Union
from urllib.parse import urlsplit

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


class SSRFError(ValueError):
    """Raised when a target host/IP resolves to a non-public / disallowed address."""


# Extra IPv4 ranges to block on top of ipaddress's own classification.
# (is_private/is_global classification varies slightly across CPython
# patch levels; this list makes the intent explicit and version-proof.)
_EXTRA_BLOCK_V4 = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),    # CGNAT / shared address space
    ipaddress.ip_network("169.254.0.0/16"),   # link-local incl. 169.254.169.254 (IMDS)
    ipaddress.ip_network("192.0.0.0/24"),     # IETF protocol assignments
    ipaddress.ip_network("192.0.2.0/24"),     # TEST-NET-1
    ipaddress.ip_network("198.18.0.0/15"),    # benchmarking
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),   # TEST-NET-3
]


def _unmap(ip: IPAddress) -> IPAddress:
    """Collapse IPv4-mapped / 6to4 / Teredo IPv6 to the embedded IPv4."""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped:
            return ip.ipv4_mapped
        if ip.sixtofour:
            return ip.sixtofour
        if ip.teredo:
            # teredo -> (server, client); the client is the routable endpoint
            return ip.teredo[1]
    return ip


def ip_block_reason(ip_str: str) -> Optional[str]:
    """Return a human reason string if the IP must be blocked, else None."""
    try:
        ip = ipaddress.ip_address(str(ip_str).strip().strip("[]").split("%")[0])
    except ValueError:
        return f"not a valid IP address: {ip_str!r}"
    ip = _unmap(ip)
    if ip.is_loopback:
        return "loopback"
    if ip.is_private:
        return "private (RFC1918 / ULA)"
    if ip.is_link_local:
        return "link-local / cloud-metadata"
    if ip.is_reserved:
        return "reserved"
    if ip.is_multicast:
        return "multicast"
    if ip.is_unspecified:
        return "unspecified"
    if not ip.is_global:
        return "non-global"
    if ip.version == 4:
        for net in _EXTRA_BLOCK_V4:
            if ip in net:
                return f"blocked range {net}"
    return None


def assert_ip_public(ip_str: str) -> None:
    reason = ip_block_reason(ip_str)
    if reason:
        raise SSRFError(f"Address {ip_str} is not permitted ({reason}).")


def host_is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip().strip("[]").split("%")[0])
        return True
    except ValueError:
        return False


def extract_host(target: str) -> str:
    """Accept a bare host, host:port, or full URL; return just the hostname."""
    t = (target or "").strip()
    if not t:
        return ""
    if "://" in t:
        return (urlsplit(t).hostname or "").strip().strip("[]")
    t = t.split("/", 1)[0]              # drop any path
    if t.startswith("["):              # [IPv6]:port
        return t[1:].split("]", 1)[0]
    if t.count(":") >= 2:              # bare IPv6 literal
        return t
    return t.split(":", 1)[0].strip()  # host or host:port


def _validate_infos(host: str, infos) -> List[str]:
    ips: List[str] = []
    seen = set()
    for info in infos:
        addr = info[4][0].split("%")[0]
        if addr in seen:
            continue
        seen.add(addr)
        assert_ip_public(addr)  # raises SSRFError on the first non-public hop
        ips.append(str(_unmap(ipaddress.ip_address(addr))))
    if not ips:
        raise SSRFError(f"Host {host!r} did not resolve to any address.")
    return ips


async def resolve_public_ips(host: str, *, timeout: float = 5.0) -> List[str]:
    """
    Resolve host (A + AAAA) and return validated public IP strings.
    Fail-closed: raise SSRFError if the host does not resolve OR if ANY
    resolved address is non-public (mixed answer == rebinding attempt).
    """
    host = extract_host(host) or host.strip().strip("[]")
    if not host:
        raise SSRFError("Empty host.")
    if host_is_ip_literal(host):
        assert_ip_public(host)
        return [str(_unmap(ipaddress.ip_address(host.strip().strip("[]").split("%")[0])))]
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, None, type=socket.SOCK_STREAM),
            timeout=timeout,
        )
    except (socket.gaierror, asyncio.TimeoutError, UnicodeError, OSError) as e:
        raise SSRFError(f"Could not resolve host {host!r}: {e}")
    return _validate_infos(host, infos)


def resolve_public_ips_sync(host: str, *, timeout: float = 5.0) -> List[str]:
    """Blocking variant for code already running in a thread/executor."""
    host = extract_host(host) or host.strip().strip("[]")
    if not host:
        raise SSRFError("Empty host.")
    if host_is_ip_literal(host):
        assert_ip_public(host)
        return [str(_unmap(ipaddress.ip_address(host.strip().strip("[]").split("%")[0])))]
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError) as e:
        raise SSRFError(f"Could not resolve host {host!r}: {e}")
    return _validate_infos(host, infos)


# --- Convenience predicates / URL guard (friendly public API) -----------------

# Only these URL schemes are ever safe to fetch server-side; file://, gopher://,
# ftp://, dict://, etc. are classic SSRF exfil/pivot vectors and are rejected.
_ALLOWED_URL_SCHEMES = frozenset({"http", "https"})


def is_blocked_ip(ip_str: str) -> bool:
    """True if the IP literal must be blocked (loopback/private/link-local/…)."""
    return ip_block_reason(ip_str) is not None


def is_public_ip(ip_str: str) -> bool:
    """True only if the IP literal is a globally-routable public address."""
    return ip_block_reason(ip_str) is None


def assert_public_url(url: str, *, resolve: bool = True) -> None:
    """
    Raise SSRFError if a URL is unsafe to fetch server-side: a non-http(s)
    scheme, a missing host, an IP literal that is not public, or (when
    resolve=True) a hostname that resolves to any non-public address.
    """
    parts = urlsplit((url or "").strip())
    scheme = (parts.scheme or "").lower()
    if scheme not in _ALLOWED_URL_SCHEMES:
        raise SSRFError(f"URL scheme {scheme or '(none)'!r} is not permitted (only http/https).")
    host = (parts.hostname or "").strip().strip("[]")
    if not host:
        raise SSRFError("URL has no host.")
    if host_is_ip_literal(host):
        assert_ip_public(host)
    elif resolve:
        resolve_public_ips_sync(host)  # raises SSRFError on non-public / unresolvable host
