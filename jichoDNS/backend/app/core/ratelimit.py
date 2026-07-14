"""
Redis-backed login throttling / brute-force lockout.

Design notes
------------
* FAIL-OPEN: if Redis is unavailable the limiter ALLOWS the request (and logs
  an error) so a Redis outage cannot lock every user out of authentication.
  This is deliberately the opposite of the Stripe webhook, which fails CLOSED.
* Fixed-window counters: the TTL is set only when a counter is first created
  (INCR returns 1), so a legitimate user is locked for at most
  LOGIN_WINDOW_SECONDS after a burst of failures rather than indefinitely.
* Two independent counters per attempt: per-account (defeats password spraying
  against one victim) and per-source-IP (defeats spraying many accounts from
  one host). Either tripping locks the attempt.

Reuses the same Redis instance already used as the Celery broker
(settings.REDIS_URL) — no new infrastructure.
"""

import logging
from typing import Optional

from redis.asyncio import Redis

from app.core.config import settings

logger = logging.getLogger(__name__)

# ── Tunables ──────────────────────────────────────────────────────────────────
LOGIN_WINDOW_SECONDS = 900   # 15-minute rolling lockout window
MAX_FAILS_PER_ACCOUNT = 5    # lock a single account after N bad passwords
MAX_FAILS_PER_IP = 20        # lock a source IP after N bad attempts (any account)

_redis: Optional[Redis] = None


def _get_redis() -> Optional[Redis]:
    """Lazily create a shared async Redis client, or None if it can't be made."""
    global _redis
    if _redis is None:
        try:
            _redis = Redis.from_url(
                settings.REDIS_URL,
                encoding="utf-8",
                decode_responses=True,
                socket_connect_timeout=2,
                socket_timeout=2,
            )
        except Exception as e:  # pragma: no cover - defensive
            logger.error("login-throttle: cannot create Redis client: %s", e)
            return None
    return _redis


def client_ip(request) -> str:
    """
    Best-effort real client IP. In production JichoDNS sits behind a Cloudflare
    Tunnel, so the socket peer is the proxy — prefer CF-Connecting-IP, then the
    first hop of X-Forwarded-For, then the raw socket.
    """
    cf = request.headers.get("cf-connecting-ip")
    if cf:
        return cf.strip()
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def check_login_allowed(email: str, ip: str) -> Optional[int]:
    """
    Return None if the attempt is allowed, or the number of seconds to wait
    (Retry-After) if the account or IP is currently locked out.
    """
    r = _get_redis()
    if r is None:
        return None  # fail-open
    acct_key = f"login_fail:acct:{email.lower()}"
    ip_key = f"login_fail:ip:{ip}"
    try:
        pipe = r.pipeline()
        pipe.get(acct_key)
        pipe.ttl(acct_key)
        pipe.get(ip_key)
        pipe.ttl(ip_key)
        acct_n, acct_ttl, ip_n, ip_ttl = await pipe.execute()
        if int(acct_n or 0) >= MAX_FAILS_PER_ACCOUNT:
            return max(int(acct_ttl or 0), 1)
        if int(ip_n or 0) >= MAX_FAILS_PER_IP:
            return max(int(ip_ttl or 0), 1)
        return None
    except Exception as e:
        logger.error("login-throttle: check failed, allowing attempt: %s", e)
        return None  # fail-open


async def record_login_failure(email: str, ip: str) -> None:
    """Increment the account + IP failure counters (fixed-window TTL)."""
    r = _get_redis()
    if r is None:
        return
    acct_key = f"login_fail:acct:{email.lower()}"
    ip_key = f"login_fail:ip:{ip}"
    try:
        pipe = r.pipeline()
        pipe.incr(acct_key)
        pipe.incr(ip_key)
        acct_n, ip_n = await pipe.execute()
        exp = r.pipeline()
        if int(acct_n) == 1:
            exp.expire(acct_key, LOGIN_WINDOW_SECONDS)
        if int(ip_n) == 1:
            exp.expire(ip_key, LOGIN_WINDOW_SECONDS)
        await exp.execute()  # no-op if empty
    except Exception as e:
        logger.error("login-throttle: record failure error: %s", e)


async def clear_login_failures(email: str, ip: str) -> None:
    """Clear counters after a fully successful authentication."""
    r = _get_redis()
    if r is None:
        return
    try:
        await r.delete(f"login_fail:acct:{email.lower()}", f"login_fail:ip:{ip}")
    except Exception as e:
        logger.error("login-throttle: clear error: %s", e)


# ── Registration throttle ─────────────────────────────────────────────────────
# The register endpoint is anti-enumeration (always returns the same 202), so
# there is no per-account counter — only a per-IP cap on how many accounts one
# source can create. This stops mass/bulk signup (DB flooding, spam accounts,
# and blind account-existence probing). Fixed-window, fail-OPEN like the login
# throttle so a Redis outage never blocks legitimate signups.
REGISTER_WINDOW_SECONDS = 3600   # 1-hour window
MAX_REGISTRATIONS_PER_IP = 10    # accounts one IP may create per window

# Resend-verification is an unauthenticated mail-sending endpoint, so cap it
# harder than registration — it is otherwise a mailbox-flooding primitive.
RESEND_WINDOW_SECONDS = 3600
MAX_RESENDS_PER_IP = 6


async def _check_ip_cap(key: str, cap: int, window: int, label: str) -> Optional[int]:
    """
    Fixed-window per-IP counter shared by the register/resend throttles.

    Returns None if allowed, or seconds to wait (Retry-After) once `cap`
    attempts have been counted inside `window`.
    """
    r = _get_redis()
    if r is None:
        return None  # fail-open
    try:
        n = await r.incr(key)
        if n == 1:
            await r.expire(key, window)
        if n > cap:
            ttl = await r.ttl(key)
            return max(int(ttl or 0), 1)
        return None
    except Exception as e:
        logger.error("%s: check failed, allowing attempt: %s", label, e)
        return None  # fail-open


async def check_register_allowed(ip: str) -> Optional[int]:
    """
    Count this registration attempt against the per-IP cap.

    Returns None if allowed, or the number of seconds to wait (Retry-After) if
    the source IP has exceeded MAX_REGISTRATIONS_PER_IP within the window.
    """
    return await _check_ip_cap(
        f"register:ip:{ip}", MAX_REGISTRATIONS_PER_IP, REGISTER_WINDOW_SECONDS,
        "register-throttle",
    )


async def check_email_resend_allowed(ip: str) -> Optional[int]:
    """Per-IP cap for POST /resend-verification (unauthenticated mail sender)."""
    return await _check_ip_cap(
        f"resend_verify:ip:{ip}", MAX_RESENDS_PER_IP, RESEND_WINDOW_SECONDS,
        "resend-throttle",
    )
