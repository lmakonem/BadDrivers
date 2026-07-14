"""
Outbound email (SMTP) service.

Design constraints:
- No new dependencies: stdlib smtplib run via asyncio.to_thread (the API's
  event loop must never block on a mail server).
- Fail-safe: a mail failure must NEVER break the calling flow (registration
  still succeeds if the mail provider is down). send_email returns a bool.
- Works unconfigured: when SMTP_HOST is empty the rendered message — including
  the verification link — is written to the application log at INFO with a
  clear marker, so dev and not-yet-configured prod keep a working flow.
"""

import asyncio
import logging
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr

from app.core.config import settings

logger = logging.getLogger(__name__)

SMTP_TIMEOUT_SECONDS = 20


def email_configured() -> bool:
    """True when a real SMTP relay is configured."""
    return bool(settings.SMTP_HOST)


def _smtp_send(msg: EmailMessage) -> None:
    """Blocking SMTP delivery (runs in a worker thread). Raises on failure."""
    context = ssl.create_default_context()
    if settings.SMTP_PORT == 465:
        # Implicit TLS
        with smtplib.SMTP_SSL(
            settings.SMTP_HOST, settings.SMTP_PORT,
            timeout=SMTP_TIMEOUT_SECONDS, context=context,
        ) as server:
            if settings.SMTP_USERNAME:
                server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
            server.send_message(msg)
    else:
        with smtplib.SMTP(
            settings.SMTP_HOST, settings.SMTP_PORT, timeout=SMTP_TIMEOUT_SECONDS
        ) as server:
            if settings.SMTP_STARTTLS:
                server.starttls(context=context)
            if settings.SMTP_USERNAME:
                server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
            server.send_message(msg)


async def send_email(
    to_email: str,
    subject: str,
    text_body: str,
    html_body: str | None = None,
) -> bool:
    """
    Send one email. Returns True on success, False on any failure.
    Never raises — callers (registration, resend) must not break on mail errors.
    """
    msg = EmailMessage()
    msg["From"] = formataddr((settings.EMAIL_FROM_NAME, settings.EMAIL_FROM))
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(text_body)
    if html_body:
        msg.add_alternative(html_body, subtype="html")

    if not email_configured():
        # Console-mode delivery: keep the flow alive and make the content
        # (e.g. the verification link) retrievable from the app log.
        logger.info(
            "EMAIL (console mode — SMTP_HOST not set) to=%s subject=%r\n%s",
            to_email, subject, text_body,
        )
        return True

    try:
        await asyncio.to_thread(_smtp_send, msg)
        logger.info("Email sent to=%s subject=%r", to_email, subject)
        return True
    except Exception as e:
        logger.error("Email send FAILED to=%s subject=%r: %s", to_email, subject, e)
        return False


# ── Message builders ──────────────────────────────────────────────────────────

def _verification_link(token: str) -> str:
    base = settings.PUBLIC_BASE_URL.rstrip("/")
    return f"{base}/verify-email?token={token}"


async def send_verification_email(to_email: str, name: str | None, token: str) -> bool:
    """Send the 'confirm your email address' message for a new registration."""
    link = _verification_link(token)
    greeting = f"Hi {name}," if name else "Hi,"
    hours = settings.EMAIL_VERIFICATION_EXPIRE_HOURS

    text = (
        f"{greeting}\n\n"
        f"Welcome to JichoSec — the watchful eye over Africa's cyberspace.\n\n"
        f"Please confirm your email address by opening this link "
        f"(valid for {hours} hours):\n\n"
        f"{link}\n\n"
        f"If you did not create this account, you can ignore this email.\n\n"
        f"— The JichoSec team\n"
    )
    html = f"""\
<div style="font-family:Arial,Helvetica,sans-serif;max-width:560px;margin:0 auto;
            background:#0B1220;color:#E7ECF4;padding:32px;border-radius:12px">
  <h2 style="color:#F5B301;margin:0 0 8px">JichoSec</h2>
  <p style="color:#9AA7BD;margin:0 0 24px">The watchful eye over Africa's cyberspace</p>
  <p>{greeting}</p>
  <p>Welcome to JichoSec. Please confirm your email address to finish setting up
     your account. This link is valid for {hours} hours.</p>
  <p style="text-align:center;margin:32px 0">
    <a href="{link}"
       style="background:#F5B301;color:#0B1220;text-decoration:none;font-weight:bold;
              padding:12px 28px;border-radius:8px;display:inline-block">
      Verify my email
    </a>
  </p>
  <p style="color:#9AA7BD;font-size:13px">Or copy this link into your browser:<br>
    <a href="{link}" style="color:#38BDF8;word-break:break-all">{link}</a></p>
  <p style="color:#9AA7BD;font-size:13px">If you did not create this account,
     you can safely ignore this email.</p>
</div>
"""
    return await send_email(
        to_email,
        "Verify your email — JichoSec",
        text,
        html,
    )
