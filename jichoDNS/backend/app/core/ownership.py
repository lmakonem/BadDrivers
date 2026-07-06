"""
Multi-tenant ownership + credential redaction helpers.

Reports and brand monitors live in Elasticsearch (indices `threat_reports`
and `brand_monitors`) and carry an `owner_user_id` field; ownership for those
is enforced inline in their endpoints. Credential exposures are a global
breach corpus scoped per-tenant by *owned domains* (this module resolves the
owned-domain set) and every credential read path is redacted here.
"""

from __future__ import annotations

from typing import Iterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.models.intel import OrgWatchlist
from app.models.asm import ASMClient

# ES doc field that records which user owns a report / brand monitor.
OWNER_FIELD = "owner_user_id"

# Secret fields that must NEVER be returned to an API client.
CREDENTIAL_SECRET_FIELDS = ("password", "password_hash")


def bare_domain(value: str) -> str:
    """Normalise a domain / URL / email-domain to a bare lowercased hostname."""
    d = (value or "").strip().lower()
    if "@" in d:                      # tolerate a full email address
        d = d.rsplit("@", 1)[-1]
    if "://" in d:                    # strip scheme
        d = d.split("://", 1)[1]
    d = d.split("/", 1)[0]            # strip path
    d = d.split(":", 1)[0]            # strip port
    if d.startswith("www."):          # correct prefix strip (NOT str.lstrip)
        d = d[4:]
    return d


def redact_credential(doc: dict) -> dict:
    """Strip secret fields from one credential doc (in place) and return it."""
    if isinstance(doc, dict):
        for f in CREDENTIAL_SECRET_FIELDS:
            doc.pop(f, None)
    return doc


def redact_credentials(docs: Iterable[dict]) -> list:
    return [redact_credential(d) for d in docs]


async def get_owned_domains(user: User, db: AsyncSession) -> set:
    """
    Bare domains this user may query credential data for. Union of:
      * OrgWatchlist.domains for active watchlists owned by the user
      * ASMClient.primary_domains for clients owned by the user
    Admins are NOT special-cased here — callers grant admins full access
    (skip the domain filter) BEFORE calling this.
    """
    owned: set = set()

    wl_rows = await db.execute(
        select(OrgWatchlist.domains).where(
            OrgWatchlist.user_id == user.id,
            OrgWatchlist.is_active.is_(True),
        )
    )
    for (domains,) in wl_rows.all():
        for d in (domains or []):
            if d:
                owned.add(bare_domain(d))

    asm_rows = await db.execute(
        select(ASMClient.primary_domains).where(ASMClient.owner_user_id == user.id)
    )
    for (primary,) in asm_rows.all():
        for d in (primary or "").replace("\n", ",").split(","):
            d = d.strip()
            if d:
                owned.add(bare_domain(d))

    owned.discard("")
    return owned
