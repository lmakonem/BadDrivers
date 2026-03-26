"""
Intelligence models — watchlists, VIP profiles, dark web findings, credential exposures.

These support the intel stack (Tor/TorBot, SpiderFoot, MISP correlation).
"""

from datetime import datetime
from typing import List, Optional

from sqlalchemy import String, Text, Integer, Boolean, DateTime, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import ARRAY, JSONB

from .base import Base, TimestampMixin


class OrgWatchlist(Base, TimestampMixin):
    """
    Organization watchlist — domains, brands, and keywords to monitor
    across dark web, OSINT, and credential leak sources.
    """
    __tablename__ = "org_watchlists"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    org_name: Mapped[str] = mapped_column(String(255), nullable=False)

    # Watch targets
    domains: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String), nullable=True)
    brand_terms: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String), nullable=True)
    keywords: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String), nullable=True)
    email_patterns: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String), nullable=True)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    scan_interval_hours: Mapped[int] = mapped_column(Integer, default=24)
    last_scan_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Relationships
    vip_profiles: Mapped[List["VIPProfile"]] = relationship(back_populates="watchlist")


class VIPProfile(Base, TimestampMixin):
    """
    VIP / executive profile to monitor for credential leaks,
    impersonation, and dark web mentions.
    """
    __tablename__ = "vip_profiles"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    watchlist_id: Mapped[int] = mapped_column(ForeignKey("org_watchlists.id"), index=True)

    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    title: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    emails: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String), nullable=True)
    phone_numbers: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String), nullable=True)
    social_handles: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    alert_on_mention: Mapped[bool] = mapped_column(Boolean, default=True)
    alert_on_credential: Mapped[bool] = mapped_column(Boolean, default=True)

    watchlist: Mapped["OrgWatchlist"] = relationship(back_populates="vip_profiles")


class BrandExposure(Base, TimestampMixin):
    """
    Brand exposure event — typosquatting, phishing, impersonation,
    dark web marketplace listing, etc.
    """
    __tablename__ = "brand_exposures"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    watchlist_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("org_watchlists.id"), nullable=True, index=True
    )

    # What was found
    exposure_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    # Types: typosquat, phishing_page, dark_market_listing, paste_mention,
    #        social_impersonation, app_clone, credential_dump

    brand_term_matched: Mapped[str] = mapped_column(String(255), nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)  # torbot, spiderfoot, misp
    source_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    severity: Mapped[str] = mapped_column(String(16), default="medium")  # critical, high, medium, low
    status: Mapped[str] = mapped_column(String(32), default="open", index=True)
    # Status: open, investigating, mitigated, false_positive

    details: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    misp_event_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        Index("ix_brand_exposures_type_status", "exposure_type", "status"),
    )


class CredentialExposure(Base, TimestampMixin):
    """
    Credential exposure — leaked email/password pairs, stealer logs,
    combo lists found on dark web or in breach databases.
    """
    __tablename__ = "credential_exposures"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    watchlist_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("org_watchlists.id"), nullable=True, index=True
    )
    vip_profile_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("vip_profiles.id"), nullable=True, index=True
    )

    # Exposed credential
    email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    username: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    domain: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    password_hash: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    password_type: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    # Types: plaintext, md5, sha1, sha256, bcrypt, ntlm, unknown

    # Source info
    source: Mapped[str] = mapped_column(String(64), nullable=False)  # torbot, spiderfoot, misp, have_i_been_pwned
    source_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)  # breach name
    source_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    discovered_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    breach_date: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    severity: Mapped[str] = mapped_column(String(16), default="high")
    status: Mapped[str] = mapped_column(String(32), default="new", index=True)
    # Status: new, notified, reset, mitigated

    misp_event_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    extra_data: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    __table_args__ = (
        Index("ix_cred_exposures_email_source", "email", "source"),
    )


class VIPAlert(Base, TimestampMixin):
    """Alert generated when a VIP is mentioned or exposed."""
    __tablename__ = "vip_alerts"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    vip_profile_id: Mapped[int] = mapped_column(ForeignKey("vip_profiles.id"), index=True)

    alert_type: Mapped[str] = mapped_column(String(64), nullable=False)
    # Types: credential_leak, dark_web_mention, social_impersonation, email_in_breach

    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="high")
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    source_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    status: Mapped[str] = mapped_column(String(32), default="new", index=True)
    # Status: new, acknowledged, investigating, resolved

    details: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    misp_event_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
