"""
ASM (Attack Surface Management) PostgreSQL models.

Each customer (ASMClient) gets a fully isolated space:
  - PostgreSQL rows scoped by owner_user_id + client_id
  - Elasticsearch indices prefixed  asm_client_{id}_*
  - Celery tasks carry client_id as metadata

Architecture mirrors enterprise tools (Censys ASM / Defender EASM):
  Client → DiscoveryGroup (seeds) → [async scan] → ES assets/findings/changes
"""

from datetime import datetime
from typing import Optional, List
from sqlalchemy import (
    String, Boolean, Integer, Float, DateTime,
    ForeignKey, Text, JSON, Index
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin


class ASMClient(Base, TimestampMixin):
    """
    One organisation being monitored. Owned by a single JichoDNS user.

    Each client gets fully-isolated Elasticsearch indices so data from
    different customers never mixes:
        asm_client_{id}_assets
        asm_client_{id}_findings
        asm_client_{id}_changes
        asm_client_{id}_ti_hits
    """

    __tablename__ = "asm_clients"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    owner_user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # ── Identity ──────────────────────────────────────────────────────────────
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    industry: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    country_code: Mapped[Optional[str]] = mapped_column(String(5), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # ── SOC context ───────────────────────────────────────────────────────────
    # Who inside the client org owns external security
    asset_owner: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    # e.g. "Finance", "Core Banking", "Mobile"
    business_unit: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    # Primary domains (comma-separated) — quick-ref without going to discovery groups
    primary_domains: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Contact email for alert notifications
    contact_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # ── Alert / webhook config ────────────────────────────────────────────────
    # Outbound webhook URL for new critical findings
    webhook_url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    # JSON array of notification triggers:
    # ["critical_finding","new_asset","ti_hit","cert_expiry","port_opened"]
    notify_on: Mapped[Optional[dict]] = mapped_column(JSON, default=list)

    # ── Status ────────────────────────────────────────────────────────────────
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    # ── Scan configuration ────────────────────────────────────────────────────
    # Human-readable label stored for display (derived from scan_interval_minutes)
    scan_schedule: Mapped[str] = mapped_column(String(50), default="every_24h")
    # Canonical interval in minutes.  0 = manual only.
    # Allowed values: 0, 30, 60, 240, 360, 480, 720, 1440
    scan_interval_minutes: Mapped[int] = mapped_column(Integer, default=1440)
    last_scan_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    # next_scan_at is set to last_scan_at + scan_interval_minutes after every scan.
    # The beat task runs every 30 min and dispatches any client where next_scan_at <= now.
    next_scan_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_scan_job_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # ── Risk summary (cached — refreshed after every scan) ────────────────────
    total_assets: Mapped[int] = mapped_column(Integer, default=0)
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    critical_findings: Mapped[int] = mapped_column(Integer, default=0)
    high_findings: Mapped[int] = mapped_column(Integer, default=0)
    # Composite risk score 0–100
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    # Risk grade A–F
    risk_grade: Mapped[str] = mapped_column(String(2), default="?")
    # Assets seen in threat-intel feeds
    ti_hit_count: Mapped[int] = mapped_column(Integer, default=0)
    # Open ports count
    open_ports: Mapped[int] = mapped_column(Integer, default=0)
    # SSL expiry issues
    ssl_issues: Mapped[int] = mapped_column(Integer, default=0)

    # ── Relationships ─────────────────────────────────────────────────────────
    discovery_groups: Mapped[List["ASMDiscoveryGroup"]] = relationship(
        back_populates="client", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_asm_clients_owner_slug", "owner_user_id", "slug", unique=True),
    )

    # ── ES index helpers ──────────────────────────────────────────────────────

    @property
    def es_prefix(self) -> str:
        return f"asm_client_{self.id}"

    @property
    def assets_index(self) -> str:
        return f"{self.es_prefix}_assets"

    @property
    def findings_index(self) -> str:
        return f"{self.es_prefix}_findings"

    @property
    def changes_index(self) -> str:
        return f"{self.es_prefix}_changes"

    @property
    def ti_hits_index(self) -> str:
        return f"{self.es_prefix}_ti_hits"

    # ── Schedule helpers ──────────────────────────────────────────────────────

    # Map interval → canonical label (used as scan_schedule display value)
    INTERVAL_LABELS: dict = {
        0:    "manual",
        30:   "every_30m",
        60:   "every_1h",
        240:  "every_4h",
        360:  "every_6h",
        480:  "every_8h",
        720:  "every_12h",
        1440: "every_24h",
    }

    @classmethod
    def label_for(cls, minutes: int) -> str:
        return cls.INTERVAL_LABELS.get(minutes, f"every_{minutes}m")

    def set_next_scan_from_now(self) -> None:
        """Compute and store next_scan_at based on scan_interval_minutes."""
        from datetime import datetime, timedelta
        if self.scan_interval_minutes <= 0:
            self.next_scan_at = None  # manual only
        else:
            base = self.last_scan_at or datetime.utcnow()
            self.next_scan_at = base + timedelta(minutes=self.scan_interval_minutes)

    def __repr__(self) -> str:
        return f"<ASMClient {self.name} (id={self.id})>"


class ASMDiscoveryGroup(Base, TimestampMixin):
    """
    A named collection of seeds that define what to scan for a client.

    Seed types supported:
        domain    → e.g. "safaricom.co.ke"
        ip_range  → e.g. "196.201.0.0/18"
        asn       → e.g. "AS36908"
        org_name  → e.g. "Safaricom" (drives WHOIS org search)
        email_domain → e.g. "safaricom.co.ke" (drives cert & OSINT search)

    Scan modules per group (all boolean toggles):
        include_subdomains  — crt.sh + SecurityTrails + Shodan DNS
        include_ports       — TCP connect scan of COMMON_PORTS
        include_ssl         — TLS cert grab + analysis
        include_whois       — WHOIS/RDAP enrichment
        include_ct_logs     — Live crt.sh CT stream monitoring
        include_http_checks — HTTP header + tech fingerprint checks
        include_nuclei      — Nuclei-style CVE/misconfiguration templates
        include_ti_enrich   — Join against IOC index for TI context
    """

    __tablename__ = "asm_discovery_groups"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    client_id: Mapped[int] = mapped_column(
        ForeignKey("asm_clients.id", ondelete="CASCADE"), nullable=False, index=True
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    # Seeds: list of {type: str, value: str} dicts
    seeds: Mapped[Optional[dict]] = mapped_column(JSON, default=list)

    # ── Scan modules ──────────────────────────────────────────────────────────
    include_subdomains: Mapped[bool] = mapped_column(Boolean, default=True)
    include_ports: Mapped[bool] = mapped_column(Boolean, default=True)
    include_ssl: Mapped[bool] = mapped_column(Boolean, default=True)
    include_whois: Mapped[bool] = mapped_column(Boolean, default=True)
    include_ct_logs: Mapped[bool] = mapped_column(Boolean, default=True)
    include_http_checks: Mapped[bool] = mapped_column(Boolean, default=True)
    include_nuclei: Mapped[bool] = mapped_column(Boolean, default=False)
    include_ti_enrich: Mapped[bool] = mapped_column(Boolean, default=True)

    # ── Discovery state ───────────────────────────────────────────────────────
    last_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_run_job_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    assets_discovered: Mapped[int] = mapped_column(Integer, default=0)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)

    # ── Relationship ──────────────────────────────────────────────────────────
    client: Mapped["ASMClient"] = relationship(back_populates="discovery_groups")

    def __repr__(self) -> str:
        return f"<ASMDiscoveryGroup {self.name} (client_id={self.client_id})>"
