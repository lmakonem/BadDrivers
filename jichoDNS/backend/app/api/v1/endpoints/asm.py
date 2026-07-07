"""
Attack Surface Management (ASM) API Endpoints

Supports multi-client management:
  - CRUD for ASMClient (organizations being monitored)
  - CRUD for DiscoveryGroups and seeds
  - Asset discovery (background Celery task or synchronous)
  - Asset / vulnerability / change querying per client
  - Per-scan utilities: DNS, SSL, ports, subdomains, services
"""

import asyncio
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select, func, text, or_, and_
from sqlalchemy.ext.asyncio import AsyncSession

import time as _time
from collections import defaultdict, deque

from app.api.deps import get_current_user, get_db
from app.core.config import settings
from app.core.net_guard import resolve_public_ips, extract_host, SSRFError
from app.models.user import User
from app.models.asm import ASMClient, ASMDiscoveryGroup
from app.services.attack_surface import AttackSurfaceManager, AssetType, ChangeType
from app.services.elasticsearch import es_service
from app.services.asm_enterprise import ASMEnterpriseService

# Tiers that have access to ASM features — enterprise-locked to match the UI
ASM_TIERS = {"enterprise"}


def _require_asm_tier(user: User) -> None:
    """Raise 403 if the user's tier does not include ASM access."""
    if user.is_admin:
        return
    if user.tier not in ASM_TIERS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Attack Surface Management requires an Enterprise subscription.",
        )


async def _user_can_access_client(client_id: int, user: User, db: AsyncSession) -> bool:
    """Check if a user can access a client — owner, admin with access grant, or is_admin."""
    if user.is_admin:
        return True  # platform admins can access all clients
    # Non-admin: must have an explicit access grant in asm_client_access
    row = await db.execute(
        text("SELECT 1 FROM asm_client_access WHERE client_id=:cid AND user_id=:uid LIMIT 1"),
        {"cid": client_id, "uid": user.id},
    )
    return row.fetchone() is not None


async def _require_client_access(client_id: int, user: User, db: AsyncSession) -> ASMClient:
    """Load client and verify access, raise 404 if not found or not accessible."""
    result = await db.execute(select(ASMClient).where(ASMClient.id == client_id))
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    if not await _user_can_access_client(client_id, user, db):
        raise HTTPException(status_code=404, detail="Client not found")
    return client


async def _accessible_client_ids(user: User, db: AsyncSession) -> list:
    """Return list of client IDs this user can access."""
    if user.is_admin:
        # Admins see all clients — return all client IDs
        rows = await db.execute(text("SELECT id FROM asm_clients"))
        return [r[0] for r in rows.fetchall()]
    rows = await db.execute(
        text("SELECT client_id FROM asm_client_access WHERE user_id=:uid"),
        {"uid": user.id},
    )
    return [r[0] for r in rows.fetchall()]


# =============================================================================
# SSRF / abuse guards for on-demand check + scan endpoints
# =============================================================================

# Per-user rolling-window scan counter (process-local; see net_guard notes).
_SCAN_TIMES: dict = defaultdict(deque)


def _enforce_scan_rate(user: User) -> None:
    """Simple per-user rolling-window cap on on-demand scans/checks (429)."""
    window = float(getattr(settings, "ASM_SCAN_RATE_WINDOW_SECONDS", 60))
    base = int(getattr(settings, "ASM_SCAN_RATE_MAX", 20))
    limit = base * 5 if (user.is_admin or user.tier == "enterprise") else base
    now = _time.monotonic()
    dq = _SCAN_TIMES[user.id]
    while dq and now - dq[0] > window:
        dq.popleft()
    if len(dq) >= limit:
        raise HTTPException(
            status_code=429,
            detail="Scan rate limit exceeded. Please wait a moment and retry.",
        )
    dq.append(now)


async def _owned_domain_suffixes(user: User, db: AsyncSession) -> set:
    """Lowercased root domains the user owns (client primary_domains + seeds)."""
    cids = await _accessible_client_ids(user, db)
    if not cids:
        return set()
    suffixes: set = set()
    pd_rows = await db.execute(
        select(ASMClient.primary_domains).where(ASMClient.id.in_(cids))
    )
    for (pd,) in pd_rows.all():
        if pd:
            for d in str(pd).split(","):
                d = d.strip().lower().rstrip(".")
                if d:
                    suffixes.add(d)
    seed_rows = await db.execute(
        select(ASMDiscoveryGroup.seeds).where(ASMDiscoveryGroup.client_id.in_(cids))
    )
    for (seeds,) in seed_rows.all():
        for seed in (seeds or []):
            if isinstance(seed, dict) and seed.get("value"):
                d = str(seed["value"]).strip().lower().rstrip(".")
                if d:
                    suffixes.add(d)
    return suffixes


def _host_within_owned(host: str, suffixes: set) -> bool:
    h = (host or "").strip().lower().rstrip(".")
    return any(h == s or h.endswith("." + s) for s in suffixes)


async def _assert_target_owned(host: str, user: User, db: AsyncSession) -> None:
    """403 unless host is (a subdomain of) a domain the caller owns. Admins bypass."""
    if user.is_admin:
        return
    suffixes = await _owned_domain_suffixes(user, db)
    if not _host_within_owned(host, suffixes):
        raise HTTPException(
            status_code=403,
            detail=("Target is not within a domain registered to your ASM clients. "
                    "Add it as a client primary domain or a discovery-group seed first."),
        )


async def _precheck_target(
    target: str,
    user: User,
    db: AsyncSession,
    *,
    resolve: bool = True,
) -> str:
    """
    Shared guard for on-demand ASM check/scan endpoints:
      1. per-user scan rate cap (429)
      2. ownership: target host must belong to a domain the caller owns (403; admins bypass)
      3. SSRF: resolve host and reject if any address is non-public (400) — when resolve=True
    Returns the extracted hostname.
    """
    _enforce_scan_rate(user)
    host = extract_host(target)
    if not host:
        raise HTTPException(status_code=400, detail="Invalid target.")
    await _assert_target_owned(host, user, db)
    if resolve:
        try:
            await resolve_public_ips(host)
        except SSRFError as e:
            raise HTTPException(status_code=400, detail=f"Target not permitted: {e}")
    return host


router = APIRouter()

# =============================================================================
# Per-client ASM service factory (keyed by client_id)
# =============================================================================

_asm_cache: dict = {}
_ent_cache: dict = {}


async def _get_asm(client_id: Optional[int] = None) -> AttackSurfaceManager:
    """Return a cached AttackSurfaceManager scoped to client_id (discovery engine)."""
    key = client_id or 0
    if key not in _asm_cache:
        await es_service.connect()
        _asm_cache[key] = AttackSurfaceManager(
            es_client=es_service.client,
            client_id=client_id,
        )
    svc = _asm_cache[key]
    if svc.es_client is None and es_service.client:
        svc.es_client = es_service.client
    return svc


async def _get_ent(client_id: int) -> ASMEnterpriseService:
    """Return a cached ASMEnterpriseService scoped to client_id (enrichment + findings)."""
    if client_id not in _ent_cache:
        await es_service.connect()
        _ent_cache[client_id] = ASMEnterpriseService(
            es_client=es_service.client,
            client_id=client_id,
        )
    svc = _ent_cache[client_id]
    if svc.es is None and es_service.client:
        svc.es = es_service.client
    return svc


# =============================================================================
# Pydantic schemas
# =============================================================================

# Valid scan intervals in minutes.  0 = manual only.
VALID_INTERVALS = {0, 30, 60, 240, 360, 480, 720, 1440}


class ClientCreate(BaseModel):
    name: str
    industry: Optional[str] = None
    country_code: Optional[str] = None
    description: Optional[str] = None
    asset_owner: Optional[str] = None
    business_unit: Optional[str] = None
    contact_email: Optional[str] = None
    webhook_url: Optional[str] = None
    notify_on: Optional[List[str]] = None
    # Canonical interval in minutes (0 = manual).
    # Allowed: 0, 30, 60, 240, 360, 480, 720, 1440
    scan_interval_minutes: int = 1440


class ClientUpdate(BaseModel):
    name: Optional[str] = None
    industry: Optional[str] = None
    country_code: Optional[str] = None
    description: Optional[str] = None
    asset_owner: Optional[str] = None
    business_unit: Optional[str] = None
    contact_email: Optional[str] = None
    webhook_url: Optional[str] = None
    notify_on: Optional[List[str]] = None
    scan_interval_minutes: Optional[int] = None
    is_active: Optional[bool] = None


class DiscoveryGroupCreate(BaseModel):
    name: str
    description: Optional[str] = None
    seeds: List[dict] = Field(default_factory=list)
    include_subdomains: bool = True
    include_ports: bool = True
    include_ssl: bool = True
    include_whois: bool = True
    include_ct_logs: bool = True
    include_http_checks: bool = True
    include_nuclei: bool = False
    include_ti_enrich: bool = True


class DiscoveryGroupUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    seeds: Optional[List[dict]] = None
    include_subdomains: Optional[bool] = None
    include_ports: Optional[bool] = None
    include_ssl: Optional[bool] = None
    include_whois: Optional[bool] = None
    include_ct_logs: Optional[bool] = None
    include_http_checks: Optional[bool] = None
    include_nuclei: Optional[bool] = None
    include_ti_enrich: Optional[bool] = None
    is_active: Optional[bool] = None


class DiscoverRequest(BaseModel):
    domain: str
    include_subdomains: bool = True
    include_ports: bool = True
    include_ssl: bool = True
    client_id: Optional[int] = None


class ScanRequest(BaseModel):
    target: str
    scan_type: str = "full"   # full | ports | ssl | vulnerabilities
    client_id: Optional[int] = None


def _slug(name: str) -> str:
    import re
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:100]


def _client_response(c: ASMClient) -> dict:
    return {
        "id": c.id,
        "name": c.name,
        "slug": c.slug,
        "industry": c.industry,
        "country_code": c.country_code,
        "description": c.description,
        "asset_owner": c.asset_owner,
        "business_unit": c.business_unit,
        "contact_email": c.contact_email,
        "webhook_url": c.webhook_url,
        "notify_on": c.notify_on or [],
        "is_active": c.is_active,
        "scan_schedule": c.scan_schedule,
        "scan_interval_minutes": c.scan_interval_minutes,
        "last_scan_at": c.last_scan_at.isoformat() if c.last_scan_at else None,
        "next_scan_at": c.next_scan_at.isoformat() if c.next_scan_at else None,
        "total_assets": c.total_assets,
        "total_findings": c.total_findings,
        "critical_findings": c.critical_findings,
        "high_findings": c.high_findings,
        "risk_score": c.risk_score,
        "risk_grade": c.risk_grade,
        "ti_hit_count": c.ti_hit_count,
        "open_ports": c.open_ports,
        "ssl_issues": c.ssl_issues,
        "created_at": c.created_at.isoformat(),
        "updated_at": c.updated_at.isoformat(),
    }


def _group_response(g: ASMDiscoveryGroup) -> dict:
    return {
        "id": g.id,
        "client_id": g.client_id,
        "name": g.name,
        "description": g.description,
        "is_active": g.is_active,
        "seeds": g.seeds or [],
        "include_subdomains": g.include_subdomains,
        "include_ports": g.include_ports,
        "include_ssl": g.include_ssl,
        "include_whois": g.include_whois,
        "include_ct_logs": g.include_ct_logs,
        "include_http_checks": g.include_http_checks,
        "include_nuclei": g.include_nuclei,
        "include_ti_enrich": g.include_ti_enrich,
        "last_run_at": g.last_run_at.isoformat() if g.last_run_at else None,
        "assets_discovered": g.assets_discovered,
        "findings_count": g.findings_count,
        "created_at": g.created_at.isoformat(),
    }


# =============================================================================
# Static metadata endpoints  (must be before any /{param} dynamic routes)
# =============================================================================

@router.get("/schedules")
async def list_schedules():
    """Return all valid scan schedules with labels and intervals."""
    return {
        "schedules": [
            {"label": "Manual only",    "value": "manual",     "interval_minutes": 0},
            {"label": "Every 30 min",   "value": "every_30m",  "interval_minutes": 30},
            {"label": "Every 1 hour",   "value": "every_1h",   "interval_minutes": 60},
            {"label": "Every 4 hours",  "value": "every_4h",   "interval_minutes": 240},
            {"label": "Every 6 hours",  "value": "every_6h",   "interval_minutes": 360},
            {"label": "Every 8 hours",  "value": "every_8h",   "interval_minutes": 480},
            {"label": "Every 12 hours", "value": "every_12h",  "interval_minutes": 720},
            {"label": "Every 24 hours", "value": "every_24h",  "interval_minutes": 1440},
        ]
    }


# =============================================================================
# Client CRUD  (fixed paths BEFORE /{client_id} dynamic routes)
# =============================================================================

@router.get("/clients")
async def list_clients(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all ASM clients this user has access to."""
    _require_asm_tier(current_user)
    accessible_ids = await _accessible_client_ids(current_user, db)
    if not accessible_ids:
        return {"clients": [], "total": 0}
    result = await db.execute(
        select(ASMClient)
        .where(ASMClient.id.in_(accessible_ids))
        .order_by(ASMClient.name.asc())
    )
    clients = result.scalars().all()
    return {"clients": [_client_response(c) for c in clients], "total": len(clients)}


@router.post("/clients")
async def create_client(
    body: ClientCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a new ASM client (organization to monitor)."""
    _require_asm_tier(current_user)

    interval = body.scan_interval_minutes
    if interval not in VALID_INTERVALS:
        raise HTTPException(
            status_code=400,
            detail=f"scan_interval_minutes must be one of {sorted(VALID_INTERVALS)}",
        )

    slug = _slug(body.name)
    existing = await db.execute(
        select(ASMClient).where(
            ASMClient.id.in_(await _accessible_client_ids(current_user, db)),
            ASMClient.slug == slug,
        )
    )
    if existing.scalar_one_or_none():
        slug = f"{slug}-{int(datetime.utcnow().timestamp())}"

    client = ASMClient(
        owner_user_id=current_user.id,
        name=body.name,
        slug=slug,
        industry=body.industry,
        country_code=body.country_code,
        description=body.description,
        asset_owner=body.asset_owner,
        business_unit=body.business_unit,
        contact_email=body.contact_email,
        webhook_url=body.webhook_url,
        notify_on=body.notify_on or [],
        scan_interval_minutes=interval,
        scan_schedule=ASMClient.label_for(interval),
    )
    # Set next_scan_at if auto-scheduled
    client.set_next_scan_from_now()
    db.add(client)
    await db.commit()
    await db.refresh(client)
    # Grant the creator access in the access control table
    await db.execute(
        text("INSERT INTO asm_client_access (client_id, user_id) VALUES (:cid, :uid) ON CONFLICT DO NOTHING"),
        {"cid": client.id, "uid": current_user.id},
    )
    await db.commit()
    return _client_response(client)


@router.get("/clients/{client_id}")
async def get_client(
    client_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a specific ASM client."""
    result = await db.execute(
        select(ASMClient).where(
            ASMClient.id == client_id,
            ASMClient.id.in_(await _accessible_client_ids(current_user, db)),
        )
    )
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    return _client_response(client)


@router.put("/clients/{client_id}")
async def update_client(
    client_id: int,
    body: ClientUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update an ASM client."""
    result = await db.execute(
        select(ASMClient).where(
            ASMClient.id == client_id,
            ASMClient.id.in_(await _accessible_client_ids(current_user, db)),
        )
    )
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    updates = body.model_dump(exclude_none=True)

    if "scan_interval_minutes" in updates:
        interval = updates["scan_interval_minutes"]
        if interval not in VALID_INTERVALS:
            raise HTTPException(
                status_code=400,
                detail=f"scan_interval_minutes must be one of {sorted(VALID_INTERVALS)}",
            )
        updates["scan_schedule"] = ASMClient.label_for(interval)

    for field, value in updates.items():
        setattr(client, field, value)

    # Recompute next_scan_at whenever the interval changes
    if "scan_interval_minutes" in updates:
        client.set_next_scan_from_now()

    await db.commit()
    await db.refresh(client)
    return _client_response(client)


@router.delete("/clients/{client_id}")
async def delete_client(
    client_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete an ASM client and all its data."""
    result = await db.execute(
        select(ASMClient).where(
            ASMClient.id == client_id,
            ASMClient.id.in_(await _accessible_client_ids(current_user, db)),
        )
    )
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    await db.delete(client)
    await db.commit()
    # Evict both cached services for this client
    _asm_cache.pop(client_id, None)
    _ent_cache.pop(client_id, None)
    return {"status": "deleted", "client_id": client_id}


# =============================================================================
# Discovery Group CRUD
# =============================================================================

@router.get("/clients/{client_id}/groups")
async def list_groups(
    client_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List discovery groups for a client."""
    # Verify client ownership
    c = await db.execute(
        select(ASMClient).where(
            ASMClient.id == client_id,
            ASMClient.id.in_(await _accessible_client_ids(current_user, db)),
        )
    )
    if not c.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Client not found")

    result = await db.execute(
        select(ASMDiscoveryGroup)
        .where(ASMDiscoveryGroup.client_id == client_id)
        .order_by(ASMDiscoveryGroup.created_at.desc())
    )
    groups = result.scalars().all()
    return {"groups": [_group_response(g) for g in groups], "total": len(groups)}


@router.post("/clients/{client_id}/groups")
async def create_group(
    client_id: int,
    body: DiscoveryGroupCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a discovery group for a client."""
    c = await db.execute(
        select(ASMClient).where(
            ASMClient.id == client_id,
            ASMClient.id.in_(await _accessible_client_ids(current_user, db)),
        )
    )
    if not c.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Client not found")

    group = ASMDiscoveryGroup(
        client_id=client_id,
        name=body.name,
        description=body.description,
        seeds=body.seeds,
        include_subdomains=body.include_subdomains,
        include_ports=body.include_ports,
        include_ssl=body.include_ssl,
        include_whois=body.include_whois,
        include_ct_logs=body.include_ct_logs,
        include_http_checks=body.include_http_checks,
        include_nuclei=body.include_nuclei,
        include_ti_enrich=body.include_ti_enrich,
    )
    db.add(group)
    await db.commit()
    await db.refresh(group)
    return _group_response(group)


@router.put("/clients/{client_id}/groups/{group_id}")
async def update_group(
    client_id: int,
    group_id: int,
    body: DiscoveryGroupUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update a discovery group."""
    c = await db.execute(
        select(ASMClient).where(
            ASMClient.id == client_id,
            ASMClient.id.in_(await _accessible_client_ids(current_user, db)),
        )
    )
    if not c.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Client not found")

    result = await db.execute(
        select(ASMDiscoveryGroup).where(
            ASMDiscoveryGroup.id == group_id,
            ASMDiscoveryGroup.client_id == client_id,
        )
    )
    group = result.scalar_one_or_none()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    for field, value in body.model_dump(exclude_none=True).items():
        setattr(group, field, value)

    await db.commit()
    await db.refresh(group)
    return _group_response(group)


@router.delete("/clients/{client_id}/groups/{group_id}")
async def delete_group(
    client_id: int,
    group_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete a discovery group."""
    c = await db.execute(
        select(ASMClient).where(
            ASMClient.id == client_id,
            ASMClient.id.in_(await _accessible_client_ids(current_user, db)),
        )
    )
    if not c.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Client not found")

    result = await db.execute(
        select(ASMDiscoveryGroup).where(
            ASMDiscoveryGroup.id == group_id,
            ASMDiscoveryGroup.client_id == client_id,
        )
    )
    group = result.scalar_one_or_none()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    await db.delete(group)
    await db.commit()
    return {"status": "deleted", "group_id": group_id}


# =============================================================================
# Discovery — trigger scan for a client
# =============================================================================

@router.post("/clients/{client_id}/discover")
async def start_client_discovery(
    client_id: int,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Trigger full discovery for all active groups of a client.
    Runs all group seeds through the discovery engine (async, non-blocking).
    Returns immediately with job metadata; poll /clients/{id}/summary for results.
    """
    result = await db.execute(
        select(ASMClient).where(
            ASMClient.id == client_id,
            ASMClient.id.in_(await _accessible_client_ids(current_user, db)),
        )
    )
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    groups_result = await db.execute(
        select(ASMDiscoveryGroup).where(
            ASMDiscoveryGroup.client_id == client_id,
            ASMDiscoveryGroup.is_active == True,  # noqa: E712
        )
    )
    groups = groups_result.scalars().all()

    if not groups:
        raise HTTPException(
            status_code=400,
            detail="No active discovery groups. Add at least one group with seeds first.",
        )

    # Collect all domain seeds from all groups
    domains: List[str] = []
    for group in groups:
        for seed in (group.seeds or []):
            if seed.get("type") in ("domain", None) and seed.get("value"):
                domains.append(seed["value"])

    if not domains:
        raise HTTPException(
            status_code=400,
            detail="No domain seeds found in active groups.",
        )

    # Dispatch to Celery (non-blocking)
    try:
        from app.worker import run_asm_discovery
        task = run_asm_discovery.delay(client_id=client_id, domains=domains)
        job_id = task.id
    except Exception:
        # If Celery is unavailable fall back to background task
        job_id = f"bg-{client_id}-{int(datetime.utcnow().timestamp())}"

        async def _bg():
            asm = await _get_asm(client_id)
            for domain in domains:
                try:
                    await asm.discover_assets(domain=domain)
                except Exception as exc:
                    import logging
                    logging.getLogger(__name__).error(f"BG discovery failed for {domain}: {exc}")

        background_tasks.add_task(_bg)

    # Update last_scan_at and store the job id
    client.last_scan_at = datetime.utcnow()
    client.last_scan_job_id = job_id
    # next_scan_at will be recomputed by the worker after the scan finishes,
    # but set a provisional value now so the scheduler doesn't double-dispatch.
    client.set_next_scan_from_now()
    await db.commit()

    return {
        "status": "started",
        "client_id": client_id,
        "job_id": job_id,
        "domains": domains,
        "message": f"Discovery started for {len(domains)} domain(s) across {len(groups)} group(s)",
    }


@router.get("/clients/{client_id}/summary")
async def get_client_summary(
    client_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get attack surface summary for a specific client."""
    result = await db.execute(
        select(ASMClient).where(
            ASMClient.id == client_id,
            ASMClient.id.in_(await _accessible_client_ids(current_user, db)),
        )
    )
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    asm = await _get_asm(client_id)
    ent = await _get_ent(client_id)
    try:
        # Base discovery summary (asset counts, risk score from discovery scan)
        summary = await asm.get_summary()
        # Enterprise findings summary (enriched findings from enterprise pipeline)
        findings_summary = await ent.get_findings_summary()

        # Merge: prefer enterprise findings data where available
        total_findings = findings_summary.get("total_open", 0) or summary.get("total_vulnerabilities", 0)
        by_sev = findings_summary.get("by_severity", {})
        critical = by_sev.get("critical", 0) or summary.get("critical_vulnerabilities", 0)
        high = by_sev.get("high", 0) or summary.get("high_vulnerabilities", 0)

        # ── Cross-dataset enrichment ──────────────────────────────────────────
        # Pull brand exposures and credential leaks from the platform's other
        # datasets, correlated by the client's country code and name keywords.
        brand_hits = 0
        cred_hits = 0
        indicator_hits = 0
        region_risk: Optional[dict] = None
        try:
            # Brand exposures: match on client name keywords
            name_kw = client.name.split()[0].lower() if client.name else ""
            brand_res = await db.execute(
                text("""
                    SELECT COUNT(*) FROM brand_exposures be
                    JOIN org_watchlists ow ON be.watchlist_id = ow.id
                    WHERE ow.user_id = :uid
                """),
                {"uid": current_user.id},
            )
            brand_hits = brand_res.scalar() or 0

            # Credential exposures
            cred_res = await db.execute(
                text("""
                    SELECT COUNT(*) FROM credential_exposures ce
                    JOIN org_watchlists ow ON ce.watchlist_id = ow.id
                    WHERE ow.user_id = :uid
                """),
                {"uid": current_user.id},
            )
            cred_hits = cred_res.scalar() or 0

            # Threat indicators matching client country
            if client.country_code:
                ind_res = await db.execute(
                    text("""
                        SELECT COUNT(*) FROM indicators
                        WHERE country_code = :cc AND active = true
                    """),
                    {"cc": client.country_code},
                )
                indicator_hits = ind_res.scalar() or 0

                # Regional risk score for client's country
                reg_res = await db.execute(
                    text("""
                        SELECT overall_risk, c2_risk, exfil_risk, phishing_risk,
                               indicator_count, c2_count, exfil_count, phishing_count
                        FROM region_scores
                        WHERE country_code = :cc
                        ORDER BY aggregated_at DESC LIMIT 1
                    """),
                    {"cc": client.country_code},
                )
                row = reg_res.fetchone()
                if row:
                    region_risk = {
                        "overall_risk": row[0],
                        "c2_risk": row[1],
                        "exfil_risk": row[2],
                        "phishing_risk": row[3],
                        "indicator_count": row[4],
                        "c2_count": row[5],
                        "exfil_count": row[6],
                        "phishing_count": row[7],
                    }
        except Exception:
            pass  # Non-fatal — enrichment is best-effort

        # ── Risk score with all datasets ─────────────────────────────────────
        from app.services.asm_enterprise import compute_risk_score
        # Build synthetic finding list from severity counts so compute_risk_score
        # gets the full picture even without raw finding objects
        synthetic_findings = (
            [{"severity": "critical", "is_cisa_kev": False, "is_exploitable": False}] * critical +
            [{"severity": "high",     "is_cisa_kev": False, "is_exploitable": False}] * high +
            [{"severity": "medium",   "is_cisa_kev": False, "is_exploitable": False}] * by_sev.get("medium", 0) +
            [{"severity": "low",      "is_cisa_kev": False, "is_exploitable": False}] * by_sev.get("low", 0)
        )
        kev_count = findings_summary.get("kev_count", 0)
        exploitable_count = findings_summary.get("exploitable_count", 0)
        # Inject KEV/exploitable into synthetic findings for scoring
        for i in range(min(kev_count, len(synthetic_findings))):
            synthetic_findings[i]["is_cisa_kev"] = True
            synthetic_findings[i]["is_exploitable"] = True
        for i in range(min(exploitable_count, len(synthetic_findings))):
            synthetic_findings[i]["is_exploitable"] = True

        score, grade, factors = compute_risk_score(
            findings=synthetic_findings,
            ti_hits=summary.get("ti_hit_count", 0) or client.ti_hit_count,
            open_ports=summary.get("total_open_ports", 0),
            ssl_issues=summary.get("ssl_issues", 0),
            total_assets=summary.get("total_assets", 0),
        )

        # Boost score for brand/credential exposure
        if brand_hits > 0:
            score = min(score + min(brand_hits * 3, 10), 100.0)
            factors.append(f"{brand_hits} brand exposure(s) detected")
        if cred_hits > 0:
            score = min(score + min(cred_hits * 5, 15), 100.0)
            factors.append(f"{cred_hits} credential leak(s) found")
        if indicator_hits > 0:
            factors.append(f"{indicator_hits} active threat indicator(s) in {client.country_code}")

        # Re-grade after boost
        score = round(score, 1)
        if score <= 10:   grade = "A"
        elif score <= 25: grade = "B"
        elif score <= 45: grade = "C"
        elif score <= 65: grade = "D"
        else:             grade = "F"

        # Use discovery risk if enterprise hasn't run yet
        risk_score = score if total_findings > 0 else max(score, summary.get("average_risk_score", 0.0))

        # Persist cached stats to Postgres
        client.total_assets = summary.get("total_assets", 0)
        client.total_findings = total_findings
        client.critical_findings = critical
        client.high_findings = high
        client.risk_score = risk_score
        client.risk_grade = grade
        client.open_ports = summary.get("total_open_ports", 0)
        client.ssl_issues = summary.get("ssl_issues", 0)
        await db.commit()

        return {
            **summary,
            "total_findings": total_findings,
            "findings_by_severity": by_sev,
            "findings_by_category": findings_summary.get("by_category", {}),
            "kev_count": kev_count,
            "exploitable_count": exploitable_count,
            "avg_epss": findings_summary.get("avg_epss", 0.0),
            "risk_score": risk_score,
            "risk_grade": grade,
            "risk_factors": factors,
            # Cross-dataset intel
            "brand_exposures": brand_hits,
            "credential_leaks": cred_hits,
            "country_indicator_count": indicator_hits,
            "region_risk": region_risk,
            "client_id": client_id,
            "client_name": client.name,
            "country_code": client.country_code,
            "industry": client.industry,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/clients/{client_id}/assets")
async def list_client_assets(
    client_id: int,
    asset_type: Optional[str] = Query(None),
    search: Optional[str] = Query(None, description="Full-text search across asset values"),
    ti_tagged: Optional[bool] = Query(None, description="Filter to only TI-tagged assets"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List assets for a client with full-text search, type filter, and TI-tag filter."""
    result = await db.execute(
        select(ASMClient).where(
            ASMClient.id == client_id,
            ASMClient.id.in_(await _accessible_client_ids(current_user, db)),
        )
    )
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Client not found")

    ent = await _get_ent(client_id)
    try:
        assets, total = await ent.get_assets(
            asset_type=asset_type,
            search=search,
            ti_tagged=ti_tagged,
            limit=limit,
            offset=offset,
        )
        by_type: dict = {}
        for asset in assets:
            t = asset.get("type", "unknown") if isinstance(asset, dict) else getattr(asset, "type", "unknown")
            by_type[str(t)] = by_type.get(str(t), 0) + 1
        return {"total": total, "assets": assets, "by_type": by_type}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/clients/{client_id}/findings")
async def list_client_findings(
    client_id: int,
    severity: Optional[str] = Query(None),
    category: Optional[str] = Query(None, description="cve|ssl|http_header|port|ti_hit|email_security|dns_takeover|misconfiguration"),
    status: str = Query("open", description="open|accepted|remediated"),
    search: Optional[str] = Query(None, description="Full-text search across finding title, description, and asset value"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List enriched findings for a client (CVEs with EPSS/KEV, TI hits, SSL issues,
    HTTP header gaps, DNS takeover risks). Replaces /vulnerabilities.
    """
    result = await db.execute(
        select(ASMClient).where(
            ASMClient.id == client_id,
            ASMClient.id.in_(await _accessible_client_ids(current_user, db)),
        )
    )
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Client not found")

    ent = await _get_ent(client_id)
    try:
        findings, total = await ent.get_findings(
            severity=severity,
            category=category,
            status=status,
            search=search,
            limit=limit,
            offset=offset,
        )
        # Severity counts must reflect the whole index, not just this page
        summary = await ent.get_findings_summary()
        by_sev = summary.get("by_severity", {})
        return {
            "total": total,
            "critical": by_sev.get("critical", 0),
            "high": by_sev.get("high", 0),
            "medium": by_sev.get("medium", 0),
            "low": by_sev.get("low", 0),
            "findings": findings,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/clients/{client_id}/vulnerabilities")
async def list_client_vulnerabilities(
    client_id: int,
    severity: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Alias for /findings kept for backwards compatibility.
    Prefer /clients/{id}/findings which includes EPSS, KEV, and TI-hit categories.
    """
    return await list_client_findings(
        client_id=client_id,
        severity=severity,
        category=None,
        status="open",
        limit=limit,
        offset=offset,
        db=db,
        current_user=current_user,
    )


@router.get("/clients/{client_id}/changes")
async def list_client_changes(
    client_id: int,
    days: int = Query(7, ge=1, le=90),
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get recent asset changes for a client."""
    result = await db.execute(
        select(ASMClient).where(
            ASMClient.id == client_id,
            ASMClient.id.in_(await _accessible_client_ids(current_user, db)),
        )
    )
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Client not found")

    asm = await _get_asm(client_id)
    try:
        since = datetime.utcnow() - timedelta(days=days)
        changes = await asm.get_changes(since=since, limit=limit)
        return {"total": len(changes), "changes": changes}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/clients/{client_id}/darkweb")
async def client_darkweb(
    client_id: int,
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Dark-web exposure scoped to a single ASM client.

    Correlates the client's identity (name + primary domains) and any matching
    OrgWatchlist (brand terms, keywords, domains) against:
      - darkweb_posts : crawled .onion / paste / dark-web-search results — full content
      - iocs          : threat-intel indicators that reference the client's domains
    """
    import logging
    log = logging.getLogger(__name__)

    result = await db.execute(
        select(ASMClient).where(
            ASMClient.id == client_id,
            ASMClient.id.in_(await _accessible_client_ids(current_user, db)),
        )
    )
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    # ── Build the term/domain set from the client + its matching watchlist ────
    terms: set = set()
    domains: set = set()
    if client.name:
        terms.add(client.name)
    for d in (client.primary_domains or "").split(","):
        d = d.strip()
        if d:
            domains.add(d)
            terms.add(d)

    from app.models.intel import OrgWatchlist
    wl_res = await db.execute(
        select(OrgWatchlist).where(
            OrgWatchlist.user_id == client.owner_user_id,
            OrgWatchlist.name == client.name,
        )
    )
    wl = wl_res.scalar_one_or_none()
    if wl:
        for t in (wl.brand_terms or []):
            terms.add(t)
        for k in (wl.keywords or []):
            terms.add(k)
        for d in (wl.domains or []):
            domains.add(d)
            terms.add(d)

    terms = {t for t in terms if t and len(t) >= 3}
    base = {"client_id": client_id, "terms": sorted(terms),
            "watchlist_id": wl.id if wl else None,
            "posts": [], "ioc_hits": [], "total_posts": 0, "total_ioc_hits": 0}
    if not terms:
        return base

    await es_service.connect()
    if not es_service.client:
        base["error"] = "search backend unavailable"
        return base

    # ── darkweb_posts: full crawl content matching any term ───────────────────
    try:
        if await es_service.client.indices.exists(index="darkweb_posts"):
            should = [
                {"multi_match": {
                    "query": t,
                    "type": "phrase",
                    "fields": ["title^3", "body_text^2", "crawl_query^3", "url",
                               "tags", "emails_found", "domains_found", "onion_links"],
                }}
                for t in terms
            ]
            res = await es_service.client.search(
                index="darkweb_posts",
                body={
                    "query": {"bool": {"should": should, "minimum_should_match": 1}},
                    "sort": [{"discovered_at": {"order": "desc", "unmapped_type": "date"}}],
                    "size": limit,
                },
            )
            base["posts"] = [{**h["_source"], "_id": h["_id"], "_score": h["_score"]}
                             for h in res["hits"]["hits"]]
            base["total_posts"] = res["hits"]["total"]["value"]
    except Exception as e:
        log.warning(f"client_darkweb: darkweb_posts query failed for client={client_id}: {e}")

    # ── iocs: threat-intel indicators referencing the client's domains ────────
    try:
        if domains and await es_service.client.indices.exists(index="iocs"):
            should = [
                {"multi_match": {
                    "query": d,
                    "type": "phrase",
                    "fields": ["indicator^2", "target", "tags", "source_url"],
                }}
                for d in domains
            ]
            res = await es_service.client.search(
                index="iocs",
                body={
                    "query": {"bool": {"should": should, "minimum_should_match": 1}},
                    "size": min(limit, 50),
                },
            )
            base["ioc_hits"] = [{**h["_source"], "_id": h["_id"]} for h in res["hits"]["hits"]]
            base["total_ioc_hits"] = res["hits"]["total"]["value"]
    except Exception as e:
        log.warning(f"client_darkweb: iocs query failed for client={client_id}: {e}")

    return base


# =============================================================================
# TI correlation  (manual trigger + update findings status)
# =============================================================================

@router.post("/clients/{client_id}/correlate-ti")
async def trigger_ti_correlation(
    client_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Re-run threat-intel correlation against all assets for this client.
    Joins the asset inventory against the live IOC index and creates TI-hit findings.
    Runs synchronously (fast — ES terms query, no scanning).
    """
    result = await db.execute(
        select(ASMClient).where(
            ASMClient.id == client_id,
            ASMClient.id.in_(await _accessible_client_ids(current_user, db)),
        )
    )
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    ent = await _get_ent(client_id)
    try:
        ti_result = await ent.run_ti_correlation()
        # Update TI hit count on client
        client.ti_hit_count = ti_result.get("ti_hits", 0)
        await db.commit()
        return {**ti_result, "client_id": client_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/clients/{client_id}/findings/{finding_id}/status")
async def update_finding_status(
    client_id: int,
    finding_id: str,
    new_status: str = Query(..., description="open|accepted|remediated"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update a finding's status (accept risk, mark remediated, reopen)."""
    result = await db.execute(
        select(ASMClient).where(
            ASMClient.id == client_id,
            ASMClient.id.in_(await _accessible_client_ids(current_user, db)),
        )
    )
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Client not found")

    if new_status not in ("open", "accepted", "remediated"):
        raise HTTPException(status_code=400, detail="status must be open|accepted|remediated")

    ent = await _get_ent(client_id)
    try:
        await ent.es.update(
            index=ent.findings_index,
            id=finding_id,
            doc={"status": new_status},
            retry_on_conflict=3,
        )
        return {"finding_id": finding_id, "status": new_status}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Export
# =============================================================================

@router.get("/clients/{client_id}/export")
async def export_client_data(
    client_id: int,
    export_type: str = Query("assets", description="assets|findings"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Export asset inventory or findings as CSV for SIEM/audit ingestion.
    Returns CSV content with Content-Disposition: attachment header.
    """
    result = await db.execute(
        select(ASMClient).where(
            ASMClient.id == client_id,
            ASMClient.id.in_(await _accessible_client_ids(current_user, db)),
        )
    )
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    ent = await _get_ent(client_id)
    try:
        from fastapi.responses import Response
        csv_data = await ent.export_csv(export_type)
        filename = f"{client.slug}_{export_type}_{datetime.utcnow().strftime('%Y%m%d')}.csv"
        return Response(
            content=csv_data,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Scan job status tracking
# =============================================================================

@router.get("/jobs/{job_id}")
async def get_job_status(
    job_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Poll the status of an async discovery job (Celery task).
    Returns state: PENDING | STARTED | SUCCESS | FAILURE | REVOKED
    """
    _require_asm_tier(current_user)
    # Ownership: non-admins may only poll a job that belongs to a client they
    # can access. The dispatching client records its most recent job in
    # ASMClient.last_scan_job_id; admins bypass and can poll any job.
    if not current_user.is_admin:
        owner = await db.execute(
            select(ASMClient.id).where(
                ASMClient.last_scan_job_id == job_id,
                ASMClient.id.in_(await _accessible_client_ids(current_user, db)),
            )
        )
        if owner.scalar_one_or_none() is None:
            raise HTTPException(status_code=404, detail="Job not found")
    try:
        from celery.result import AsyncResult
        from app.worker import celery_app
        result = AsyncResult(job_id, app=celery_app)
        state = result.state
        info: dict = {}
        if state == "SUCCESS":
            info = result.result if isinstance(result.result, dict) else {}
        elif state == "FAILURE":
            info = {"error": str(result.result)}
        return {
            "job_id": job_id,
            "state": state,
            "info": info,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# On-demand security check utilities (all require auth + ASM tier)
# =============================================================================

@router.get("/check/ssl/{domain}")
async def check_ssl(
    domain: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Check SSL/TLS configuration and certificate health for a domain."""
    _require_asm_tier(current_user)
    host = await _precheck_target(domain, current_user, db)
    asm = await _get_asm()
    try:
        result = await asm.check_ssl_certificates(host)
        return result.model_dump() if result and hasattr(result, "model_dump") else result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/check/dns/{domain}")
async def get_dns_records(
    domain: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get all DNS records for a domain."""
    _require_asm_tier(current_user)
    host = await _precheck_target(domain, current_user, db, resolve=False)
    asm = await _get_asm()
    try:
        records = await asm.get_dns_records(host)
        return {
            "domain": domain,
            "records": [r.model_dump() if hasattr(r, "model_dump") else r for r in records],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/check/subdomains/{domain}")
async def discover_subdomains(
    domain: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Discover subdomains using crt.sh, Shodan, and SecurityTrails."""
    _require_asm_tier(current_user)
    host = await _precheck_target(domain, current_user, db, resolve=False)
    asm = await _get_asm()
    try:
        subdomains = await asm._discover_subdomains(host)
        return {"domain": host, "total": len(subdomains), "subdomains": list(subdomains)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/check/ports/{target}")
async def scan_ports(
    target: str,
    ports: str = Query("common", description="'common' or comma-separated ports e.g. '80,443,22'"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Scan ports on a target. Enterprise tier only for broad scans."""
    _require_asm_tier(current_user)
    host = await _precheck_target(target, current_user, db)
    asm = await _get_asm()
    try:
        port_list: List[int] = []
        if ports != "common":
            for part in ports.split(","):
                part = part.strip()
                if "-" in part:
                    start, end = part.split("-")
                    port_list.extend(range(int(start), int(end) + 1))
                else:
                    port_list.append(int(part))
            # Enterprise gets 500 ports, professional gets 100
            limit = 500 if current_user.tier == "enterprise" or current_user.is_admin else 100
            port_list = port_list[:limit]
        return await asm.scan_ports(host, port_list if port_list else None)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/check/services/{domain}")
async def find_exposed_services(
    domain: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Find exposed services for a domain."""
    _require_asm_tier(current_user)
    host = await _precheck_target(domain, current_user, db)
    asm = await _get_asm()
    try:
        services = await asm.find_exposed_services(host)
        return {
            "domain": domain,
            "total": len(services),
            "services": [s.model_dump() if hasattr(s, "model_dump") else s for s in services],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/check/security/{domain}")
async def check_security_posture(
    domain: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Comprehensive security posture check for a domain.
    Covers: DNS takeover risk, email security (SPF/DKIM/DMARC),
    HTTP security headers, TLS quality, open redirect risk.
    """
    _require_asm_tier(current_user)
    domain = await _precheck_target(domain, current_user, db)
    asm = await _get_asm()
    try:
        dns_records, ssl_info = await asyncio.gather(
            asm.get_dns_records(domain),
            asm.check_ssl_certificates(domain),
            return_exceptions=True,
        )

        findings: List[dict] = []
        score = 100  # start at 100, deduct per finding

        # ── Email security ────────────────────────────────────────────────────
        records_list = dns_records if isinstance(dns_records, list) else []
        txt_values = [r.value for r in records_list if getattr(r, "record_type", "") == "TXT"]
        mx_values = [r.value for r in records_list if getattr(r, "record_type", "") == "MX"]

        has_spf = any("v=spf1" in v for v in txt_values)
        has_dmarc_cname = any("_dmarc" in getattr(r, "value", "") for r in records_list)
        has_dmarc = has_dmarc_cname or any("v=DMARC1" in v for v in txt_values)
        has_dkim_hint = any("._domainkey." in getattr(r, "value", "") for r in records_list)

        if not has_spf:
            findings.append({"category": "email_security", "severity": "high",
                "title": "Missing SPF Record",
                "description": "No SPF TXT record found. Domain is vulnerable to email spoofing.",
                "remediation": "Add a TXT record: v=spf1 include:yourprovider.com ~all"})
            score -= 15
        if not has_dmarc:
            findings.append({"category": "email_security", "severity": "high",
                "title": "Missing DMARC Record",
                "description": "No DMARC policy found. Emails cannot be authenticated by receivers.",
                "remediation": "Add TXT record at _dmarc.yourdomain.com: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com"})
            score -= 15
        if not has_dkim_hint and mx_values:
            findings.append({"category": "email_security", "severity": "medium",
                "title": "No DKIM Selectors Detected",
                "description": "No DKIM selector records found. Email signing may not be configured.",
                "remediation": "Configure DKIM for your mail provider and publish the public key as a TXT record."})
            score -= 10

        # ── DNS takeover detection ────────────────────────────────────────────
        DANGLING_SERVICES = [
            "amazonaws.com", "heroku.com", "github.io", "github.com",
            "azurewebsites.net", "cloudfront.net", "fastly.net",
            "shopify.com", "wordpress.com", "ghost.io", "pantheon.io",
        ]
        cname_values = [r.value for r in records_list if getattr(r, "record_type", "") == "CNAME"]
        for cname in cname_values:
            for svc in DANGLING_SERVICES:
                if svc in cname:
                    # Try to resolve the CNAME target — blocking gethostbyname
                    # must run off the event loop or it stalls concurrent requests
                    try:
                        import socket
                        await asyncio.to_thread(socket.gethostbyname, cname.rstrip("."))
                    except socket.gaierror:
                        findings.append({"category": "dns_takeover", "severity": "critical",
                            "title": f"Potential DNS Takeover: {cname}",
                            "description": f"CNAME {cname} points to {svc} but the target does not resolve. This subdomain may be takeable.",
                            "remediation": f"Remove the CNAME record for this subdomain or re-provision the {svc} resource."})
                        score -= 30

        # ── SSL/TLS findings ──────────────────────────────────────────────────
        if isinstance(ssl_info, Exception) or ssl_info is None:
            findings.append({"category": "ssl", "severity": "high",
                "title": "SSL Certificate Unavailable",
                "description": "Could not retrieve SSL certificate. Port 443 may be closed or certificate is invalid.",
                "remediation": "Ensure HTTPS is enabled and a valid certificate is installed."})
            score -= 20
        else:
            if getattr(ssl_info, "is_expired", False):
                findings.append({"category": "ssl", "severity": "critical",
                    "title": "SSL Certificate Expired",
                    "description": f"Certificate expired on {getattr(ssl_info, 'valid_until', 'unknown')}",
                    "remediation": "Renew the SSL certificate immediately."})
                score -= 30
            elif getattr(ssl_info, "days_until_expiry", 999) < 30:
                findings.append({"category": "ssl", "severity": "medium",
                    "title": f"SSL Certificate Expiring Soon ({ssl_info.days_until_expiry} days)",
                    "description": "Certificate will expire in less than 30 days.",
                    "remediation": "Renew the SSL certificate before it expires."})
                score -= 10
            key_size = getattr(ssl_info, "key_size", None)
            if key_size and key_size < 2048:
                findings.append({"category": "ssl", "severity": "high",
                    "title": f"Weak SSL Key Size ({key_size} bits)",
                    "description": "Key size below 2048 bits is considered insecure.",
                    "remediation": "Reissue the certificate with at least a 2048-bit RSA or 256-bit ECDSA key."})
                score -= 15
            sig_algo = getattr(ssl_info, "signature_algorithm", "") or ""
            if "sha1" in sig_algo.lower():
                findings.append({"category": "ssl", "severity": "high",
                    "title": "Deprecated SHA-1 Signature Algorithm",
                    "description": "SHA-1 is cryptographically broken and rejected by modern browsers.",
                    "remediation": "Reissue the certificate using SHA-256 or better."})
                score -= 15

        # ── HTTP security headers (best-effort via httpx) ─────────────────────
        try:
            import httpx
            # follow_redirects disabled: prevents a redirect to an internal
            # address bypassing the pre-request SSRF validation (OWASP SSRF cheat sheet).
            async with httpx.AsyncClient(timeout=10, follow_redirects=False, verify=False) as client:
                r = await client.get(f"https://{domain}", headers={"User-Agent": "JichoSec-ASM/1.0"})
                h = {k.lower(): v for k, v in r.headers.items()}

            header_checks = [
                ("strict-transport-security", "high", "Missing HSTS Header",
                 "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"),
                ("x-frame-options", "medium", "Missing X-Frame-Options",
                 "Add: X-Frame-Options: SAMEORIGIN to prevent clickjacking."),
                ("x-content-type-options", "low", "Missing X-Content-Type-Options",
                 "Add: X-Content-Type-Options: nosniff"),
                ("content-security-policy", "medium", "Missing Content-Security-Policy",
                 "Define a Content-Security-Policy header to restrict resource loading."),
                ("referrer-policy", "low", "Missing Referrer-Policy",
                 "Add: Referrer-Policy: strict-origin-when-cross-origin"),
                ("permissions-policy", "low", "Missing Permissions-Policy",
                 "Add a Permissions-Policy header to restrict browser feature access."),
            ]
            sev_deduct = {"critical": 25, "high": 15, "medium": 8, "low": 3}
            for header, sev, title, rem in header_checks:
                if header not in h:
                    findings.append({"category": "http_headers", "severity": sev,
                        "title": title, "description": f"The {header} header is not set.",
                        "remediation": rem})
                    score -= sev_deduct.get(sev, 5)
        except Exception:
            pass  # HTTP headers check is best-effort

        score = max(0, min(100, score))
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            by_severity[f.get("severity", "info")] = by_severity.get(f.get("severity", "info"), 0) + 1

        return {
            "domain": domain,
            "security_score": score,
            "grade": "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 45 else "F",
            "total_findings": len(findings),
            "by_severity": by_severity,
            "findings": findings,
            "checks_performed": ["spf", "dmarc", "dkim", "dns_takeover", "ssl_tls", "http_headers"],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Backwards-compat legacy endpoints — now require auth + tier
# =============================================================================

@router.get("/assets")
async def list_assets(
    asset_type: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
):
    """List assets scoped to this user's clients (aggregated)."""
    _require_asm_tier(current_user)
    # Return empty — callers should use /clients/{id}/assets instead
    return {"total": 0, "assets": [], "by_type": {}}


@router.get("/vulnerabilities")
async def list_vulnerabilities(
    severity: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    current_user: User = Depends(get_current_user),
):
    """List vulnerabilities — use /clients/{id}/vulnerabilities instead."""
    _require_asm_tier(current_user)
    return {"total": 0, "vulnerabilities": []}


@router.get("/changes")
async def list_changes(
    days: int = Query(7, ge=1, le=90),
    limit: int = Query(100, ge=1, le=1000),
    current_user: User = Depends(get_current_user),
):
    """Get asset changes — use /clients/{id}/changes instead."""
    _require_asm_tier(current_user)
    return {"total": 0, "changes": []}


@router.get("/summary")
async def get_summary(
    current_user: User = Depends(get_current_user),
):
    """Summary stats — use /clients/{id}/summary instead."""
    _require_asm_tier(current_user)
    return {"total_assets": 0, "by_type": {}, "risk_score": 0.0}


@router.get("/stats")
async def get_asm_stats(
    current_user: User = Depends(get_current_user),
):
    """Overall stats — use /clients/{id}/summary instead."""
    _require_asm_tier(current_user)
    return {"total_assets": 0, "assets_by_type": {}, "total_vulnerabilities": 0,
            "vulnerabilities_by_severity": {}, "recent_changes": 0}


@router.post("/scan")
async def run_scan(
    request: ScanRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Run a targeted security scan against a client-owned asset."""
    _require_asm_tier(current_user)
    # Verify client ownership if client_id provided (fixes prior undefined-name bug).
    if request.client_id:
        await _require_client_access(request.client_id, current_user, db)
    # Rate-cap + ownership-by-domain + SSRF resolve guard on the target itself.
    target = await _precheck_target(request.target, current_user, db)
    request.target = target

    asm = await _get_asm(request.client_id)
    try:
        results: dict = {}
        if request.scan_type in ("full", "ports"):
            results["ports"] = await asm.scan_ports(request.target)
        if request.scan_type in ("full", "ssl"):
            try:
                ssl_obj = await asm.check_ssl_certificates(request.target)
                results["ssl"] = ssl_obj.model_dump() if ssl_obj and hasattr(ssl_obj, "model_dump") else ssl_obj
            except Exception:
                results["ssl"] = None
        if request.scan_type in ("full", "vulnerabilities"):
            asset_dict = {"type": "domain", "value": request.target, "id": request.target}
            try:
                results["vulnerabilities"] = await asm.check_vulnerabilities(asset_dict)
            except Exception:
                results["vulnerabilities"] = []
        return {"status": "completed", "target": request.target, "scan_type": request.scan_type, "results": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Keep old paths as aliases (no-ops that redirect to new paths in docs)
@router.get("/ssl/{domain}")
async def check_ssl_legacy(
    domain: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Deprecated — use GET /check/ssl/{domain}"""
    _require_asm_tier(current_user)
    host = await _precheck_target(domain, current_user, db)
    asm = await _get_asm()
    try:
        result = await asm.check_ssl_certificates(host)
        return result.model_dump() if result and hasattr(result, "model_dump") else result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/dns/{domain}")
async def get_dns_records_legacy(
    domain: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Deprecated — use GET /check/dns/{domain}"""
    _require_asm_tier(current_user)
    host = await _precheck_target(domain, current_user, db, resolve=False)
    asm = await _get_asm()
    try:
        records = await asm.get_dns_records(host)
        return {"domain": domain, "records": [r.model_dump() if hasattr(r, "model_dump") else r for r in records]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Access Management  (admin only)
# =============================================================================

class AccessGrant(BaseModel):
    user_id: int
    access_level: str = "read"  # read | admin | owner


@router.get("/access/users")
async def list_users_for_access(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Admin: list all users eligible to receive client access."""
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin only")
    rows = await db.execute(
        text("SELECT id, email, name, is_admin, tier FROM users WHERE is_active=TRUE ORDER BY email")
    )
    return {"users": [{"id": r[0], "email": r[1], "name": r[2], "is_admin": r[3], "tier": r[4]} for r in rows.fetchall()]}


@router.get("/clients/{client_id}/access")
async def list_client_access(
    client_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Admin: list all users who have access to a client."""
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin only")
    rows = await db.execute(
        text("""
            SELECT a.user_id, u.email, u.name, a.access_level, a.granted_at,
                   gb.email AS granted_by_email
            FROM asm_client_access a
            JOIN users u ON u.id = a.user_id
            LEFT JOIN users gb ON gb.id = a.granted_by
            WHERE a.client_id = :cid
            ORDER BY a.granted_at DESC
        """),
        {"cid": client_id},
    )
    return {"client_id": client_id, "access": [
        {"user_id": r[0], "email": r[1], "name": r[2], "access_level": r[3],
         "granted_at": r[4].isoformat() if r[4] else None, "granted_by_email": r[5]}
        for r in rows.fetchall()
    ]}


@router.post("/clients/{client_id}/access")
async def grant_client_access(
    client_id: int,
    body: AccessGrant,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Admin: grant a user access to a client."""
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin only")
    if body.access_level not in ("read", "admin", "owner"):
        raise HTTPException(status_code=400, detail="access_level must be read|admin|owner")
    await db.execute(
        text("""
            INSERT INTO asm_client_access (client_id, user_id, granted_by, access_level)
            VALUES (:cid, :uid, :gby, :lvl)
            ON CONFLICT (client_id, user_id) DO UPDATE SET access_level=:lvl, granted_by=:gby, granted_at=NOW()
        """),
        {"cid": client_id, "uid": body.user_id, "gby": current_user.id, "lvl": body.access_level},
    )
    await db.commit()
    return {"granted": True, "client_id": client_id, "user_id": body.user_id, "access_level": body.access_level}


@router.delete("/clients/{client_id}/access/{user_id}")
async def revoke_client_access(
    client_id: int,
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Admin: revoke a user's access to a client."""
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin only")
    # Cannot revoke owner's own access
    client_row = await db.execute(select(ASMClient).where(ASMClient.id == client_id))
    client = client_row.scalar_one_or_none()
    if client and client.owner_user_id == user_id:
        raise HTTPException(status_code=400, detail="Cannot revoke access from the client owner")
    await db.execute(
        text("DELETE FROM asm_client_access WHERE client_id=:cid AND user_id=:uid"),
        {"cid": client_id, "uid": user_id},
    )
    await db.commit()
    return {"revoked": True, "client_id": client_id, "user_id": user_id}


@router.post("/access/bulk-grant")
async def bulk_grant_access(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    user_id: int = Query(...),
    access_level: str = Query("read"),
):
    """Admin: grant a user access to ALL clients at once."""
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin only")
    clients_res = await db.execute(select(ASMClient.id))
    client_ids = [r[0] for r in clients_res.fetchall()]
    for cid in client_ids:
        await db.execute(
            text("""
                INSERT INTO asm_client_access (client_id, user_id, granted_by, access_level)
                VALUES (:cid, :uid, :gby, :lvl)
                ON CONFLICT (client_id, user_id) DO UPDATE SET access_level=:lvl, granted_by=:gby, granted_at=NOW()
            """),
            {"cid": cid, "uid": user_id, "gby": current_user.id, "lvl": access_level},
        )
    await db.commit()
    return {"granted": len(client_ids), "user_id": user_id, "access_level": access_level}


@router.post("/access/bulk-revoke")
async def bulk_revoke_access(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    user_id: int = Query(...),
):
    """Admin: revoke a user's access to all non-owned clients."""
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin only")
    await db.execute(
        text("""
            DELETE FROM asm_client_access
            WHERE user_id=:uid
              AND client_id NOT IN (SELECT id FROM asm_clients WHERE owner_user_id=:uid)
        """),
        {"uid": user_id},
    )
    await db.commit()
    return {"revoked": True, "user_id": user_id}


@router.get("/subdomains/{domain}")
async def discover_subdomains_legacy(
    domain: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Deprecated — use GET /check/subdomains/{domain}"""
    _require_asm_tier(current_user)
    host = await _precheck_target(domain, current_user, db, resolve=False)
    asm = await _get_asm()
    try:
        subdomains = await asm._discover_subdomains(host)
        return {"domain": host, "total": len(subdomains), "subdomains": list(subdomains)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/services/{domain}")
async def find_exposed_services_legacy(
    domain: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Deprecated — use GET /check/services/{domain}"""
    _require_asm_tier(current_user)
    host = await _precheck_target(domain, current_user, db)
    asm = await _get_asm()
    try:
        services = await asm.find_exposed_services(host)
        return {"domain": host, "total": len(services),
                "services": [s.model_dump() if hasattr(s, "model_dump") else s for s in services]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
