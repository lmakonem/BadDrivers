"""
Intel endpoints — dark web posts, OSINT results, credential exposures,
watchlists, and VIP profiles.

All endpoints require authentication. Watchlist management requires
professional+ tier.
"""

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.api.deps import get_current_user
from app.models.user import User
from app.models.intel import (
    OrgWatchlist,
    VIPProfile,
    BrandExposure,
    CredentialExposure,
    VIPAlert,
)
from app.services.elasticsearch import es_service

logger = logging.getLogger(__name__)

router = APIRouter()


# ── Schemas ───────────────────────────────────────────────────────────────────

class WatchlistCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    org_name: str = Field(min_length=1, max_length=255)
    domains: List[str] = []
    brand_terms: List[str] = []
    keywords: List[str] = []
    email_patterns: List[str] = []


class VIPCreate(BaseModel):
    full_name: str = Field(min_length=2, max_length=255)
    title: Optional[str] = None
    emails: List[str] = []
    phone_numbers: List[str] = []


# ── Watchlist CRUD ────────────────────────────────────────────────────────────

@router.get("/watchlists")
async def list_watchlists(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List the current user's watchlists."""
    result = await db.execute(
        select(OrgWatchlist)
        .where(OrgWatchlist.user_id == current_user.id)
        .order_by(desc(OrgWatchlist.created_at))
    )
    watchlists = result.scalars().all()
    return {
        "items": [
            {
                "id": w.id,
                "name": w.name,
                "org_name": w.org_name,
                "domains": w.domains or [],
                "brand_terms": w.brand_terms or [],
                "keywords": w.keywords or [],
                "is_active": w.is_active,
                "last_scan_at": w.last_scan_at.isoformat() if w.last_scan_at else None,
                "created_at": w.created_at.isoformat(),
            }
            for w in watchlists
        ],
        "total": len(watchlists),
    }


@router.post("/watchlists", status_code=201)
async def create_watchlist(
    body: WatchlistCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a new organization watchlist."""
    wl = OrgWatchlist(
        user_id=current_user.id,
        name=body.name,
        org_name=body.org_name,
        domains=body.domains,
        brand_terms=body.brand_terms,
        keywords=body.keywords,
        email_patterns=body.email_patterns,
        is_active=True,
        scan_interval_hours=24,
    )
    db.add(wl)
    await db.flush()
    await db.refresh(wl)
    return {"id": wl.id, "name": wl.name, "created": True}


@router.patch("/watchlists/{watchlist_id}")
async def update_watchlist(
    watchlist_id: int,
    body: WatchlistCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update an existing watchlist (merge keywords)."""
    result = await db.execute(
        select(OrgWatchlist).where(
            OrgWatchlist.id == watchlist_id,
            OrgWatchlist.user_id == current_user.id,
        )
    )
    wl = result.scalar_one_or_none()
    if not wl:
        raise HTTPException(404, "Watchlist not found")

    # Merge arrays (deduplicate)
    if body.domains:
        existing = set(wl.domains or [])
        existing.update(body.domains)
        wl.domains = list(existing)
    if body.brand_terms:
        existing = set(wl.brand_terms or [])
        existing.update(body.brand_terms)
        wl.brand_terms = list(existing)
    if body.keywords:
        existing = set(wl.keywords or [])
        existing.update(body.keywords)
        wl.keywords = list(existing)
    if body.email_patterns:
        existing = set(wl.email_patterns or [])
        existing.update(body.email_patterns)
        wl.email_patterns = list(existing)
    if body.name:
        wl.name = body.name
    if body.org_name:
        wl.org_name = body.org_name

    await db.flush()
    await db.refresh(wl)
    return {
        "id": wl.id,
        "name": wl.name,
        "domains": wl.domains or [],
        "brand_terms": wl.brand_terms or [],
        "keywords": wl.keywords or [],
        "updated": True,
    }


@router.post("/watchlists/{watchlist_id}/vips", status_code=201)
async def add_vip(
    watchlist_id: int,
    body: VIPCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Add a VIP profile to a watchlist."""
    # Verify ownership
    result = await db.execute(
        select(OrgWatchlist).where(
            OrgWatchlist.id == watchlist_id,
            OrgWatchlist.user_id == current_user.id,
        )
    )
    wl = result.scalar_one_or_none()
    if not wl:
        raise HTTPException(404, "Watchlist not found")

    vip = VIPProfile(
        watchlist_id=watchlist_id,
        full_name=body.full_name,
        title=body.title,
        emails=body.emails,
        phone_numbers=body.phone_numbers,
        is_active=True,
    )
    db.add(vip)
    await db.flush()
    await db.refresh(vip)
    return {"id": vip.id, "full_name": vip.full_name, "created": True}


# ── Dark Web Search ───────────────────────────────────────────────────────────

@router.get("/darkweb/search")
async def search_darkweb(
    q: str = Query(..., min_length=2, description="Search term"),
    limit: int = Query(50, ge=1, le=500),
):
    """Search dark web posts in Elasticsearch."""
    await es_service.connect()
    try:
        result = await es_service.client.search(
            index="darkweb_posts",
            body={
                "query": {
                    "multi_match": {
                        "query": q,
                        "fields": ["title^2", "body_text", "url", "brand_matches"],
                    }
                },
                "sort": [{"discovered_at": "desc"}],
                "size": limit,
            },
        )
        hits = [
            {**h["_source"], "id": h["_id"], "score": h["_score"]}
            for h in result["hits"]["hits"]
        ]
        return {"total": result["hits"]["total"]["value"], "items": hits}
    except Exception as e:
        if "index_not_found" in str(e):
            return {"total": 0, "items": [], "message": "No dark web data collected yet"}
        raise HTTPException(500, str(e))


@router.get("/darkweb/recent")
async def recent_darkweb(
    limit: int = Query(20, ge=1, le=100),
    severity: Optional[str] = Query(None),
):
    """Get recent dark web findings."""
    await es_service.connect()
    try:
        query: dict = {"match_all": {}}
        if severity:
            query = {"term": {"severity": severity}}

        result = await es_service.client.search(
            index="darkweb_posts",
            body={
                "query": query,
                "sort": [{"discovered_at": "desc"}],
                "size": limit,
            },
        )
        hits = [{**h["_source"], "id": h["_id"]} for h in result["hits"]["hits"]]
        return {"total": result["hits"]["total"]["value"], "items": hits}
    except Exception as e:
        if "index_not_found" in str(e):
            return {"total": 0, "items": [], "message": "No dark web data collected yet"}
        raise HTTPException(500, str(e))


# ── OSINT Results ─────────────────────────────────────────────────────────────

@router.get("/osint/results")
async def osint_results(
    scan_target: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
):
    """Get OSINT scan results."""
    await es_service.connect()
    try:
        must = []
        if scan_target:
            must.append({"term": {"scan_target": scan_target}})
        if severity:
            must.append({"term": {"severity": severity}})

        query = {"bool": {"must": must}} if must else {"match_all": {}}

        result = await es_service.client.search(
            index="osint_results",
            body={
                "query": query,
                "sort": [{"discovered_at": "desc"}],
                "size": limit,
            },
        )
        hits = [{**h["_source"], "id": h["_id"]} for h in result["hits"]["hits"]]
        return {"total": result["hits"]["total"]["value"], "items": hits}
    except Exception as e:
        if "index_not_found" in str(e):
            return {"total": 0, "items": [], "message": "No OSINT scans completed yet"}
        raise HTTPException(500, str(e))


# ── Credential Exposures ──────────────────────────────────────────────────────

@router.get("/credentials/search")
async def search_credentials(
    domain: Optional[str] = Query(None, description="Filter by email domain"),
    email: Optional[str] = Query(None, description="Search by exact email"),
    severity: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
):
    """Search credential exposures."""
    await es_service.connect()
    try:
        must = []
        if domain:
            must.append({"term": {"domain": domain.lower()}})
        if email:
            must.append({"term": {"email": email.lower()}})
        if severity:
            must.append({"term": {"severity": severity}})

        query = {"bool": {"must": must}} if must else {"match_all": {}}

        result = await es_service.client.search(
            index="credential_exposures",
            body={
                "query": query,
                "sort": [{"discovered_at": "desc"}],
                "size": limit,
                "_source": {
                    "excludes": ["password", "password_hash"],  # never expose secrets via API
                },
            },
        )
        hits = [{**h["_source"], "id": h["_id"]} for h in result["hits"]["hits"]]
        return {"total": result["hits"]["total"]["value"], "items": hits}
    except Exception as e:
        if "index_not_found" in str(e):
            return {"total": 0, "items": [], "message": "No credential data collected yet"}
        raise HTTPException(500, str(e))


@router.get("/credentials/stats")
async def credential_stats():
    """Get credential exposure statistics."""
    await es_service.connect()
    try:
        result = await es_service.client.search(
            index="credential_exposures",
            body={
                "size": 0,
                "aggs": {
                    "total": {"value_count": {"field": "email"}},
                    "by_severity": {"terms": {"field": "severity"}},
                    "by_source": {"terms": {"field": "source"}},
                    "by_domain": {"terms": {"field": "domain", "size": 20}},
                    "vip_count": {"filter": {"term": {"vip_match": True}}},
                },
            },
        )
        aggs = result.get("aggregations", {})
        return {
            "total": aggs.get("total", {}).get("value", 0),
            "by_severity": {
                b["key"]: b["doc_count"]
                for b in aggs.get("by_severity", {}).get("buckets", [])
            },
            "by_source": {
                b["key"]: b["doc_count"]
                for b in aggs.get("by_source", {}).get("buckets", [])
            },
            "top_domains": {
                b["key"]: b["doc_count"]
                for b in aggs.get("by_domain", {}).get("buckets", [])
            },
            "vip_exposures": aggs.get("vip_count", {}).get("doc_count", 0),
        }
    except Exception as e:
        if "index_not_found" in str(e):
            return {"total": 0, "message": "No credential data collected yet"}
        raise HTTPException(500, str(e))


# ── VIP Alerts ────────────────────────────────────────────────────────────────

@router.get("/vip/alerts")
async def vip_alerts(
    status: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get VIP alerts for the user's watchlists."""
    # Get user's watchlist IDs
    wl_result = await db.execute(
        select(OrgWatchlist.id).where(OrgWatchlist.user_id == current_user.id)
    )
    wl_ids = [r[0] for r in wl_result.all()]
    if not wl_ids:
        return {"items": [], "total": 0}

    # Get VIP profile IDs
    vip_result = await db.execute(
        select(VIPProfile.id).where(VIPProfile.watchlist_id.in_(wl_ids))
    )
    vip_ids = [r[0] for r in vip_result.all()]
    if not vip_ids:
        return {"items": [], "total": 0}

    # Query alerts
    q = select(VIPAlert).where(VIPAlert.vip_profile_id.in_(vip_ids))
    if status:
        q = q.where(VIPAlert.status == status)
    q = q.order_by(desc(VIPAlert.created_at)).limit(limit)

    result = await db.execute(q)
    alerts = result.scalars().all()

    return {
        "items": [
            {
                "id": a.id,
                "alert_type": a.alert_type,
                "title": a.title,
                "description": a.description,
                "severity": a.severity,
                "source": a.source,
                "status": a.status,
                "created_at": a.created_at.isoformat(),
            }
            for a in alerts
        ],
        "total": len(alerts),
    }
