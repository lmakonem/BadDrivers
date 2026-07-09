"""
Dark Web Monitoring API Endpoints

Provides endpoints for:
- Leaked credentials search
- Dark web mentions monitoring
- Data breach tracking
- Monitoring configuration
"""

from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, EmailStr
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.config import settings
from app.core.database import get_db
from app.core.ownership import bare_domain, get_owned_domains, redact_credential
from app.models.user import User
from app.services.darkweb import (
    DarkWebMonitor,
    LeakedCredential,
    DarkWebMention,
    DataBreach,
    MonitoredTarget,
    DarkWebAlert,
    LeakSeverity,
    MentionSeverity,
    MonitorType,
)

router = APIRouter()
darkweb_service = DarkWebMonitor()


# =============================================================================
# Request/Response Models
# =============================================================================

class LeakSearchRequest(BaseModel):
    """Request model for leak search."""
    domain: Optional[str] = None
    email: Optional[str] = None
    include_passwords: bool = False


class MentionSearchRequest(BaseModel):
    """Request model for mention search."""
    keywords: List[str]
    sources: Optional[List[str]] = None
    days: int = 30


class AddMonitorRequest(BaseModel):
    """Request model for adding a monitoring target."""
    target_type: MonitorType
    target_value: str
    organization: Optional[str] = None
    alert_email: Optional[str] = None
    alert_webhook: Optional[str] = None


class LeakSearchResponse(BaseModel):
    """Response model for leak search."""
    total: int
    results: List[dict]
    search_domain: Optional[str]
    search_email: Optional[str]
    is_demo: Optional[bool] = None


class MentionSearchResponse(BaseModel):
    """Response model for mention search."""
    total: int
    results: List[dict]
    keywords: List[str]
    is_demo: Optional[bool] = None


class BreachListResponse(BaseModel):
    """Response model for breach list."""
    total: int
    breaches: List[dict]
    is_demo: Optional[bool] = None


class AlertListResponse(BaseModel):
    """Response model for alert list."""
    total: int
    unread: int
    alerts: List[dict]
    is_demo: Optional[bool] = None


class MonitorListResponse(BaseModel):
    """Response model for monitor list."""
    total: int
    monitors: List[dict]


# =============================================================================
# Endpoints
# =============================================================================

@router.get("/leaks")
async def search_leaks(
    domain: Optional[str] = Query(None, description="Domain to search for leaks"),
    email: Optional[str] = Query(None, description="Email to search for leaks"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Search for leaked credentials.

    Search by domain to find all leaked emails from that domain,
    or search by specific email address. Returns raw breach records, so
    non-admins are restricted to domains they own and every record is
    redacted of password/password_hash before it leaves the server.
    """
    if not domain and not email:
        raise HTTPException(
            status_code=400,
            detail="Either domain or email must be provided"
        )

    empty = {
        "total": 0,
        "results": [],
        "search_domain": domain,
        "search_email": email,
        "sources_checked": [],
        "is_demo": False,
    }

    # Owned-domain scoping — non-admins only see leaks for domains they monitor.
    if not current_user.is_admin:
        owned = await get_owned_domains(current_user, db)
        if not owned:
            return empty
        requested = bare_domain(email) if email else bare_domain(domain)
        if requested not in owned:
            return empty

    try:
        results = await darkweb_service.search_leaks(
            domain=domain or "",
            email=email,
            # Only inject synthetic demo leaks in explicit mock mode; in
            # production (ALLOW_MOCK_DATA=false) return real, possibly-empty
            # results instead of fabricated credentials.
            include_demo=settings.ALLOW_MOCK_DATA,
        )

        leaks = [redact_credential(dict(leak)) for leak in results.get("leaks", [])]

        return {
            "total": results.get("total", 0),
            "results": leaks,
            "search_domain": domain,
            "search_email": email,
            "sources_checked": results.get("sources_checked", []),
            "is_demo": results.get("is_demo", False),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/mentions")
async def search_mentions(
    keywords: str = Query(..., description="Comma-separated keywords to search"),
    source_type: Optional[str] = Query(None, description="Filter by source type"),
    days: int = Query(30, ge=1, le=365, description="Days to look back"),
    limit: int = Query(100, ge=1, le=1000),
):
    """
    Search for dark web mentions of keywords.
    
    Monitors paste sites, forums, and marketplaces for brand mentions.
    """
    keyword_list = [k.strip() for k in keywords.split(",") if k.strip()]
    
    if not keyword_list:
        raise HTTPException(
            status_code=400,
            detail="At least one keyword must be provided"
        )
    
    try:
        source_types = [source_type] if source_type else None
        
        results = await darkweb_service.search_mentions(
            keywords=keyword_list,
            source_types=source_types,
            limit=limit,
        )
        
        return {
            "total": results.get("total", 0),
            "results": results.get("mentions", []),
            "keywords": keyword_list,
            "by_source_type": results.get("by_source_type", {}),
            "by_severity": results.get("by_severity", {}),
            "is_demo": results.get("is_demo", False),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/breaches")
async def list_breaches(
    search: Optional[str] = Query(None, description="Search breach names"),
    min_records: Optional[int] = Query(None, description="Minimum records count"),
    hours: int = Query(720, ge=1, le=8760, description="Hours to look back (default 30 days)"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """
    List known data breaches.
    
    Returns information about data breaches including affected records
    and types of data exposed.
    """
    try:
        results = await darkweb_service.get_recent_leaks(
            hours=hours,
            limit=limit,
        )
        
        return {
            "total": results.get("total_breaches", 0),
            "breaches": results.get("breaches", []),
            "total_affected_records": results.get("total_affected_records", 0),
            "is_demo": results.get("is_demo", False),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/breaches/{breach_name}")
async def get_breach_details(breach_name: str):
    """
    Get detailed information about a specific breach.
    """
    try:
        breach = await darkweb_service.get_breach_details(breach_name)
        
        if not breach:
            raise HTTPException(status_code=404, detail="Breach not found")
        
        return breach
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/monitor")
async def add_monitor(
    request: AddMonitorRequest,
    current_user: User = Depends(get_current_user),
):
    """
    Add a new monitoring target.

    Monitor domains, emails, or keywords for dark web exposure.
    """
    try:
        monitor = await darkweb_service.add_monitor(
            target=request.target_value,
            target_type=request.target_type,
            organization=request.organization,
            alert_email=request.alert_email,
            webhook_url=request.alert_webhook,
            owner_user_id=current_user.id,
        )

        return monitor.model_dump() if hasattr(monitor, 'model_dump') else monitor.__dict__
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/monitors")
async def list_monitors(
    active_only: bool = Query(True, description="Only show active monitors"),
    limit: int = Query(100, ge=1, le=500),
    current_user: User = Depends(get_current_user),
):
    """
    List monitoring targets owned by the caller (admins see all).
    """
    try:
        owner_user_id = None if current_user.is_admin else current_user.id
        monitors = await darkweb_service.get_monitors(
            active_only=active_only,
            limit=limit,
            owner_user_id=owner_user_id,
        )

        return {
            "total": len(monitors),
            "monitors": monitors,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/monitor/{monitor_id}")
async def delete_monitor(
    monitor_id: str,
    current_user: User = Depends(get_current_user),
):
    """
    Delete a monitoring target (owner or admin only).
    """
    try:
        monitor = await darkweb_service.get_monitor(monitor_id)
        if not monitor:
            raise HTTPException(status_code=404, detail="Monitor not found")
        if not current_user.is_admin and monitor.get("owner_user_id") != current_user.id:
            raise HTTPException(status_code=404, detail="Monitor not found")

        success = await darkweb_service.delete_monitor(monitor_id)

        if not success:
            raise HTTPException(status_code=404, detail="Monitor not found")

        return {"status": "deleted", "id": monitor_id}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/alerts")
async def get_alerts(
    severity: Optional[str] = Query(None, description="Filter by severity"),
    unread_only: bool = Query(False, description="Only show unread alerts"),
    limit: int = Query(50, ge=1, le=500),
    current_user: User = Depends(get_current_user),
):
    """
    Get dark web monitoring alerts scoped to the caller (admins see all).
    """
    try:
        owner_user_id = None if current_user.is_admin else current_user.id
        results = await darkweb_service.get_alerts(
            unread_only=unread_only,
            severity_filter=severity,
            limit=limit,
            owner_user_id=owner_user_id,
        )
        
        return {
            "total": results.get("total", 0),
            "unread": results.get("unread_count", 0),
            "alerts": results.get("alerts", []),
            "by_severity": results.get("by_severity", {}),
            "is_demo": results.get("is_demo", False),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/alerts/{alert_id}/read")
async def mark_alert_read(
    alert_id: str,
    current_user: User = Depends(get_current_user),
):
    """
    Mark an alert as read (owner or admin only).
    """
    try:
        alert = await darkweb_service.get_alert(alert_id)
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        if not current_user.is_admin and alert.get("owner_user_id") != current_user.id:
            raise HTTPException(status_code=404, detail="Alert not found")

        success = await darkweb_service.mark_alert_read(alert_id)

        if not success:
            raise HTTPException(status_code=404, detail="Alert not found")

        return {"status": "read", "id": alert_id}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/exposure/{email}")
async def check_exposure(
    email: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Check if an email has been exposed in any breaches.

    Returns a summary of exposure across known breaches. Non-admins may only
    check emails whose domain they own.
    """
    # Owned-domain scoping — non-admins may only probe their own domains.
    if not current_user.is_admin:
        owned = await get_owned_domains(current_user, db)
        if not owned or bare_domain(email) not in owned:
            raise HTTPException(
                status_code=403,
                detail="Not authorized to check exposure for this email's domain",
            )

    try:
        exposure = await darkweb_service.check_credential_exposure(email)

        return exposure
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats")
async def get_darkweb_stats():
    """
    Get dark web monitoring statistics.
    """
    try:
        stats = await darkweb_service.get_statistics()
        
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/paste-sites")
async def list_paste_sites():
    """
    Get list of monitored paste sites.
    """
    return {
        "sites": darkweb_service.get_paste_sites(),
        "total": len(darkweb_service.get_paste_sites()),
    }


@router.post("/scan-pastes")
async def scan_paste_sites(keywords: List[str]):
    """
    Scan paste sites for specific keywords.
    """
    try:
        results = await darkweb_service.scan_paste_sites(keywords)
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
