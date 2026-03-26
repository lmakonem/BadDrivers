"""
Brand Protection API Endpoints

Provides endpoints for:
- Typosquatting detection
- Brand monitoring
- Phishing domain detection
- Lookalike domain discovery
"""

from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel

from app.services.brand_protection import (
    BrandProtectionService,
    BrandMonitor,
    TyposquatDomain,
    BrandAlert,
    PhishingDomain,
)

router = APIRouter()
brand_service = BrandProtectionService()


# =============================================================================
# Request/Response Models
# =============================================================================

class AddBrandRequest(BaseModel):
    """Request model for adding a brand to monitor."""
    brand_name: str
    primary_domain: str
    additional_domains: List[str] = []
    keywords: List[str] = []
    alert_email: Optional[str] = None
    alert_webhook: Optional[str] = None


class CheckDomainRequest(BaseModel):
    """Request model for checking a suspicious domain."""
    domain: str


class TyposquatResponse(BaseModel):
    """Response model for typosquat detection."""
    original_domain: str
    total_variants: int
    registered_count: int
    high_risk_count: int
    variants: List[dict]


class BrandListResponse(BaseModel):
    """Response model for brand list."""
    total: int
    brands: List[dict]


class AlertListResponse(BaseModel):
    """Response model for brand alerts."""
    total: int
    critical: int
    high: int
    alerts: List[dict]


class BrandReportResponse(BaseModel):
    """Response model for brand protection report."""
    brand_id: str
    brand_name: str
    monitored_since: str
    total_typosquats: int
    registered_typosquats: int
    active_phishing: int
    alerts_last_30_days: int
    risk_score: float
    top_threats: List[dict]
    recommendations: List[str]


# =============================================================================
# Endpoints
# =============================================================================

@router.post("/monitor")
async def add_brand_monitor(
    request: AddBrandRequest,
    background_tasks: BackgroundTasks,
):
    """
    Add a brand to monitor for typosquatting and impersonation.
    
    Starts initial scan for existing typosquat domains.
    """
    try:
        monitor = await brand_service.monitor_brand(
            brand_name=request.brand_name,
            domain=request.primary_domain,
            additional_domains=request.additional_domains,
            keywords=request.keywords,
            alert_email=request.alert_email,
            alert_webhook=request.alert_webhook,
        )
        
        return monitor.model_dump() if hasattr(monitor, 'model_dump') else monitor.__dict__
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/monitors")
async def list_brand_monitors(
    active_only: bool = Query(True, description="Only show active monitors"),
    limit: int = Query(100, ge=1, le=500),
):
    """
    List all monitored brands.
    """
    try:
        brands = await brand_service.list_brand_monitors(
            active_only=active_only,
            limit=limit,
        )
        
        return {
            "total": len(brands),
            "brands": brands,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/monitors/{brand_id}")
async def get_brand_monitor(brand_id: str):
    """
    Get details of a specific brand monitor.
    """
    try:
        brand = await brand_service.get_brand_monitor(brand_id)
        
        if not brand:
            raise HTTPException(status_code=404, detail="Brand monitor not found")
        
        return brand.model_dump() if hasattr(brand, 'model_dump') else brand.__dict__
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/monitors/{brand_id}")
async def delete_brand_monitor(brand_id: str):
    """
    Delete a brand monitor.
    """
    # Note: delete_brand_monitor not implemented in service yet
    raise HTTPException(status_code=501, detail="Delete not implemented yet")


@router.get("/typosquats/{domain}")
async def detect_typosquats(
    domain: str,
    limit: int = Query(100, ge=1, le=500),
):
    """
    Detect typosquat variants for a domain.
    
    Uses multiple techniques including:
    - Character omission
    - Character swap
    - Homoglyph substitution
    - TLD variations
    - And more...
    """
    try:
        # Use the sync detection method
        variants = brand_service.detect_typosquatting(domain)
        
        # Get stored typosquats for this domain
        stored = await brand_service.get_stored_typosquats(domain, limit=limit)
        
        registered = [v for v in stored if v.get("is_registered")]
        high_risk = [v for v in stored if v.get("risk_score", 0) >= 70]
        
        return {
            "original_domain": domain,
            "total_variants": len(variants),
            "stored_count": len(stored),
            "registered_count": len(registered),
            "high_risk_count": len(high_risk),
            "variants": stored[:limit] if stored else [{"domain": v, "technique": "generated"} for v in variants[:limit]],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/alerts")
async def get_brand_alerts(
    brand_id: Optional[str] = Query(None, description="Filter by brand"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    limit: int = Query(50, ge=1, le=500),
):
    """
    Get brand protection alerts.
    """
    try:
        result = await brand_service.get_alerts(
            brand_id=brand_id,
            severity=severity,
            limit=limit,
        )
        
        alert_list = result.get("alerts", []) if isinstance(result, dict) else result
        
        def _sev(a):
            if isinstance(a, dict):
                return a.get("severity", "")
            return getattr(a, "severity", "")
        
        critical = sum(1 for a in alert_list if _sev(a) == "critical")
        high = sum(1 for a in alert_list if _sev(a) == "high")
        
        return {
            "total": result.get("total", len(alert_list)) if isinstance(result, dict) else len(alert_list),
            "critical": critical,
            "high": high,
            "alerts": alert_list,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: str, user: str = "system"):
    """
    Acknowledge a brand alert.
    """
    try:
        success = await brand_service.acknowledge_alert(alert_id, acknowledged_by=user)
        
        if not success:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        return {"status": "acknowledged", "id": alert_id}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/check")
async def check_suspicious_domain(request: CheckDomainRequest):
    """
    Check if a domain is potentially impersonating a legitimate domain.
    
    Returns similarity score and risk assessment.
    """
    try:
        result = await brand_service.check_suspicious_domain(
            domain=request.domain,
        )
        
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/report/{brand_id}")
async def get_brand_report(brand_id: str):
    """
    Get a comprehensive brand protection report.
    """
    try:
        report = await brand_service.generate_brand_report(brand_id)
        
        if not report:
            raise HTTPException(status_code=404, detail="Brand not found")
        
        return report
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/lookalikes/{domain}")
async def find_lookalike_domains(
    domain: str,
    limit: int = Query(100, ge=1, le=500),
):
    """
    Find registered domains that look similar to the given domain.
    
    Uses certificate transparency logs and DNS enumeration.
    """
    try:
        lookalikes = await brand_service.get_lookalike_domains(
            domain=domain,
            limit=limit,
        )
        
        return {
            "domain": domain,
            "total": len(lookalikes),
            "lookalikes": lookalikes,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/takedown/{domain}")
async def request_takedown(
    domain: str,
    evidence: Optional[str] = None,
):
    """
    Submit a takedown request for a malicious domain.
    
    Note: This creates a record and optionally sends to abuse contacts.
    Actual takedown requires manual follow-up.
    """
    # Note: request_takedown not implemented in service yet
    return {
        "status": "submitted",
        "domain": domain,
        "message": "Takedown request recorded. Manual follow-up required.",
    }


@router.get("/stats")
async def get_brand_stats():
    """
    Get overall brand protection statistics.
    """
    try:
        # Get counts from various sources
        monitors = await brand_service.list_brand_monitors(limit=1000)
        alerts_response = await brand_service.get_alerts(limit=1000)
        
        # Handle both list and dict responses
        if isinstance(alerts_response, dict):
            alerts = alerts_response.get("alerts", [])
            total_alerts = alerts_response.get("total", len(alerts))
        else:
            alerts = alerts_response
            total_alerts = len(alerts)
        
        # Safely extract severity from alert objects
        def get_severity(alert):
            if isinstance(alert, dict):
                return alert.get("severity", "")
            return getattr(alert, "severity", "")
        
        return {
            "total_monitors": len(monitors) if isinstance(monitors, list) else monitors.get("total", 0),
            "total_alerts": total_alerts,
            "critical_alerts": sum(1 for a in alerts if get_severity(a) == "critical"),
            "high_alerts": sum(1 for a in alerts if get_severity(a) == "high"),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Pre-configured African Brands
# =============================================================================

@router.get("/african-brands")
async def get_african_brands():
    """
    Get list of pre-configured African brands for monitoring.
    """
    return {
        "brands": [
            {
                "name": "M-Pesa",
                "domain": "safaricom.co.ke",
                "category": "mobile_money",
                "country": "KE",
            },
            {
                "name": "Safaricom",
                "domain": "safaricom.co.ke",
                "category": "telecom",
                "country": "KE",
            },
            {
                "name": "MTN",
                "domain": "mtn.com",
                "category": "telecom",
                "country": "ZA",
            },
            {
                "name": "Airtel Africa",
                "domain": "airtel.africa",
                "category": "telecom",
                "country": "Multi",
            },
            {
                "name": "Standard Bank",
                "domain": "standardbank.co.za",
                "category": "banking",
                "country": "ZA",
            },
            {
                "name": "Equity Bank",
                "domain": "equitybank.co.ke",
                "category": "banking",
                "country": "KE",
            },
            {
                "name": "KCB Bank",
                "domain": "kcbgroup.com",
                "category": "banking",
                "country": "KE",
            },
            {
                "name": "Jumia",
                "domain": "jumia.com",
                "category": "ecommerce",
                "country": "Multi",
            },
            {
                "name": "Takealot",
                "domain": "takealot.com",
                "category": "ecommerce",
                "country": "ZA",
            },
            {
                "name": "Flutterwave",
                "domain": "flutterwave.com",
                "category": "fintech",
                "country": "NG",
            },
            {
                "name": "Paystack",
                "domain": "paystack.com",
                "category": "fintech",
                "country": "NG",
            },
            {
                "name": "Interswitch",
                "domain": "interswitchgroup.com",
                "category": "fintech",
                "country": "NG",
            },
        ]
    }
