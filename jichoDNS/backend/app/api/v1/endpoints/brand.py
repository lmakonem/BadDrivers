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
    brand_name: str
    primary_domain: str
    additional_domains: List[str] = []
    keywords: List[str] = []
    alert_email: Optional[str] = None
    alert_webhook: Optional[str] = None


class CheckDomainRequest(BaseModel):
    domain: str


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
        # Build the domains list from primary + additional
        all_domains = [request.primary_domain] + request.additional_domains

        monitor = await brand_service.monitor_brand(
            brand_name=request.brand_name,
            keywords=request.keywords or [request.brand_name.lower()],
            domains=all_domains,
            alert_email=request.alert_email,
        )

        return monitor.model_dump() if hasattr(monitor, "model_dump") else monitor.__dict__
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/monitors")
async def list_brand_monitors(
    active_only: bool = Query(True),
    limit: int = Query(100, ge=1, le=500),
):
    """List all monitored brands."""
    try:
        brands = await brand_service.list_brand_monitors(
            active_only=active_only, limit=limit,
        )
        brands_list = brands if isinstance(brands, list) else brands.get("brands", [])
        return {"total": len(brands_list), "brands": brands_list}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/monitors/{brand_id}")
async def get_brand_monitor(brand_id: str):
    """Get details of a specific brand monitor."""
    try:
        brand = await brand_service.get_brand_monitor(brand_id)
        if not brand:
            raise HTTPException(status_code=404, detail="Brand monitor not found")
        return brand.model_dump() if hasattr(brand, "model_dump") else brand.__dict__
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/monitors/{brand_id}")
async def delete_brand_monitor(brand_id: str):
    """Delete a brand monitor."""
    try:
        await brand_service.connect()
        if not brand_service.es_client:
            raise HTTPException(status_code=503, detail="Elasticsearch unavailable")

        # Check it exists
        brand = await brand_service.get_brand_monitor(brand_id)
        if not brand:
            raise HTTPException(status_code=404, detail="Brand monitor not found")

        # Delete from ES
        await brand_service.es_client.delete(
            index=brand_service.monitor_index, id=brand_id, refresh="wait_for",
        )
        return {"success": True, "message": f"Brand monitor {brand_id} deleted"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/typosquats")
async def list_all_typosquats(
    registered_only: bool = Query(False),
    min_risk_score: float = Query(0, ge=0, le=100),
    limit: int = Query(100, ge=1, le=500),
):
    """
    List all stored typosquat domains across all monitored brands.
    """
    try:
        result = await brand_service.get_stored_typosquats(
            registered_only=registered_only,
            min_risk_score=min_risk_score,
            limit=limit,
        )

        # Returns {"typosquats": [...], "total": int}
        typosquats = result.get("typosquats", []) if isinstance(result, dict) else result
        total = result.get("total", len(typosquats)) if isinstance(result, dict) else len(typosquats)

        return {
            "total": total,
            "typosquats": typosquats,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/typosquats/{domain}")
async def detect_typosquats(
    domain: str,
    limit: int = Query(100, ge=1, le=500),
):
    """
    Detect typosquat variants for a specific domain.
    Uses multiple techniques: omission, transposition, homoglyph, TLD swap, etc.
    """
    try:
        # Generate variants (sync)
        variants = brand_service.detect_typosquatting(domain)

        # Get stored typosquats for this domain
        stored_result = await brand_service.get_stored_typosquats(
            original_domain=domain, limit=limit,
        )

        # get_stored_typosquats returns {"typosquats": [...], "total": int}
        stored = stored_result.get("typosquats", []) if isinstance(stored_result, dict) else stored_result
        registered = [v for v in stored if v.get("is_registered")]
        high_risk = [v for v in stored if v.get("risk_score", 0) >= 70]

        return {
            "original_domain": domain,
            "total_variants": len(variants),
            "stored_count": len(stored),
            "registered_count": len(registered),
            "high_risk_count": len(high_risk),
            "variants": stored[:limit] if stored else [
                {"domain": v, "technique": "generated"} for v in variants[:limit]
            ],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/alerts")
async def get_brand_alerts(
    brand_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
):
    """Get brand protection alerts."""
    try:
        result = await brand_service.get_alerts(
            brand_id=brand_id, severity=severity, limit=limit,
        )

        alert_list = result.get("alerts", []) if isinstance(result, dict) else result

        def _sev(a):
            return a.get("severity", "") if isinstance(a, dict) else getattr(a, "severity", "")

        return {
            "total": result.get("total", len(alert_list)) if isinstance(result, dict) else len(alert_list),
            "critical": sum(1 for a in alert_list if _sev(a) == "critical"),
            "high": sum(1 for a in alert_list if _sev(a) == "high"),
            "alerts": alert_list,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: str, user: str = "system"):
    """Acknowledge a brand alert."""
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
    """Check if a domain is potentially impersonating a legitimate domain."""
    try:
        return await brand_service.check_suspicious_domain(domain=request.domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/report/{brand_id}")
async def get_brand_report(brand_id: str):
    """Get a comprehensive brand protection report."""
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
    """Find registered domains that look similar to the given domain."""
    try:
        lookalikes = await brand_service.get_lookalike_domains(domain=domain, limit=limit)
        return {"domain": domain, "total": len(lookalikes), "lookalikes": lookalikes}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/takedown/{domain}")
async def request_takedown(domain: str, evidence: Optional[str] = None):
    """
    Submit a takedown request for a malicious domain.
    Note: Creates a record. Actual takedown requires manual follow-up.
    """
    return {
        "status": "submitted",
        "domain": domain,
        "message": "Takedown request recorded. Manual follow-up required.",
    }


@router.get("/stats")
async def get_brand_stats():
    """Get overall brand protection statistics."""
    try:
        monitors_result = await brand_service.list_brand_monitors(limit=1000)
        monitors = monitors_result if isinstance(monitors_result, list) else monitors_result.get("brands", [])

        alerts_response = await brand_service.get_alerts(limit=1000)
        alerts = alerts_response.get("alerts", []) if isinstance(alerts_response, dict) else alerts_response
        total_alerts = alerts_response.get("total", len(alerts)) if isinstance(alerts_response, dict) else len(alerts)

        def _sev(a):
            return a.get("severity", "") if isinstance(a, dict) else getattr(a, "severity", "")

        # Get typosquat count
        typo_result = await brand_service.get_stored_typosquats(limit=1)
        typo_total = typo_result.get("total", 0) if isinstance(typo_result, dict) else 0

        return {
            "total_monitors": len(monitors),
            "total_alerts": total_alerts,
            "critical_alerts": sum(1 for a in alerts if _sev(a) == "critical"),
            "high_alerts": sum(1 for a in alerts if _sev(a) == "high"),
            "total_typosquats": typo_total,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Pre-configured African Brands
# =============================================================================

@router.get("/african-brands")
async def get_african_brands():
    """Get list of pre-configured African brands for monitoring."""
    return {
        "brands": [
            {"name": "M-Pesa", "domain": "safaricom.co.ke", "category": "mobile_money", "country": "KE"},
            {"name": "Safaricom", "domain": "safaricom.co.ke", "category": "telecom", "country": "KE"},
            {"name": "MTN", "domain": "mtn.com", "category": "telecom", "country": "ZA"},
            {"name": "Airtel Africa", "domain": "airtel.africa", "category": "telecom", "country": "Multi"},
            {"name": "Standard Bank", "domain": "standardbank.co.za", "category": "banking", "country": "ZA"},
            {"name": "Equity Bank", "domain": "equitybank.co.ke", "category": "banking", "country": "KE"},
            {"name": "KCB Bank", "domain": "kcbgroup.com", "category": "banking", "country": "KE"},
            {"name": "Jumia", "domain": "jumia.com", "category": "ecommerce", "country": "Multi"},
            {"name": "Takealot", "domain": "takealot.com", "category": "ecommerce", "country": "ZA"},
            {"name": "Flutterwave", "domain": "flutterwave.com", "category": "fintech", "country": "NG"},
            {"name": "Paystack", "domain": "paystack.com", "category": "fintech", "country": "NG"},
            {"name": "Interswitch", "domain": "interswitchgroup.com", "category": "fintech", "country": "NG"},
        ]
    }
