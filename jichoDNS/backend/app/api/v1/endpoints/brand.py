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

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel

from app.api.deps import get_current_user
from app.models.user import User
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
    current_user: User = Depends(get_current_user),
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
            owner_user_id=current_user.id,
        )

        return monitor.model_dump() if hasattr(monitor, "model_dump") else monitor.__dict__
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/monitors")
async def list_brand_monitors(
    active_only: bool = Query(True),
    limit: int = Query(200, ge=1, le=500),
    current_user: User = Depends(get_current_user),
):
    """List all monitored brands directly from Elasticsearch."""
    try:
        await brand_service.connect()
        es = brand_service.es_client
        if not es:
            raise HTTPException(status_code=503, detail="Elasticsearch unavailable")

        if current_user.is_admin:
            query = {"match_all": {}}
        else:
            query = {"bool": {"filter": [{"term": {"owner_user_id": current_user.id}}]}}
        resp = await es.search(
            index="brand_monitors",
            query=query,
            size=limit,
            track_total_hits=True,
        )
        brands_list = [h["_source"] for h in resp["hits"]["hits"]]
        total_raw = resp["hits"]["total"]
        total = total_raw["value"] if isinstance(total_raw, dict) else int(total_raw)
        # Sort in Python: by typosquat_count desc
        brands_list.sort(key=lambda b: int(b.get("typosquat_count", 0) or 0), reverse=True)
        return {"total": total, "brands": brands_list}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/monitors/{brand_id}")
async def get_brand_monitor(
    brand_id: str,
    current_user: User = Depends(get_current_user),
):
    """Get details of a specific brand monitor."""
    try:
        brand = await brand_service.get_brand_monitor(brand_id)
        if not brand:
            raise HTTPException(status_code=404, detail="Brand monitor not found")
        if not current_user.is_admin and getattr(brand, "owner_user_id", None) != current_user.id:
            raise HTTPException(status_code=404, detail="Brand monitor not found")
        return brand.model_dump() if hasattr(brand, "model_dump") else brand.__dict__
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/monitors/{brand_id}")
async def delete_brand_monitor(
    brand_id: str,
    current_user: User = Depends(get_current_user),
):
    """Delete a brand monitor."""
    try:
        await brand_service.connect()
        if not brand_service.es_client:
            raise HTTPException(status_code=503, detail="Elasticsearch unavailable")

        # Check it exists and is owned by the caller
        brand = await brand_service.get_brand_monitor(brand_id)
        if not brand:
            raise HTTPException(status_code=404, detail="Brand monitor not found")
        if not current_user.is_admin and getattr(brand, "owner_user_id", None) != current_user.id:
            raise HTTPException(status_code=404, detail="Brand monitor not found")

        # Delete from ES
        await brand_service.es_client.delete(
            index=brand_service.brand_index, id=brand_id, refresh="wait_for",
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
    brand_name: Optional[str] = Query(None),
    client_id: Optional[int] = Query(None),
    severity: Optional[str] = Query(None),
    alert_type: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """Get brand protection alerts with filtering and pagination."""
    try:
        await brand_service.connect()
        es = brand_service.es_client
        if not es:
            raise HTTPException(status_code=503, detail="Elasticsearch unavailable")

        filters = []
        if brand_id:
            filters.append({"term": {"brand_id": brand_id}})
        if brand_name:
            filters.append({"match": {"brand_name": brand_name}})
        if client_id:
            filters.append({"term": {"client_id": client_id}})
        if severity:
            filters.append({"term": {"severity": severity}})
        if alert_type:
            filters.append({"term": {"alert_type": alert_type}})

        query = {"bool": {"filter": filters}} if filters else {"match_all": {}}

        resp = await es.search(
            index="brand_alerts",
            query=query,
            sort=[{"severity": {"order": "asc"}}, {"detected_at": "desc"}],
            size=limit,
            from_=offset,
            track_total_hits=True,
        )
        alert_list = [h["_source"] for h in resp["hits"]["hits"]]
        total_raw = resp["hits"]["total"]
        total = total_raw["value"] if isinstance(total_raw, dict) else int(total_raw)

        def _sev(a):
            return a.get("severity", "") if isinstance(a, dict) else ""

        return {
            "total": total,
            "critical": sum(1 for a in alert_list if _sev(a) == "critical"),
            "high": sum(1 for a in alert_list if _sev(a) == "high"),
            "alerts": alert_list,
        }
    except HTTPException:
        raise
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
    """Get overall brand protection statistics directly from Elasticsearch."""
    try:
        await brand_service.connect()
        es = brand_service.es_client
        if not es:
            raise HTTPException(status_code=503, detail="Elasticsearch unavailable")

        # Count monitors
        mon_count = await es.count(index="brand_monitors", query={"match_all": {}})
        total_monitors = mon_count.get("count", 0)

        # Count all alerts
        alert_count = await es.count(index="brand_alerts", query={"match_all": {}})
        total_alerts = alert_count.get("count", 0)

        # Count critical alerts
        crit_count = await es.count(index="brand_alerts", query={"term": {"severity": "critical"}})
        critical_alerts = crit_count.get("count", 0)

        # Count high alerts
        high_count = await es.count(index="brand_alerts", query={"term": {"severity": "high"}})
        high_alerts = high_count.get("count", 0)

        # Count typosquats (domain_registered + typosquat_detected)
        typo_count = await es.count(index="brand_alerts", query={"bool": {"should": [
            {"term": {"alert_type": "typosquat_detected"}},
            {"term": {"alert_type": "domain_registered"}},
        ], "minimum_should_match": 1}})
        total_typosquats = typo_count.get("count", 0)

        return {
            "total_monitors": total_monitors,
            "total_alerts": total_alerts,
            "critical_alerts": critical_alerts,
            "high_alerts": high_alerts,
            "total_typosquats": total_typosquats,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Pre-configured African Brands
# =============================================================================

# =============================================================================
# Credential Leaks — per brand monitor (live query against credential_exposures)
# =============================================================================

# Generic words whose IOC matches are false positives (too broad)
_GENERIC_IOC_WORDS = {
    "orange", "telecom", "telkom", "openserve", "mobile", "airtel", "mtn",
    "vodacom", "standard", "first", "national", "bank", "blue", "red",
}

@router.get("/monitors/{monitor_id}/credentials")
async def get_brand_credentials(
    monitor_id: str,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = Query(None),
    _current_user: User = Depends(get_current_user),
):
    """
    Return actual leaked credential records for this brand monitor's domains.
    Queries credential_exposures index live — no duplication.
    """
    try:
        await brand_service.connect()
        es = brand_service.es_client
        if not es:
            raise HTTPException(status_code=503, detail="Elasticsearch unavailable")

        # Load monitor to get domains
        mon_resp = await es.get(index="brand_monitors", id=monitor_id)
        monitor = mon_resp["_source"]
        if not _current_user.is_admin and monitor.get("owner_user_id") != _current_user.id:
            raise HTTPException(status_code=404, detail="Brand monitor not found")
        domains = monitor.get("domains", [])
        bare_domains = list(set(d.lstrip("www.") for d in domains if d))

        if not bare_domains:
            return {"total": 0, "records": [], "by_severity": {}, "by_source": {}, "domains_checked": []}

        filters: list = [{"bool": {"should": [{"term": {"domain": d}} for d in bare_domains], "minimum_should_match": 1}}]
        if severity:
            filters.append({"term": {"severity": severity}})

        resp = await es.search(
            index="credential_exposures",
            query={"bool": {"filter": filters}},
            sort=[{"severity": {"order": "asc"}}, {"breach_date": {"order": "desc", "unmapped_type": "date"}}],
            size=limit,
            from_=offset,
            track_total_hits=True,
            _source=["email", "username", "domain", "password_type", "password_length",
                     "source_name", "breach_date", "severity", "country", "vip_match", "tags"],
        )

        total_raw = resp["hits"]["total"]
        total = total_raw["value"] if isinstance(total_raw, dict) else int(total_raw)
        records = [h["_source"] for h in resp["hits"]["hits"]]

        # Aggregate stats (from entire result set — use a separate agg query)
        agg_resp = await es.search(
            index="credential_exposures",
            query={"bool": {"filter": [{"bool": {"should": [{"term": {"domain": d}} for d in bare_domains], "minimum_should_match": 1}}]}},
            size=0,
            aggs={
                "by_severity":     {"terms": {"field": "severity",     "size": 10}},
                "by_source":       {"terms": {"field": "source_name",  "size": 20}},
                "by_type":         {"terms": {"field": "password_type", "size": 10}},
                "by_domain":       {"terms": {"field": "domain",       "size": 20}},
                "plaintext_count": {"filter": {"term": {"password_type": "plaintext"}}},
            },
        )
        aggs = agg_resp.get("aggregations", {})

        def _buckets(key: str) -> dict:
            return {b["key"]: b["doc_count"] for b in aggs.get(key, {}).get("buckets", [])}

        return {
            "total": total,
            "monitor_id": monitor_id,
            "brand_name": monitor.get("brand_name"),
            "domains_checked": bare_domains,
            "plaintext_count": aggs.get("plaintext_count", {}).get("doc_count", 0),
            "by_severity": _buckets("by_severity"),
            "by_source":   _buckets("by_source"),
            "by_type":     _buckets("by_type"),
            "by_domain":   _buckets("by_domain"),
            "records": records,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Threat Intelligence — per brand monitor (live IOC correlation)
# =============================================================================

@router.get("/monitors/{monitor_id}/intel")
async def get_brand_intel(
    monitor_id: str,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    _current_user: User = Depends(get_current_user),
):
    """
    Return IOC feed matches for this brand monitor's domains/keywords.
    Filters out generic keyword matches to avoid false positives.
    """
    try:
        await brand_service.connect()
        es = brand_service.es_client
        if not es:
            raise HTTPException(status_code=503, detail="Elasticsearch unavailable")

        # Load monitor
        mon_resp = await es.get(index="brand_monitors", id=monitor_id)
        monitor = mon_resp["_source"]
        if not _current_user.is_admin and monitor.get("owner_user_id") != _current_user.id:
            raise HTTPException(status_code=404, detail="Brand monitor not found")
        domains = monitor.get("domains", [])

        # Extract specific (non-generic) bases from domains
        specific_bases = []
        for d in domains:
            base = d.lstrip("www.").split(".")[0]
            if len(base) >= 4 and base.lower() not in _GENERIC_IOC_WORDS:
                specific_bases.append(base)
        specific_bases = list(set(specific_bases))

        if not specific_bases:
            return {"total": 0, "records": [], "by_threat_type": {}, "by_source": {}}

        # Also match on exact domain values
        bare_domains = list(set(d.lstrip("www.") for d in domains if d))

        should = (
            [{"terms": {"indicator": bare_domains}}] +
            [{"wildcard": {"indicator": f"*{b}*"}} for b in specific_bases[:4]]
        )

        resp = await es.search(
            index="iocs",
            query={"bool": {
                "should": should,
                "minimum_should_match": 1,
                "filter": [{"term": {"active": True}}],
            }},
            sort=[{"risk_score": {"order": "desc", "unmapped_type": "float"}}],
            size=limit,
            from_=offset,
            track_total_hits=True,
            _source=["indicator", "indicator_type", "threat_type", "source",
                     "risk_score", "tags", "country_code", "first_seen", "last_seen"],
        )

        total_raw = resp["hits"]["total"]
        total = total_raw["value"] if isinstance(total_raw, dict) else int(total_raw)
        records = [h["_source"] for h in resp["hits"]["hits"]]

        # Aggregations
        agg_resp = await es.search(
            index="iocs",
            query={"bool": {"should": should, "minimum_should_match": 1, "filter": [{"term": {"active": True}}]}},
            size=0,
            aggs={
                "by_threat_type": {"terms": {"field": "threat_type", "size": 10}},
                "by_source":      {"terms": {"field": "source",      "size": 20}},
                "by_ioc_type":    {"terms": {"field": "indicator_type", "size": 10}},
            },
        )
        aggs = agg_resp.get("aggregations", {})
        def _buckets(key: str) -> dict:
            return {b["key"]: b["doc_count"] for b in aggs.get(key, {}).get("buckets", [])}

        return {
            "total": total,
            "monitor_id": monitor_id,
            "brand_name": monitor.get("brand_name"),
            "bases_searched": specific_bases,
            "by_threat_type": _buckets("by_threat_type"),
            "by_source":      _buckets("by_source"),
            "by_ioc_type":    _buckets("by_ioc_type"),
            "records": records,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


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
