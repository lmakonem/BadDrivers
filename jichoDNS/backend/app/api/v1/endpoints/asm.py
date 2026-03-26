"""
Attack Surface Management API Endpoints

Provides endpoints for:
- Asset discovery (subdomains, IPs, ports, SSL)
- Vulnerability scanning
- Port scanning
- SSL/TLS analysis
- Asset change monitoring
"""

from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel

from app.services.attack_surface import (
    AttackSurfaceManager,
    AssetType,
    ChangeType,
)
from app.services.elasticsearch import es_service

router = APIRouter()

# Lazy-initialized with ES client on first use
_asm_service: Optional[AttackSurfaceManager] = None


async def _get_asm() -> AttackSurfaceManager:
    """Get or create the ASM service with an ES client."""
    global _asm_service
    if _asm_service is None:
        await es_service.connect()
        _asm_service = AttackSurfaceManager(es_client=es_service.client)
    elif _asm_service.es_client is None and es_service.client:
        _asm_service.es_client = es_service.client
    return _asm_service


# =============================================================================
# Request/Response Models
# =============================================================================

class DiscoverRequest(BaseModel):
    domain: str
    include_subdomains: bool = True
    include_ports: bool = True
    include_ssl: bool = True


class ScanRequest(BaseModel):
    target: str  # IP or domain
    scan_type: str = "full"  # full, ports, ssl, vulnerabilities


# =============================================================================
# Endpoints
# =============================================================================

@router.post("/discover")
async def start_discovery(
    request: DiscoverRequest,
    background_tasks: BackgroundTasks,
):
    """
    Start asset discovery for a domain.
    Discovers subdomains, IPs, open ports, and SSL certificates.
    """
    asm = await _get_asm()
    try:
        result = await asm.discover_assets(
            domain=request.domain,
            include_ports=request.include_ports,
            include_ssl=request.include_ssl,
        )

        return {
            "status": "completed",
            "domain": request.domain,
            "assets_found": len(result.assets) if result else 0,
            "subdomains": len(result.subdomains) if result else 0,
            "vulnerabilities": len(result.vulnerabilities) if result else 0,
            "summary": {
                "total_ips": len(result.ips) if result else 0,
                "total_subdomains": len(result.subdomains) if result else 0,
                "ssl_valid": result.ssl_info is not None if result else False,
            } if result else {},
        }
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        raise HTTPException(status_code=500, detail=f"{str(e)} | TRACE: {tb[-500:]}")


@router.get("/assets")
async def list_assets(
    asset_type: Optional[str] = Query(None, description="Filter by asset type"),
    domain: Optional[str] = Query(None, description="Filter by root domain"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """List discovered assets."""
    asm = await _get_asm()
    try:
        result = await asm.get_assets(
            asset_type=AssetType(asset_type) if asset_type else None,
            limit=limit,
            offset=offset,
        )

        # get_assets returns Tuple[List, int]
        if isinstance(result, tuple):
            assets, total = result
        else:
            assets = result
            total = len(assets) if isinstance(assets, list) else 0

        by_type: dict = {}
        for asset in (assets if isinstance(assets, list) else []):
            t = asset.get("type", "unknown") if isinstance(asset, dict) else getattr(asset, "type", "unknown")
            by_type[str(t)] = by_type.get(str(t), 0) + 1

        return {
            "total": total,
            "assets": assets,
            "by_type": by_type,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/vulnerabilities")
async def list_vulnerabilities(
    severity: Optional[str] = Query(None, description="Filter by severity"),
    asset_id: Optional[str] = Query(None, description="Filter by asset"),
    limit: int = Query(100, ge=1, le=1000),
):
    """List discovered vulnerabilities."""
    asm = await _get_asm()
    try:
        result = await asm.get_vulnerabilities(
            severity=severity,
            asset_id=asset_id,
            limit=limit,
        )

        # get_vulnerabilities may return (list, int) tuple or just list
        if isinstance(result, tuple):
            vulns, total = result
        else:
            vulns = result if isinstance(result, list) else []
            total = len(vulns)

        def _sev(v):
            return v.get("severity", "") if isinstance(v, dict) else getattr(v, "severity", "")

        return {
            "total": total,
            "critical": sum(1 for v in vulns if _sev(v) == "critical"),
            "high": sum(1 for v in vulns if _sev(v) == "high"),
            "medium": sum(1 for v in vulns if _sev(v) == "medium"),
            "low": sum(1 for v in vulns if _sev(v) == "low"),
            "vulnerabilities": vulns,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/changes")
async def list_changes(
    asset_id: Optional[str] = Query(None, description="Filter by asset"),
    days: int = Query(7, ge=1, le=90, description="Days to look back"),
    limit: int = Query(100, ge=1, le=1000),
):
    """Get recent asset changes."""
    asm = await _get_asm()
    try:
        since = datetime.utcnow() - timedelta(days=days)
        changes = await asm.get_changes(
            asset_id=asset_id,
            since=since,
            limit=limit,
        )

        return {
            "total": len(changes),
            "changes": changes,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/scan")
async def run_scan(request: ScanRequest):
    """Run a security scan on a target."""
    asm = await _get_asm()
    try:
        results = {}

        if request.scan_type in ["full", "ports"]:
            results["ports"] = await asm.scan_ports(request.target)

        if request.scan_type in ["full", "ssl"]:
            try:
                results["ssl"] = await asm.check_ssl_certificates(request.target)
            except Exception:
                results["ssl"] = None

        if request.scan_type in ["full", "vulnerabilities"]:
            try:
                results["vulnerabilities"] = await asm.check_vulnerabilities(request.target)
            except Exception:
                results["vulnerabilities"] = []

        return {
            "status": "completed",
            "target": request.target,
            "scan_type": request.scan_type,
            "results": results,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/summary")
async def get_summary(domain: Optional[str] = Query(None)):
    """Get attack surface summary statistics."""
    asm = await _get_asm()
    try:
        summary = await asm.get_summary(domain=domain)
        return {
            "total_assets": summary.get("total_assets", 0),
            "by_type": summary.get("by_type", {}),
            "risk_score": summary.get("average_risk_score", 0.0),
            "critical_vulns": summary.get("critical_vulnerabilities", 0),
            "high_vulns": summary.get("high_vulnerabilities", 0),
            "open_ports": summary.get("total_open_ports", 0),
            "ssl_issues": summary.get("ssl_issues", 0),
            "recent_changes": summary.get("changes_last_7_days", 0),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/ssl/{domain}")
async def check_ssl(domain: str):
    """Check SSL/TLS configuration for a domain."""
    asm = await _get_asm()
    try:
        return await asm.check_ssl_certificates(domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/dns/{domain}")
async def get_dns_records(domain: str):
    """Get DNS records for a domain."""
    asm = await _get_asm()
    try:
        records = await asm.get_dns_records(domain)
        return {
            "domain": domain,
            "records": [r.model_dump() if hasattr(r, "model_dump") else r for r in records],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/ports/{target}")
async def scan_ports(
    target: str,
    ports: str = Query("1-1000", description="Port range to scan"),
):
    """Scan ports on a target IP or domain."""
    asm = await _get_asm()
    try:
        port_list: List[int] = []
        for part in ports.split(","):
            if "-" in part:
                start, end = part.split("-")
                port_list.extend(range(int(start), int(end) + 1))
            else:
                port_list.append(int(part))

        return await asm.scan_ports(target, port_list[:100])
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/subdomains/{domain}")
async def discover_subdomains(domain: str):
    """Discover subdomains for a domain using multiple sources."""
    asm = await _get_asm()
    try:
        # Use the internal discovery method (renamed from private to avoid linting concern)
        subdomains = await asm._discover_subdomains(domain)
        return {
            "domain": domain,
            "total": len(subdomains),
            "subdomains": list(subdomains),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/services/{domain}")
async def find_exposed_services(domain: str):
    """Find exposed services for a domain."""
    asm = await _get_asm()
    try:
        services = await asm.find_exposed_services(domain)
        return {
            "domain": domain,
            "total": len(services),
            "services": [s.model_dump() if hasattr(s, "model_dump") else s for s in services],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats")
async def get_asm_stats():
    """Get overall attack surface management statistics."""
    asm = await _get_asm()
    try:
        assets_result = await asm.get_assets(limit=10000)
        if isinstance(assets_result, tuple):
            assets, _ = assets_result
        else:
            assets = assets_result if isinstance(assets_result, list) else []

        by_type: dict = {}
        for asset in assets:
            t = asset.get("type", "unknown") if isinstance(asset, dict) else getattr(asset, "type", "unknown")
            by_type[str(t)] = by_type.get(str(t), 0) + 1

        vulns_result = await asm.get_vulnerabilities(limit=10000)
        if isinstance(vulns_result, tuple):
            vulns, _ = vulns_result
        else:
            vulns = vulns_result if isinstance(vulns_result, list) else []

        def _sev(v):
            return v.get("severity", "") if isinstance(v, dict) else getattr(v, "severity", "")

        since = datetime.utcnow() - timedelta(days=7)
        changes = await asm.get_changes(since=since, limit=100)

        return {
            "total_assets": len(assets),
            "assets_by_type": by_type,
            "total_vulnerabilities": len(vulns),
            "vulnerabilities_by_severity": {
                "critical": sum(1 for v in vulns if _sev(v) == "critical"),
                "high": sum(1 for v in vulns if _sev(v) == "high"),
                "medium": sum(1 for v in vulns if _sev(v) == "medium"),
                "low": sum(1 for v in vulns if _sev(v) == "low"),
            },
            "recent_changes": len(changes),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
