"""
Attack Surface Management API Endpoints

Provides endpoints for:
- Asset discovery
- Vulnerability scanning
- Port scanning
- SSL/TLS analysis
- Asset change monitoring
"""

from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel

from app.services.attack_surface import (
    AttackSurfaceManager,
    Asset,
    AssetType,
    Vulnerability,
    AssetChange,
    DiscoveryResult,
)

router = APIRouter()
asm_service = AttackSurfaceManager()


# =============================================================================
# Request/Response Models
# =============================================================================

class DiscoverRequest(BaseModel):
    """Request model for asset discovery."""
    domain: str
    include_subdomains: bool = True
    include_ports: bool = True
    include_ssl: bool = True


class ScanRequest(BaseModel):
    """Request model for security scan."""
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
    try:
        # Run discovery
        result = await asm_service.discover_assets(
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
    """
    List discovered assets.
    """
    try:
        result = await asm_service.get_assets(
            asset_type=AssetType(asset_type) if asset_type else None,
            limit=limit,
            offset=offset,
        )
        
        # Handle different return types
        if isinstance(result, tuple):
            assets, by_type = result
        else:
            assets = result
            by_type = {}
            for asset in assets:
                t = asset.get("type", "unknown") if isinstance(asset, dict) else getattr(asset, "type", "unknown")
                by_type[str(t)] = by_type.get(str(t), 0) + 1
        
        return {
            "total": len(assets),
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
    """
    List discovered vulnerabilities.
    """
    try:
        vulns = await asm_service.get_vulnerabilities(
            severity=severity,
            asset_id=asset_id,
            limit=limit,
        )
        
        # Count by severity
        critical = sum(1 for v in vulns if (v.get("severity") if isinstance(v, dict) else getattr(v, "severity", "")) == "critical")
        high = sum(1 for v in vulns if (v.get("severity") if isinstance(v, dict) else getattr(v, "severity", "")) == "high")
        medium = sum(1 for v in vulns if (v.get("severity") if isinstance(v, dict) else getattr(v, "severity", "")) == "medium")
        low = sum(1 for v in vulns if (v.get("severity") if isinstance(v, dict) else getattr(v, "severity", "")) == "low")
        
        return {
            "total": len(vulns),
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
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
    """
    Get recent asset changes.
    """
    try:
        changes = await asm_service.get_changes(
            asset_id=asset_id,
            days=days,
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
    """
    Run a security scan on a target.
    """
    try:
        results = {}
        
        # Run port scan
        if request.scan_type in ["full", "ports"]:
            ports_result = await asm_service.scan_ports(request.target)
            results["ports"] = ports_result
        
        # Run SSL check if it's a domain
        if request.scan_type in ["full", "ssl"]:
            try:
                ssl_result = await asm_service.check_ssl_certificates(request.target)
                results["ssl"] = ssl_result
            except Exception:
                results["ssl"] = None
        
        # Run vulnerability check
        if request.scan_type in ["full", "vulnerabilities"]:
            try:
                vuln_result = await asm_service.check_vulnerabilities(request.target)
                results["vulnerabilities"] = vuln_result
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
async def get_summary(domain: Optional[str] = Query(None, description="Filter by domain")):
    """
    Get attack surface summary statistics.
    """
    try:
        summary = await asm_service.get_summary(domain=domain)
        
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
    """
    Check SSL/TLS configuration for a domain.
    """
    try:
        result = await asm_service.check_ssl_certificates(domain)
        
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/dns/{domain}")
async def get_dns_records(domain: str):
    """
    Get DNS records for a domain.
    """
    try:
        records = await asm_service.get_dns_records(domain)
        
        return {
            "domain": domain,
            "records": [r.model_dump() if hasattr(r, 'model_dump') else r for r in records],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/ports/{target}")
async def scan_ports(
    target: str,
    ports: str = Query("1-1000", description="Port range to scan"),
):
    """
    Scan ports on a target IP or domain.
    """
    try:
        # Parse port range
        port_list = []
        for part in ports.split(","):
            if "-" in part:
                start, end = part.split("-")
                port_list.extend(range(int(start), int(end) + 1))
            else:
                port_list.append(int(part))
        
        result = await asm_service.scan_ports(target, port_list[:100])  # Limit to 100 ports
        
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/subdomains/{domain}")
async def discover_subdomains(domain: str):
    """
    Discover subdomains for a domain using multiple sources.
    """
    try:
        subdomains = await asm_service._discover_subdomains(domain)
        
        return {
            "domain": domain,
            "total": len(subdomains),
            "subdomains": list(subdomains),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/services/{domain}")
async def find_exposed_services(domain: str):
    """
    Find exposed services for a domain.
    """
    try:
        services = await asm_service.find_exposed_services(domain)
        
        return {
            "domain": domain,
            "total": len(services),
            "services": [s.model_dump() if hasattr(s, 'model_dump') else s for s in services],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats")
async def get_asm_stats():
    """
    Get overall attack surface management statistics.
    """
    try:
        # Get assets
        assets_result = await asm_service.get_assets(limit=10000)
        if isinstance(assets_result, tuple):
            assets, by_type = assets_result
        else:
            assets = assets_result
            by_type = {}
        
        # Get vulnerabilities
        vulns = await asm_service.get_vulnerabilities(limit=10000)
        
        # Count vulnerabilities by severity
        critical = sum(1 for v in vulns if (v.get("severity") if isinstance(v, dict) else getattr(v, "severity", "")) == "critical")
        high = sum(1 for v in vulns if (v.get("severity") if isinstance(v, dict) else getattr(v, "severity", "")) == "high")
        medium = sum(1 for v in vulns if (v.get("severity") if isinstance(v, dict) else getattr(v, "severity", "")) == "medium")
        low = sum(1 for v in vulns if (v.get("severity") if isinstance(v, dict) else getattr(v, "severity", "")) == "low")
        
        # Get recent changes
        from datetime import datetime, timedelta
        changes = await asm_service.get_changes(since=datetime.utcnow() - timedelta(days=7), limit=100)
        
        return {
            "total_assets": len(assets),
            "assets_by_type": by_type,
            "total_vulnerabilities": len(vulns),
            "vulnerabilities_by_severity": {
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
            },
            "recent_changes": len(changes),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
