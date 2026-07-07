"""
Reports API endpoints — real HTML report generation from ES data.

Provides endpoints for generating, listing, viewing (HTML), downloading,
and deleting threat intelligence reports.  Also serves sample/demo reports
that work without Elasticsearch for showcasing the platform.

IMPORTANT: Fixed-path routes (/samples, /types/available, /generate) are
registered BEFORE dynamic /{report_id} routes to prevent FastAPI from
matching literal segments as path parameters.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field

from app.api.deps import get_current_user
from app.models.user import User
from app.services.elasticsearch import es_service
from app.services.report_generator import (
    generate_report as build_report,
    generate_sample_report as build_sample,
)

logger = logging.getLogger(__name__)

router = APIRouter()

REPORTS_INDEX = "threat_reports"

VALID_TYPES = {
    "threat_intelligence", "incident_summary", "executive_briefing",
    "ioc_analysis", "dark_web_exposure",
}

TYPE_MAP = {
    "weekly": "threat_intelligence", "monthly": "threat_intelligence",
    "custom": "threat_intelligence", "incident": "incident_summary",
    "executive": "executive_briefing",
}


# =============================================================================
# Pydantic models
# =============================================================================

class GenerateReportRequest(BaseModel):
    report_type: str = Field(default="threat_intelligence")
    title: Optional[str] = Field(default=None)
    time_range: str = Field(default="7d")
    include_iocs: bool = Field(default=True)
    include_darkweb: bool = Field(default=True)
    include_credentials: bool = Field(default=True)
    custom_prompt: Optional[str] = Field(default=None)


class ReportSummary(BaseModel):
    id: str
    title: str
    type: str
    status: str
    severity: str
    generated_at: str
    date_range: str = "7d"
    description: str = ""
    stats: dict = {}
    pages: int = 1
    is_sample: bool = False


class ReportListResponse(BaseModel):
    reports: List[ReportSummary]
    total: int
    page: int
    page_size: int


class ReportDetail(BaseModel):
    id: str
    title: str
    type: str
    status: str
    severity: str
    generated_at: str
    date_range: str = "7d"
    description: str = ""
    stats: dict = {}
    pages: int = 1
    html: Optional[str] = None
    is_sample: bool = False


class DeleteResponse(BaseModel):
    success: bool
    message: str


# =============================================================================
# Helpers
# =============================================================================

async def _ensure_index():
    if not es_service.client:
        await es_service.connect()
    if not es_service.client:
        return
    try:
        exists = await es_service.client.indices.exists(index=REPORTS_INDEX)
        if not exists:
            await es_service.client.indices.create(
                index=REPORTS_INDEX,
                body={
                    "mappings": {
                        "properties": {
                            "id": {"type": "keyword"},
                            "title": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                            "type": {"type": "keyword"},
                            "status": {"type": "keyword"},
                            "severity": {"type": "keyword"},
                            "generated_at": {"type": "date"},
                            "date_range": {"type": "keyword"},
                            "description": {"type": "text"},
                            "stats": {"type": "object", "enabled": False},
                            "pages": {"type": "integer"},
                            "html": {"type": "text", "index": False},
                            "is_sample": {"type": "boolean"},
                            "owner_user_id": {"type": "integer"},
                        }
                    }
                },
            )
    except Exception as e:
        logger.warning(f"Index setup: {e}")


async def _store_report(doc: dict) -> bool:
    await _ensure_index()
    if not es_service.client:
        return False
    try:
        await es_service.client.index(
            index=REPORTS_INDEX, id=doc["id"], document=doc, refresh="wait_for",
        )
        return True
    except Exception as e:
        logger.error(f"Store report error: {e}")
        return False


def _resolve_type(raw: str) -> str:
    return TYPE_MAP.get(raw, raw)


# =============================================================================
# Sample / demo reports (no ES required)
# =============================================================================

_SAMPLE_IDS = {
    "threat_intelligence": "sample-threat-intel-001",
    "executive_briefing":  "sample-exec-brief-001",
    "ioc_analysis":        "sample-ioc-analysis-001",
    "incident_summary":    "sample-incident-001",
    "dark_web_exposure":   "sample-darkweb-001",
}


def _build_sample(rtype: str) -> dict:
    result = build_sample(rtype)
    sid = _SAMPLE_IDS.get(rtype, f"sample-{rtype}-001")
    return {
        "id": sid,
        "title": result["title"],
        "type": result["type"],
        "status": "ready",
        "severity": result["severity"],
        "generated_at": result["generated_at"],
        "date_range": result.get("date_range", "7d"),
        "description": result.get("description", ""),
        "stats": result.get("stats", {}),
        "pages": result.get("pages", 1),
        "html": result["html"],
        "is_sample": True,
    }


def _get_sample_if_exists(report_id: str) -> Optional[dict]:
    for rtype, sid in _SAMPLE_IDS.items():
        if report_id == sid:
            return _build_sample(rtype)
    return None


# =============================================================================
# FIXED-PATH ROUTES  (must come BEFORE /{report_id} dynamic routes)
# =============================================================================

@router.get("/types/available")
async def get_report_types():
    """List available report types, severity levels, and time ranges."""
    return {
        "report_types": [
            {"value": "threat_intelligence", "name": "Threat Intelligence Report",
             "description": "Comprehensive threat landscape analysis with IOCs, sources, and geo distribution"},
            {"value": "incident_summary", "name": "Incident Summary",
             "description": "Security incident timeline, attack vectors, and containment actions"},
            {"value": "executive_briefing", "name": "Executive Briefing",
             "description": "High-level summary for leadership with key metrics and business impact"},
            {"value": "ioc_analysis", "name": "IOC Analysis Report",
             "description": "Detailed IOC breakdown by type, threat category, and geographic origin"},
            {"value": "dark_web_exposure", "name": "Dark Web Exposure Report",
             "description": "Credential leaks, brand mentions, dark web posts, and typosquatting"},
        ],
        "severity_levels": [
            {"value": "critical", "name": "Critical"}, {"value": "high", "name": "High"},
            {"value": "medium", "name": "Medium"}, {"value": "low", "name": "Low"},
        ],
        "time_ranges": [
            {"value": "1h", "name": "Last Hour"}, {"value": "6h", "name": "Last 6 Hours"},
            {"value": "24h", "name": "Last 24 Hours"}, {"value": "7d", "name": "Last 7 Days"},
            {"value": "30d", "name": "Last 30 Days"}, {"value": "90d", "name": "Last 90 Days"},
        ],
    }


@router.get("/samples")
async def list_sample_reports():
    """
    Return all 5 sample/demo reports (no ES required).
    These showcase the platform's report capabilities with realistic static data.
    """
    samples = []
    for rtype in ["threat_intelligence", "executive_briefing", "ioc_analysis",
                   "incident_summary", "dark_web_exposure"]:
        s = _build_sample(rtype)
        samples.append(ReportSummary(
            id=s["id"], title=s["title"], type=s["type"], status=s["status"],
            severity=s["severity"], generated_at=s["generated_at"],
            date_range=s["date_range"], description=s.get("description", ""),
            stats=s["stats"], pages=s["pages"], is_sample=True,
        ))
    return {"reports": samples, "total": len(samples)}


@router.get("/samples/{report_type}/html")
async def view_sample_html(report_type: str):
    """View a sample report as rendered HTML."""
    rtype = _resolve_type(report_type)
    if rtype not in VALID_TYPES:
        raise HTTPException(status_code=400, detail=f"Invalid type. Use: {', '.join(VALID_TYPES)}")
    s = _build_sample(rtype)
    return Response(content=s["html"], media_type="text/html")


@router.get("/samples/{report_type}/download")
async def download_sample(report_type: str):
    """Download a sample report as an HTML file."""
    rtype = _resolve_type(report_type)
    if rtype not in VALID_TYPES:
        raise HTTPException(status_code=400, detail=f"Invalid type. Use: {', '.join(VALID_TYPES)}")
    s = _build_sample(rtype)
    filename = f"JichoSec_Sample_{rtype.replace('_', '-')}.html"
    return Response(
        content=s["html"], media_type="text/html",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/generate", response_model=ReportDetail)
async def generate_report(
    req: GenerateReportRequest,
    current_user: User = Depends(get_current_user),
):
    """
    Generate a new threat report from real Elasticsearch data.
    Stored in ES for later retrieval and download.
    """
    report_type = _resolve_type(req.report_type)

    try:
        result = await build_report(
            report_type=report_type,
            title=req.title,
            include_iocs=req.include_iocs,
            include_darkweb=req.include_darkweb,
            include_credentials=req.include_credentials,
            date_range=req.time_range,
            custom_prompt=req.custom_prompt,
            focus_area=req.custom_prompt,
        )
    except Exception as e:
        logger.error(f"Report generation error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Report generation failed: {e}")

    if "error" in result:
        raise HTTPException(status_code=503, detail=result["error"])

    report_id = str(uuid.uuid4())
    doc = {
        "id": report_id,
        "title": result["title"],
        "type": result["type"],
        "status": result["status"],
        "severity": result["severity"],
        "generated_at": result["generated_at"],
        "date_range": result.get("date_range", req.time_range),
        "description": result.get("description", ""),
        "stats": result.get("stats", {}),
        "pages": result.get("pages", 1),
        "html": result["html"],
        "is_sample": False,
        "owner_user_id": current_user.id,
    }

    stored = await _store_report(doc)
    if not stored:
        logger.warning("Report generated but could not be persisted to ES")

    return ReportDetail(**doc)


@router.get("", response_model=ReportListResponse)
async def list_reports(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    report_type: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    current_user: User = Depends(get_current_user),
):
    """List generated reports with pagination and optional filtering."""
    await _ensure_index()
    if not es_service.client:
        return ReportListResponse(reports=[], total=0, page=page, page_size=page_size)

    filters = []
    if report_type:
        mapped = _resolve_type(report_type)
        filters.append({"term": {"type": mapped}})
    if severity:
        filters.append({"term": {"severity": severity}})
    if not current_user.is_admin:
        filters.append({"term": {"owner_user_id": current_user.id}})

    body = {
        "query": {"bool": {"filter": filters}} if filters else {"match_all": {}},
        "sort": [{"generated_at": {"order": "desc"}}],
        "from": (page - 1) * page_size,
        "size": page_size,
        "_source": ["id", "title", "type", "status", "severity", "generated_at",
                     "date_range", "description", "stats", "pages", "is_sample"],
    }

    try:
        resp = await es_service.client.search(index=REPORTS_INDEX, body=body)
        reports = [ReportSummary(**hit["_source"]) for hit in resp["hits"]["hits"]]
        total = resp["hits"]["total"]["value"]
    except Exception as e:
        logger.warning(f"List reports error: {e}")
        reports = []
        total = 0

    return ReportListResponse(reports=reports, total=total, page=page, page_size=page_size)


# =============================================================================
# DYNAMIC /{report_id} ROUTES  (must come AFTER all fixed-path routes)
# =============================================================================

@router.get("/{report_id}", response_model=ReportDetail)
async def get_report(
    report_id: str,
    current_user: User = Depends(get_current_user),
):
    """Get a specific report by ID (includes HTML content)."""
    sample = _get_sample_if_exists(report_id)
    if sample:
        return ReportDetail(**sample)

    await _ensure_index()
    if not es_service.client:
        raise HTTPException(status_code=503, detail="Elasticsearch unavailable")
    try:
        resp = await es_service.client.get(index=REPORTS_INDEX, id=report_id)
        doc = resp["_source"]
        if not current_user.is_admin and doc.get("owner_user_id") != current_user.id:
            raise HTTPException(status_code=404, detail=f"Report {report_id} not found")
        return ReportDetail(**doc)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=404, detail=f"Report {report_id} not found")


@router.get("/{report_id}/html")
async def view_report_html(
    report_id: str,
    current_user: User = Depends(get_current_user),
):
    """Return the report as a rendered HTML page."""
    sample = _get_sample_if_exists(report_id)
    if sample:
        return Response(content=sample["html"], media_type="text/html")

    await _ensure_index()
    if not es_service.client:
        raise HTTPException(status_code=503, detail="Elasticsearch unavailable")
    try:
        resp = await es_service.client.get(index=REPORTS_INDEX, id=report_id)
        doc = resp["_source"]
        if not current_user.is_admin and doc.get("owner_user_id") != current_user.id:
            raise HTTPException(status_code=404, detail=f"Report {report_id} not found")
        html = doc.get("html", "")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=404, detail=f"Report {report_id} not found")
    return Response(content=html, media_type="text/html")


@router.get("/{report_id}/download")
async def download_report(
    report_id: str,
    current_user: User = Depends(get_current_user),
):
    """Download a report file (always HTML)."""
    sample = _get_sample_if_exists(report_id)
    if sample:
        fname = f"{sample['title'].replace(' ', '_')}_{report_id[:12]}.html"
        return Response(
            content=sample["html"], media_type="text/html",
            headers={"Content-Disposition": f'attachment; filename="{fname}"'},
        )

    await _ensure_index()
    if not es_service.client:
        raise HTTPException(status_code=503, detail="Elasticsearch unavailable")
    try:
        resp = await es_service.client.get(index=REPORTS_INDEX, id=report_id)
        doc = resp["_source"]
        if not current_user.is_admin and doc.get("owner_user_id") != current_user.id:
            raise HTTPException(status_code=404, detail=f"Report {report_id} not found")
        html = doc.get("html", "")
        title = doc.get("title", "report").replace(" ", "_")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=404, detail=f"Report {report_id} not found")
    filename = f"{title}_{report_id[:8]}.html"
    return Response(
        content=html, media_type="text/html",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.delete("/{report_id}", response_model=DeleteResponse)
async def delete_report(
    report_id: str,
    current_user: User = Depends(get_current_user),
):
    """Delete a report by ID."""
    if _get_sample_if_exists(report_id):
        raise HTTPException(status_code=400, detail="Cannot delete sample reports")

    await _ensure_index()
    if not es_service.client:
        raise HTTPException(status_code=503, detail="Elasticsearch unavailable")
    try:
        resp = await es_service.client.get(index=REPORTS_INDEX, id=report_id)
        doc = resp["_source"]
        if not current_user.is_admin and doc.get("owner_user_id") != current_user.id:
            raise HTTPException(status_code=404, detail=f"Report {report_id} not found")
        await es_service.client.delete(index=REPORTS_INDEX, id=report_id, refresh="wait_for")
        return DeleteResponse(success=True, message=f"Report {report_id} deleted")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=404, detail=f"Report {report_id} not found")
