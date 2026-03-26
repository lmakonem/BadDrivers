"""Indicator endpoints - threat intelligence data."""

from typing import List, Optional
from fastapi import APIRouter, Query, HTTPException
from pydantic import BaseModel
from datetime import datetime

from app.services.elasticsearch import es_service

router = APIRouter()


class IndicatorResponse(BaseModel):
    indicator: str
    indicator_type: str  # domain, ip, url
    threat_type: str  # c2, phishing, exfil, unknown
    source: str
    confidence: float = 0.5
    risk_score: float = 0.0
    tags: List[str] = []
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    country_code: Optional[str] = None
    asn: Optional[int] = None
    active: bool = True


class IndicatorListResponse(BaseModel):
    items: List[IndicatorResponse]
    total: int
    page: int
    page_size: int


@router.get("", response_model=IndicatorListResponse)
async def list_indicators(
    query: Optional[str] = Query(None, description="Search query"),
    threat_type: Optional[str] = Query(None, description="Filter by type: c2, phishing, exfil"),
    indicator_type: Optional[str] = Query(None, description="Filter by indicator type: domain, ip, url"),
    source: Optional[str] = Query(None, description="Filter by source"),
    country: Optional[str] = Query(None, description="Filter by country code (ISO 2-letter)"),
    min_confidence: float = Query(0.0, ge=0, le=1, description="Minimum confidence score"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
):
    """
    List threat indicators with filtering and pagination.
    
    Returns domains, IPs, and URLs identified as malicious from various threat feeds.
    """
    offset = (page - 1) * page_size
    
    result = await es_service.search_indicators(
        query=query or "",
        threat_type=threat_type,
        indicator_type=indicator_type,
        country_code=country,
        min_confidence=min_confidence,
        limit=page_size,
        offset=offset,
    )
    
    items = [IndicatorResponse(**hit) for hit in result["hits"]]
    
    return IndicatorListResponse(
        items=items,
        total=result["total"],
        page=page,
        page_size=page_size,
    )


@router.get("/stats")
async def get_indicator_stats():
    """Get statistics about stored indicators."""
    stats = await es_service.get_stats()
    return stats


@router.get("/lookup/{value}")
async def lookup_indicator(value: str):
    """
    Look up an indicator by its value (domain, IP, or URL).
    
    Returns all matching indicators and their threat classification.
    """
    result = await es_service.search_indicators(
        query=value,
        limit=10,
    )
    
    return {
        "value": value,
        "found": result["total"] > 0,
        "total": result["total"],
        "indicators": result["hits"],
    }


@router.get("/live/feed")
async def get_live_feed(
    limit: int = Query(100, ge=1, le=50000, description="Number of recent indicators to return"),
    since_minutes: int = Query(60, ge=1, le=10080, description="Get indicators from last N minutes (max 7 days)"),
):
    """
    Get recent threat indicators for live threat map visualization.
    
    Returns the most recent indicators with geographic data,
    sorted by last_seen timestamp descending.
    
    For the initial pool load, request all indicators (up to 50,000).
    For periodic refresh, use smaller limits (100-500).
    """
    from datetime import datetime, timedelta
    
    # Calculate time range
    since_time = datetime.utcnow() - timedelta(minutes=since_minutes)
    
    result = await es_service.get_recent_indicators(
        limit=limit,
        since=since_time,
    )
    
    return {
        "count": len(result),
        "since": since_time.isoformat(),
        "indicators": result,
    }


@router.get("/health/feeds")
async def get_feed_health():
    """
    Get health status of all threat feed importers.
    Shows last run time, IOC count, and whether feed is stale vs SLA.
    """
    from app.services.feed_monitor import feed_monitor
    feed_monitor.client = es_service.client
    health = await feed_monitor.get_all_health()
    stale = [h for h in health if h["status"] == "stale"]
    return {
        "feeds": health,
        "total": len(health),
        "healthy": len(health) - len(stale),
        "stale": len(stale),
        "stale_feeds": [h["feed"] for h in stale],
    }


@router.get("/{indicator_id}")
async def get_indicator(indicator_id: str):
    """Get detailed information about a specific indicator."""
    # indicator_id is in format "source:indicator"
    parts = indicator_id.split(":", 1)
    if len(parts) == 2:
        source, indicator = parts
        doc = await es_service.get_indicator(indicator, source)
        if doc:
            return doc
    
    raise HTTPException(status_code=404, detail="Indicator not found")
