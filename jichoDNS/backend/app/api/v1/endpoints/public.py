"""
Public endpoints — minimal data exposed for the landing page threat map.

Only stats, live feed (capped), and region summaries. No full IOC listing,
no individual lookups, no feed health details.
"""

from datetime import datetime, timedelta

from fastapi import APIRouter, Query

from app.services.elasticsearch import es_service

router = APIRouter()


@router.get("/indicators/stats")
async def public_indicator_stats():
    """Aggregated threat statistics — no individual IOC data."""
    try:
        await es_service.connect()
        if not es_service.client:
            return {}
        count = await es_service.client.count(index="iocs")
        total = count.get("count", 0)
        agg = await es_service.client.search(
            index="iocs",
            body={
                "size": 0,
                "aggs": {
                    "by_threat_type": {"terms": {"field": "threat_type.keyword", "size": 10}},
                    "by_source": {"terms": {"field": "source.keyword", "size": 20}},
                    "by_country": {"terms": {"field": "country_code.keyword", "size": 60}},
                },
            },
        )
        aggs = agg.get("aggregations", {})
        return {
            "total": total,
            "by_threat_type": {b["key"]: b["doc_count"] for b in aggs.get("by_threat_type", {}).get("buckets", [])},
            "by_source": {b["key"]: b["doc_count"] for b in aggs.get("by_source", {}).get("buckets", [])},
            "by_country": {b["key"]: b["doc_count"] for b in aggs.get("by_country", {}).get("buckets", [])},
        }
    except Exception:
        return {}


@router.get("/indicators/live/feed")
async def public_live_feed(
    limit: int = Query(100, ge=1, le=50000, description="Number of recent indicators"),
    since_minutes: int = Query(10080, ge=1, le=10080),
):
    """
    Recent indicators for threat map animation.

    Returns indicators with geo data for map visualization.
    """
    since_time = datetime.utcnow() - timedelta(minutes=since_minutes)
    result = await es_service.get_recent_indicators(limit=limit, since=since_time)
    return {"count": len(result), "since": since_time.isoformat(), "indicators": result}


@router.get("/regions/countries")
async def public_country_scores(min_risk: float = Query(0, ge=0, le=100)):
    """Country-level risk scores for the map choropleth."""
    try:
        scores = await es_service.get_region_scores(region_type="country", min_risk=min_risk)
        return {"items": scores, "timestamp": datetime.utcnow().isoformat()}
    except Exception:
        return {"items": [], "timestamp": datetime.utcnow().isoformat()}


@router.get("/regions/map")
async def public_map_data():
    """GeoJSON data for the threat map."""
    try:
        scores = await es_service.get_region_scores(region_type="country", min_risk=0)
        features = []
        for s in scores:
            features.append({
                "type": "Feature",
                "properties": {
                    "region_id": s.get("region_id"),
                    "region_name": s.get("region_name"),
                    "overall_risk": s.get("overall_risk", 0),
                    "indicator_count": s.get("indicator_count", 0),
                },
                "geometry": None,
            })
        return {"type": "FeatureCollection", "features": features}
    except Exception:
        return {"type": "FeatureCollection", "features": []}
