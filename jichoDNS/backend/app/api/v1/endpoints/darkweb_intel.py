"""
Dark Web Intelligence endpoints.

Aggregates dark web-relevant IOCs from all sources (threat feeds, MISP,
TorBot crawls) into a unified view. Supports searching, filtering, and
watchlist-based alerting.
"""

import logging
from datetime import datetime, timezone
from typing import Optional, List

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.user import User
from app.models.intel import OrgWatchlist
from app.services.elasticsearch import es_service

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/feed")
async def darkweb_feed(
    page: int = Query(1, ge=1),
    page_size: int = Query(30, ge=5, le=100),
    threat_type: Optional[str] = Query(None, description="Filter: phishing, c2, malware, botnet"),
    source: Optional[str] = Query(None, description="Filter by source: urlhaus, phishtank, misp, sslbl"),
    search: Optional[str] = Query(None, min_length=2, description="Search within indicators"),
    current_user: User = Depends(get_current_user),
):
    """
    Paginated dark web threat feed.

    Returns IOCs relevant to dark web monitoring: phishing, C2, malware
    distribution, and credential theft infrastructure.
    """
    await es_service.connect()
    if not es_service.client:
        return {"items": [], "total": 0, "page": page, "page_size": page_size}

    must = [{"term": {"active": True}}]

    # Default to dark-web-relevant threat types
    if threat_type:
        must.append({"term": {"threat_type.keyword": threat_type}})
    else:
        must.append({
            "terms": {"threat_type.keyword": ["phishing", "c2", "malware", "botnet"]}
        })

    if source:
        must.append({"term": {"source.keyword": source}})

    if search:
        must.append({
            "multi_match": {
                "query": search,
                "fields": ["indicator", "tags"],
                "type": "phrase_prefix",
            }
        })

    try:
        result = await es_service.client.search(
            index="iocs",
            body={
                "query": {"bool": {"must": must}},
                "sort": [{"created_at": {"order": "desc"}}],
                "from": (page - 1) * page_size,
                "size": page_size,
                "_source": [
                    "indicator", "indicator_type", "threat_type", "source",
                    "risk_score", "country_code", "ip_address", "tags",
                    "first_seen", "last_seen", "created_at",
                ],
            },
        )

        items = [h["_source"] for h in result["hits"]["hits"]]
        total = result["hits"]["total"]["value"]

        return {
            "items": items,
            "total": total,
            "page": page,
            "page_size": page_size,
            "pages": (total + page_size - 1) // page_size,
        }
    except Exception as e:
        logger.error(f"Dark web feed error: {e}")
        return {"items": [], "total": 0, "page": page, "page_size": page_size}


@router.get("/stats")
async def darkweb_stats(
    current_user: User = Depends(get_current_user),
):
    """Dark web monitoring statistics from real data."""
    await es_service.connect()
    if not es_service.client:
        return {}

    try:
        result = await es_service.client.search(
            index="iocs",
            body={
                "size": 0,
                "query": {
                    "terms": {"threat_type.keyword": ["phishing", "c2", "malware", "botnet"]}
                },
                "aggs": {
                    "by_type": {"terms": {"field": "threat_type.keyword", "size": 10}},
                    "by_source": {"terms": {"field": "source.keyword", "size": 20}},
                    "by_country": {"terms": {"field": "country_code.keyword", "size": 20}},
                    "recent_24h": {
                        "filter": {"range": {"created_at": {"gte": "now-24h"}}},
                    },
                },
            },
        )
        aggs = result.get("aggregations", {})
        total = result["hits"]["total"]["value"]

        return {
            "total_threats": total,
            "new_last_24h": aggs.get("recent_24h", {}).get("doc_count", 0),
            "by_type": {b["key"]: b["doc_count"] for b in aggs.get("by_type", {}).get("buckets", [])},
            "by_source": {b["key"]: b["doc_count"] for b in aggs.get("by_source", {}).get("buckets", [])},
            "top_countries": {b["key"]: b["doc_count"] for b in aggs.get("by_country", {}).get("buckets", [])[:10]},
        }
    except Exception as e:
        logger.error(f"Dark web stats error: {e}")
        return {}


@router.get("/watchlist/matches")
async def watchlist_matches(
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Check IOCs against the user's watchlist terms.

    Returns indicators that match any brand term, domain, or keyword
    from the user's watchlists.
    """
    # Get user's watchlist terms
    result = await db.execute(
        select(OrgWatchlist).where(
            OrgWatchlist.user_id == current_user.id,
            OrgWatchlist.is_active == True,
        )
    )
    watchlists = result.scalars().all()

    all_terms: List[str] = []
    for wl in watchlists:
        all_terms.extend(wl.domains or [])
        all_terms.extend(wl.brand_terms or [])
        all_terms.extend(wl.keywords or [])

    if not all_terms:
        return {
            "matches": [],
            "total": 0,
            "watchlist_terms": [],
            "message": "No watchlist terms configured. Add keywords to monitor.",
        }

    # Search for matches
    await es_service.connect()
    if not es_service.client:
        return {"matches": [], "total": 0, "watchlist_terms": all_terms}

    # Build a should query matching any term
    should_clauses = []
    for term in all_terms[:20]:  # Cap at 20 terms to avoid huge queries
        should_clauses.append({"match_phrase": {"indicator": term}})
        should_clauses.append({"match_phrase": {"tags": term}})

    try:
        es_result = await es_service.client.search(
            index="iocs",
            body={
                "query": {
                    "bool": {
                        "should": should_clauses,
                        "minimum_should_match": 1,
                        "filter": [{"term": {"active": True}}],
                    }
                },
                "sort": [{"created_at": {"order": "desc"}}],
                "size": limit,
                "_source": [
                    "indicator", "indicator_type", "threat_type", "source",
                    "risk_score", "country_code", "tags", "created_at",
                ],
            },
        )

        matches = []
        for hit in es_result["hits"]["hits"]:
            item = hit["_source"]
            # Determine which terms matched
            matched_terms = [
                t for t in all_terms
                if t.lower() in (item.get("indicator", "") + " " + " ".join(item.get("tags", []))).lower()
            ]
            item["matched_terms"] = matched_terms
            item["_score"] = hit["_score"]
            matches.append(item)

        return {
            "matches": matches,
            "total": es_result["hits"]["total"]["value"],
            "watchlist_terms": all_terms,
        }
    except Exception as e:
        logger.error(f"Watchlist match error: {e}")
        return {"matches": [], "total": 0, "watchlist_terms": all_terms}
