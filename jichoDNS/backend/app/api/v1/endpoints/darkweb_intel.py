"""
Dark Web Intelligence endpoints.

Queries dark web-specific data: MISP threat intel, C2 infrastructure,
phishing pages, credential leaks, dark web crawl results.

NOT for generic malware/URLhaus data — that goes on the dashboard.
"""

import logging
from datetime import datetime, timezone
from typing import Optional, List

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.database import get_db
from app.core.ownership import get_owned_domains, redact_credential
from app.models.user import User
from app.models.intel import OrgWatchlist
from app.services.elasticsearch import es_service

logger = logging.getLogger(__name__)

router = APIRouter()

# Sources and types considered "dark web intelligence"
# MISP = curated threat intel from AfISAC analysts
# phishtank/openphish = phishing infrastructure (often dark web hosted)
# C2 indicators = command & control servers
DARKWEB_SOURCES = ["misp", "phishtank", "openphish", "sslbl", "feodotracker"]
DARKWEB_TYPES = ["c2", "phishing", "botnet"]


def _darkweb_filter():
    """ES query filter for dark web-relevant data."""
    return {
        "bool": {
            "should": [
                # MISP data = curated dark web intel
                {"term": {"source": "misp"}},
                # C2 servers from any source
                {"term": {"threat_type": "c2"}},
                # Phishing from specialized feeds
                {
                    "bool": {
                        "must": [
                            {"term": {"threat_type": "phishing"}},
                            {"terms": {"source": ["phishtank", "openphish"]}},
                        ]
                    }
                },
                # Botnet infrastructure
                {"term": {"threat_type": "botnet"}},
                # SSL blocklist = malicious certificates
                {"term": {"source": "sslbl"}},
                {"term": {"source": "feodotracker"}},
            ],
            "minimum_should_match": 1,
            "filter": [{"term": {"active": True}}],
        }
    }


@router.get("/feed")
async def darkweb_feed(
    page: int = Query(1, ge=1),
    page_size: int = Query(30, ge=5, le=100),
    threat_type: Optional[str] = Query(None, description="Filter: c2, phishing, botnet"),
    source: Optional[str] = Query(None, description="Filter: misp, phishtank, openphish, sslbl, feodotracker"),
    search: Optional[str] = Query(None, min_length=2, description="Search indicators"),
    current_user: User = Depends(get_current_user),
):
    """
    Dark web threat feed — MISP intel, C2 infrastructure, phishing,
    credential theft. Paginated and searchable.
    """
    await es_service.connect()
    if not es_service.client:
        return {"items": [], "total": 0, "page": page, "page_size": page_size}

    # Start with dark web filter
    query = _darkweb_filter()

    # Additional filters narrow within dark web data
    extra_filters = []
    if threat_type:
        extra_filters.append({"term": {"threat_type": threat_type}})
    if source:
        extra_filters.append({"term": {"source": source}})
    if search:
        extra_filters.append({
            "multi_match": {
                "query": search,
                "fields": ["indicator", "tags", "ip_address"],
                "type": "phrase_prefix",
            }
        })

    if extra_filters:
        query = {"bool": {"must": [query] + extra_filters}}

    try:
        result = await es_service.client.search(
            index="iocs",
            body={
                "query": query,
                "sort": [{"created_at": {"order": "desc"}}],
                "from": (page - 1) * page_size,
                "size": page_size,
                "_source": [
                    "indicator", "indicator_type", "threat_type", "source",
                    "risk_score", "country_code", "ip_address", "tags",
                    "misp_event_id", "misp_category", "misp_comment",
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
    """Dark web monitoring statistics."""
    await es_service.connect()
    if not es_service.client:
        return {}

    try:
        result = await es_service.client.search(
            index="iocs",
            body={
                "size": 0,
                "query": _darkweb_filter(),
                "aggs": {
                    "by_type": {"terms": {"field": "threat_type", "size": 10}},
                    "by_source": {"terms": {"field": "source", "size": 20}},
                    "by_country": {"terms": {"field": "country_code", "size": 20}},
                    "misp_count": {"filter": {"term": {"source": "misp"}}},
                    "recent_24h": {"filter": {"range": {"created_at": {"gte": "now-24h"}}}},
                },
            },
        )
        aggs = result.get("aggregations", {})
        total = result["hits"]["total"]["value"]

        return {
            "total_threats": total,
            "misp_intel": aggs.get("misp_count", {}).get("doc_count", 0),
            "new_last_24h": aggs.get("recent_24h", {}).get("doc_count", 0),
            "by_type": {b["key"]: b["doc_count"] for b in aggs.get("by_type", {}).get("buckets", [])},
            "by_source": {b["key"]: b["doc_count"] for b in aggs.get("by_source", {}).get("buckets", [])},
            "top_countries": {b["key"]: b["doc_count"] for b in aggs.get("by_country", {}).get("buckets", [])[:10]},
        }
    except Exception as e:
        logger.error(f"Dark web stats error: {e}")
        return {}


@router.get("/search")
async def darkweb_search(
    q: str = Query(..., min_length=2, max_length=500, description="Search dark web data"),
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Search within dark web intelligence only.

    Searches MISP data, C2 infrastructure, phishing pages, and credential leaks.
    """
    await es_service.connect()
    if not es_service.client:
        return {"items": [], "total": 0, "query": q}

    indices_to_search = ["iocs"]
    # Also search darkweb_posts and credential_exposures if they exist
    for idx in ["darkweb_posts", "credential_exposures"]:
        try:
            if await es_service.client.indices.exists(index=idx):
                indices_to_search.append(idx)
        except Exception:
            pass

    all_items = []

    # Search dark web IOCs
    try:
        result = await es_service.client.search(
            index="iocs",
            body={
                "query": {
                    "bool": {
                        "must": [
                            _darkweb_filter(),
                            {
                                "multi_match": {
                                    "query": q,
                                    "fields": ["indicator^3", "tags", "ip_address", "misp_comment"],
                                    "type": "best_fields",
                                    "fuzziness": "AUTO",
                                }
                            },
                        ]
                    }
                },
                "sort": [{"_score": "desc"}],
                "size": limit,
                "_source": [
                    "indicator", "indicator_type", "threat_type", "source",
                    "risk_score", "country_code", "ip_address", "tags",
                    "misp_event_id", "misp_category", "created_at",
                ],
            },
        )
        for h in result["hits"]["hits"]:
            item = h["_source"]
            item["_score"] = h["_score"]
            item["_result_type"] = "ioc"
            all_items.append(item)
    except Exception as e:
        logger.warning(f"Dark web IOC search error: {e}")

    # Search darkweb_posts if index exists
    if "darkweb_posts" in indices_to_search:
        try:
            result = await es_service.client.search(
                index="darkweb_posts",
                body={
                    "query": {
                        "multi_match": {
                            "query": q,
                            "fields": ["title^2", "body_text", "url", "brand_matches"],
                        }
                    },
                    "size": limit // 2,
                },
            )
            for h in result["hits"]["hits"]:
                item = h["_source"]
                item["_score"] = h["_score"]
                item["_result_type"] = "darkweb_post"
                all_items.append(item)
        except Exception:
            pass

    # Search credential_exposures if index exists — scoped to owned domains
    if "credential_exposures" in indices_to_search:
        cred_filter = []
        cred_allowed = True
        if not current_user.is_admin:
            owned = await get_owned_domains(current_user, db)
            if not owned:
                cred_allowed = False
            else:
                cred_filter = [{"terms": {"domain": sorted(owned)}}]
        if cred_allowed:
            try:
                q_lower = q.lower()
                result = await es_service.client.search(
                    index="credential_exposures",
                    body={
                        "query": {
                            "bool": {
                                "should": [
                                    {"wildcard": {"email": {"value": f"*{q_lower}*"}}},
                                    {"wildcard": {"domain": {"value": f"*{q_lower}*"}}},
                                    {"wildcard": {"source_name": {"value": f"*{q_lower}*"}}},
                                    {"wildcard": {"tags": {"value": f"*{q_lower}*"}}},
                                ],
                                "minimum_should_match": 1,
                                "filter": cred_filter,
                            }
                        },
                        "size": limit // 2,
                        "_source": {"excludes": ["password", "password_hash"]},
                    },
                )
                for h in result["hits"]["hits"]:
                    item = redact_credential(h["_source"])
                    item["_score"] = h["_score"]
                    item["_result_type"] = "credential"
                    all_items.append(item)
            except Exception:
                pass

    # Sort all by score
    all_items.sort(key=lambda x: x.get("_score", 0), reverse=True)

    return {
        "items": all_items[:limit],
        "total": len(all_items),
        "query": q,
    }


@router.get("/watchlist/matches")
async def watchlist_matches(
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Check dark web data against user's watchlist terms.
    """
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

    await es_service.connect()
    if not es_service.client:
        return {"matches": [], "total": 0, "watchlist_terms": all_terms}

    # Match watchlist terms against GENUINE dark web data — Tor/.onion crawl
    # posts and breach credential exposures — NOT the clearnet IOC feed. (The
    # clearnet C2/phishing/MISP indicators live on the dashboard + search.)
    terms = [t for t in all_terms[:20] if t]
    matches: List[dict] = []

    # 1) Dark web crawl posts.
    try:
        if await es_service.client.indices.exists(index="darkweb_posts"):
            should = []
            for term in terms:
                for field in ("title", "body_text", "domains_found", "emails_found", "onion_links"):
                    should.append({"match_phrase": {field: term}})
            res = await es_service.client.search(
                index="darkweb_posts",
                body={
                    "query": {"bool": {"should": should, "minimum_should_match": 1}},
                    "sort": [{"discovered_at": {"order": "desc"}}],
                    "size": limit,
                },
            )
            for hit in res["hits"]["hits"]:
                s = hit["_source"]
                blob = " ".join(
                    str(s.get(f, "")) for f in ("title", "body_text", "url", "domains_found", "emails_found")
                ).lower()
                matches.append({
                    "indicator": s.get("title") or s.get("url") or "(dark web post)",
                    "threat_type": "darkweb_post",
                    "source": s.get("source") or "dark web",
                    "matched_terms": [t for t in all_terms if t.lower() in blob],
                    "created_at": s.get("discovered_at"),
                })
    except Exception as e:
        logger.warning(f"Dark web post watchlist match error: {e}")

    # 2) Breach credential exposures (scoped to the caller's owned domains).
    try:
        exists = await es_service.client.indices.exists(index="credential_exposures")
        allowed = None
        if exists and not current_user.is_admin:
            allowed = await get_owned_domains(current_user, db)
        if exists and (current_user.is_admin or allowed):
            must = []
            if allowed is not None:
                must.append({"terms": {"domain": sorted(allowed)}})
            res = await es_service.client.search(
                index="credential_exposures",
                body={
                    "query": {
                        "bool": {
                            "must": must,
                            "should": [{"terms": {"domain": [t.lower() for t in terms]}}],
                            "minimum_should_match": 1,
                        }
                    },
                    "sort": [{"discovered_at": {"order": "desc"}}],
                    "size": limit,
                },
            )
            for hit in res["hits"]["hits"]:
                s = redact_credential(hit["_source"])
                blob = (str(s.get("email", "")) + " " + str(s.get("domain", ""))).lower()
                matches.append({
                    "indicator": s.get("email") or s.get("domain") or "(credential)",
                    "threat_type": "credential_leak",
                    "source": s.get("source_name") or s.get("source") or "breach",
                    "matched_terms": [t for t in all_terms if t.lower() in blob],
                    "created_at": s.get("discovered_at"),
                })
    except Exception as e:
        logger.warning(f"Credential watchlist match error: {e}")

    return {
        "matches": matches[:limit],
        "total": len(matches),
        "watchlist_terms": all_terms,
    }


@router.get("/crawl-results")
async def get_crawl_results(
    page: int = Query(1, ge=1),
    page_size: int = Query(30, ge=5, le=100),
    search: Optional[str] = Query(None, min_length=2),
    severity: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
):
    """
    Dark web crawl results — actual pages from .onion sites, paste sites,
    dark web search engines. NOT regular IOC feeds.
    """
    await es_service.connect()
    if not es_service.client:
        return {"items": [], "total": 0, "page": page}

    try:
        exists = await es_service.client.indices.exists(index="darkweb_posts")
        if not exists:
            return {"items": [], "total": 0, "page": page, "message": "No crawl data yet. Triggering first crawl."}

        must: list = []
        if search:
            must.append({
                "multi_match": {
                    "query": search,
                    "fields": ["title^3", "body_text", "url", "emails_found", "domains_found"],
                }
            })
        if severity:
            must.append({"term": {"severity": severity}})

        query = {"bool": {"must": must}} if must else {"match_all": {}}

        result = await es_service.client.search(
            index="darkweb_posts",
            body={
                "query": query,
                "sort": [{"discovered_at": {"order": "desc"}}],
                "from": (page - 1) * page_size,
                "size": page_size,
            },
        )
        items = [h["_source"] for h in result["hits"]["hits"]]
        total = result["hits"]["total"]["value"]
        return {"items": items, "total": total, "page": page, "pages": (total + page_size - 1) // page_size}
    except Exception as e:
        logger.error(f"Crawl results error: {e}")
        return {"items": [], "total": 0, "page": page}


@router.post("/crawl")
async def trigger_crawl(
    current_user: User = Depends(get_current_user),
):
    """Trigger on-demand dark web crawl using watchlist terms."""
    from app.worker import crawl_darkweb

    # Get user's watchlist terms
    terms = None
    try:
        from app.core.database import async_session_maker
        async with async_session_maker() as db:
            result = await db.execute(
                select(OrgWatchlist).where(
                    OrgWatchlist.user_id == current_user.id,
                    OrgWatchlist.is_active == True,
                )
            )
            wls = result.scalars().all()
            terms = []
            for wl in wls:
                terms.extend(wl.brand_terms or [])
                terms.extend(wl.keywords or [])
            terms = terms[:10] if terms else None
    except Exception:
        pass

    task = crawl_darkweb.delay(terms)
    return {"task_id": task.id, "status": "started", "queries": terms or ["default"]}
