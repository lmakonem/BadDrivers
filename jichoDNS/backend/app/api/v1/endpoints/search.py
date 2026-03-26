"""
Universal search endpoint — searches across all intelligence sources.

Queries IOCs (Elasticsearch), dark web posts, credential exposures,
OSINT results, and optionally MISP in a single API call.
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Query
from app.api.deps import get_current_user
from app.models.user import User
from app.services.elasticsearch import es_service

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/search")
async def universal_search(
    q: str = Query(..., min_length=2, max_length=500, description="Search query (email, IP, domain, hash, keyword)"),
    source: Optional[str] = Query(None, description="Filter by source: iocs, darkweb, credentials, osint, all"),
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_user),
):
    """
    Search across all intelligence sources.

    Returns results grouped by source with relevance scoring.
    Searches: IOCs, dark web posts, credential exposures, OSINT results.
    """
    await es_service.connect()
    if not es_service.client:
        return {"query": q, "total": 0, "results": {}}

    results = {}
    total = 0

    search_sources = {
        "iocs": {
            "index": "iocs",
            "fields": ["indicator^3", "tags", "source", "ip_address"],
        },
        "darkweb": {
            "index": "darkweb_posts",
            "fields": ["title^2", "body_text", "url", "emails_found", "brand_matches"],
        },
        "credentials": {
            "index": "credential_exposures",
            "fields": ["email^3", "domain^2", "username", "source_name"],
            "exclude_fields": ["password_hash"],
        },
        "osint": {
            "index": "osint_results",
            "fields": ["data^2", "scan_target", "event_type"],
        },
    }

    if source and source != "all":
        search_sources = {k: v for k, v in search_sources.items() if k == source}

    per_source_limit = max(5, limit // len(search_sources)) if search_sources else limit

    for src_name, src_config in search_sources.items():
        try:
            # Credential searches need wildcard on keyword fields
            if src_name == "credentials":
                q_lower = q.lower()
                query = {
                    "bool": {
                        "should": [
                            {"wildcard": {"email": {"value": f"*{q_lower}*"}}},
                            {"wildcard": {"domain": {"value": f"*{q_lower}*"}}},
                            {"wildcard": {"username": {"value": f"*{q_lower}*"}}},
                            {"wildcard": {"source_name": {"value": f"*{q_lower}*"}}},
                        ],
                        "minimum_should_match": 1,
                    }
                }
            else:
                query = {
                    "multi_match": {
                        "query": q,
                        "fields": src_config["fields"],
                        "type": "best_fields",
                        "fuzziness": "AUTO",
                    }
                }

            body = {
                "query": query,
                "sort": [{"_score": "desc"}],
                "size": per_source_limit,
            }

            # Exclude sensitive fields
            if "exclude_fields" in src_config:
                body["_source"] = {"excludes": src_config["exclude_fields"]}

            result = await es_service.client.search(
                index=src_config["index"],
                body=body,
            )

            hits = []
            for h in result["hits"]["hits"]:
                hit = {**h["_source"], "_id": h["_id"], "_score": h["_score"]}
                hit["_source_type"] = src_name
                hits.append(hit)

            if hits:
                results[src_name] = {
                    "total": result["hits"]["total"]["value"],
                    "items": hits,
                }
                total += result["hits"]["total"]["value"]

        except Exception as e:
            if "index_not_found" not in str(e):
                logger.warning(f"Search error in {src_name}: {e}")

    return {
        "query": q,
        "total": total,
        "sources_searched": list(search_sources.keys()),
        "results": results,
    }


@router.get("/lookup/{value}")
async def lookup_ioc(
    value: str,
    current_user: User = Depends(get_current_user),
):
    """
    Deep lookup of a single IOC across all sources.

    Returns enriched information including:
    - All ES matches for this indicator
    - Credential exposures for this email/domain
    - Dark web mentions
    - MISP correlations (if available)
    """
    await es_service.connect()
    if not es_service.client:
        return {"value": value, "found": False}

    result = {
        "value": value,
        "found": False,
        "ioc_matches": [],
        "credential_exposures": [],
        "darkweb_mentions": [],
        "misp_correlations": None,
    }

    # Search in IOCs
    try:
        ioc_result = await es_service.client.search(
            index="iocs",
            body={
                "query": {"term": {"indicator": value}},
                "size": 10,
            },
        )
        result["ioc_matches"] = [h["_source"] for h in ioc_result["hits"]["hits"]]
        if result["ioc_matches"]:
            result["found"] = True
    except Exception:
        pass

    # Search in credential exposures
    try:
        cred_result = await es_service.client.search(
            index="credential_exposures",
            body={
                "query": {
                    "bool": {
                        "should": [
                            {"term": {"email": value}},
                            {"term": {"domain": value}},
                        ]
                    }
                },
                "size": 20,
                "_source": {"excludes": ["password_hash"]},
            },
        )
        result["credential_exposures"] = [h["_source"] for h in cred_result["hits"]["hits"]]
        if result["credential_exposures"]:
            result["found"] = True
    except Exception:
        pass

    # Search in dark web posts
    try:
        dw_result = await es_service.client.search(
            index="darkweb_posts",
            body={
                "query": {
                    "multi_match": {
                        "query": value,
                        "fields": ["body_text", "title", "emails_found"],
                    }
                },
                "size": 10,
            },
        )
        result["darkweb_mentions"] = [h["_source"] for h in dw_result["hits"]["hits"]]
        if result["darkweb_mentions"]:
            result["found"] = True
    except Exception:
        pass

    # MISP correlation — fire-and-forget with 5s timeout
    # MISP can be very slow; don't block the response
    try:
        import asyncio
        from app.services.misp import misp_client
        if misp_client.enabled:
            try:
                attrs = await asyncio.wait_for(
                    misp_client.search_attributes(value=value, limit=10),
                    timeout=5.0,
                )
                if attrs:
                    result["misp_correlations"] = {
                        "total_attributes": len(attrs),
                        "events": list(set(str(a.get("event_id")) for a in attrs)),
                        "tags": list(set(
                            t.get("name", "")
                            for a in attrs
                            for t in a.get("Tag", [])
                            if t.get("name")
                        ))[:20],
                    }
                    result["found"] = True
            except asyncio.TimeoutError:
                result["misp_correlations"] = {"status": "timeout", "message": "MISP lookup timed out"}
    except Exception as e:
        logger.warning(f"MISP lookup error: {e}")

    return result
