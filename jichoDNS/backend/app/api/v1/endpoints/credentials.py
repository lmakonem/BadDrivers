"""
Credential leak search and monitoring endpoints.

Searches the credential_exposures ES index and also generates synthetic
breach data from IOC feeds that contain email/credential indicators.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query
from app.api.deps import get_current_user
from app.models.user import User
from app.services.elasticsearch import es_service

logger = logging.getLogger(__name__)

router = APIRouter()


async def _ensure_cred_index():
    """Create credential_exposures index if missing."""
    await es_service.connect()
    if not es_service.client:
        return
    try:
        exists = await es_service.client.indices.exists(index="credential_exposures")
        if not exists:
            await es_service.client.indices.create(
                index="credential_exposures",
                body={
                    "mappings": {
                        "properties": {
                            "email": {"type": "keyword"},
                            "username": {"type": "keyword"},
                            "domain": {"type": "keyword"},
                            "password_hash": {"type": "keyword"},
                            "password_type": {"type": "keyword"},
                            "password_length": {"type": "integer"},
                            "source": {"type": "keyword"},
                            "source_name": {"type": "keyword"},
                            "discovered_at": {"type": "date"},
                            "breach_date": {"type": "date"},
                            "severity": {"type": "keyword"},
                            "vip_match": {"type": "boolean"},
                            "tags": {"type": "keyword"},
                        }
                    },
                    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
                },
            )
    except Exception:
        pass


@router.get("/search")
async def search_credentials(
    q: Optional[str] = Query(None, min_length=2, description="Search email, domain, or username"),
    domain: Optional[str] = Query(None, description="Filter by email domain"),
    severity: Optional[str] = Query(None, description="Filter: critical, high, medium"),
    page: int = Query(1, ge=1),
    page_size: int = Query(30, ge=5, le=100),
    current_user: User = Depends(get_current_user),
):
    """
    Search credential leaks and exposures.

    Searches the credential_exposures index. If empty, searches
    phishing IOCs from the main index that may contain credential harvesting URLs.
    """
    await es_service.connect()
    if not es_service.client:
        return {"items": [], "total": 0, "page": page, "source": "none"}

    # Try credential_exposures index first
    try:
            must = []
            if q:
                must.append({
                    "bool": {
                        "should": [
                            {"wildcard": {"email": {"value": f"*{q.lower()}*"}}},
                            {"wildcard": {"domain": {"value": f"*{q.lower()}*"}}},
                            {"wildcard": {"username": {"value": f"*{q.lower()}*"}}},
                            {"match": {"source_name": q}},
                        ],
                        "minimum_should_match": 1,
                    }
                })
            if domain:
                must.append({"term": {"domain": domain.lower()}})
            if severity:
                must.append({"term": {"severity": severity}})

            query = {"bool": {"must": must}} if must else {"match_all": {}}

            result = await es_service.client.search(
                index="credential_exposures",
                body={
                    "query": query,
                    "sort": [{"discovered_at": {"order": "desc"}}],
                    "from": (page - 1) * page_size,
                    "size": page_size,
                    "_source": [
                        "email", "username", "domain",
                        "password", "password_hash", "password_type", "password_length",
                        "source", "source_name", "discovered_at", "breach_date",
                        "severity", "country", "tags", "vip_match",
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
                "source": "credential_exposures",
            }
    except Exception as e:
        logger.error(f"Credential search error (real index): {e}")

    # Fallback: search phishing URLs only (credential harvesting pages)
    # NOT C2 IPs — only URLs that contain login/credential patterns
    try:
        must = [
            {"term": {"threat_type.keyword": "phishing"}},
            {"term": {"indicator_type.keyword": "url"}},
        ]
        if q:
            must.append({
                "multi_match": {
                    "query": q,
                    "fields": ["indicator^3", "tags"],
                    "type": "best_fields",
                    "fuzziness": "AUTO",
                }
            })

        result = await es_service.client.search(
            index="iocs",
            body={
                "query": {"bool": {"must": must, "filter": [{"term": {"active": True}}]}},
                "sort": [{"created_at": {"order": "desc"}}],
                "from": (page - 1) * page_size,
                "size": page_size,
                "_source": [
                    "indicator", "indicator_type", "threat_type", "source",
                    "risk_score", "country_code", "tags", "created_at",
                ],
            },
        )

        items = []
        for h in result["hits"]["hits"]:
            src = h["_source"]
            # Extract domain from URL
            from urllib.parse import urlparse
            try:
                parsed = urlparse(src.get("indicator", ""))
                domain = parsed.hostname or ""
            except Exception:
                domain = ""
            items.append({
                "email": src.get("indicator", ""),
                "domain": domain,
                "source": src.get("source", ""),
                "source_name": "Phishing Page",
                "severity": "high",
                "discovered_at": src.get("created_at"),
                "country_code": src.get("country_code"),
                "tags": src.get("tags", []),
                "type": "phishing_url",
            })

        total = result["hits"]["total"]["value"]
        return {
            "items": items,
            "total": total,
            "page": page,
            "page_size": page_size,
            "pages": (total + page_size - 1) // page_size,
            "source": "phishing_urls",
            "note": "Showing phishing credential-harvesting URLs. Actual breach credential data will appear when dark web crawls complete.",
        }
    except Exception as e:
        logger.error(f"Credential search error: {e}")
        return {"items": [], "total": 0, "page": page, "source": "error"}


@router.get("/stats")
async def credential_stats(
    current_user: User = Depends(get_current_user),
):
    """Credential exposure statistics."""
    await es_service.connect()
    if not es_service.client:
        return {"total": 0}

    try:
        agg = await es_service.client.search(
            index="credential_exposures",
            body={
                "size": 0,
                "aggs": {
                    "by_severity": {"terms": {"field": "severity", "size": 5}},
                    "by_source": {"terms": {"field": "source", "size": 10}},
                    "by_domain": {"terms": {"field": "domain", "size": 20}},
                    "by_country": {"terms": {"field": "country.keyword", "size": 30}},
                    "by_password_type": {"terms": {"field": "password_type", "size": 10}},
                    "vip_count": {"filter": {"term": {"vip_match": True}}},
                },
            },
        )
        aggs = agg.get("aggregations", {})
        total = agg["hits"]["total"]["value"]
        return {
            "total": total,
            "by_severity": {b["key"]: b["doc_count"] for b in aggs.get("by_severity", {}).get("buckets", [])},
            "by_source": {b["key"]: b["doc_count"] for b in aggs.get("by_source", {}).get("buckets", [])},
            "top_domains": {b["key"]: b["doc_count"] for b in aggs.get("by_domain", {}).get("buckets", [])},
            "by_country": {b["key"]: b["doc_count"] for b in aggs.get("by_country", {}).get("buckets", [])},
            "by_password_type": {b["key"]: b["doc_count"] for b in aggs.get("by_password_type", {}).get("buckets", [])},
            "vip_exposures": aggs.get("vip_count", {}).get("doc_count", 0),
            "source": "credential_exposures",
        }
    except Exception as e:
        logger.error(f"Credential stats error (real index): {e}")

    # Fallback stats from phishing IOCs
    try:
        result = await es_service.client.search(
            index="iocs",
            body={
                "size": 0,
                "query": {"terms": {"threat_type.keyword": ["phishing", "c2"]}},
                "aggs": {
                    "by_source": {"terms": {"field": "source.keyword", "size": 10}},
                    "by_type": {"terms": {"field": "threat_type.keyword", "size": 5}},
                },
            },
        )
        total = result["hits"]["total"]["value"]
        aggs = result.get("aggregations", {})
        return {
            "total": total,
            "by_source": {b["key"]: b["doc_count"] for b in aggs.get("by_source", {}).get("buckets", [])},
            "by_type": {b["key"]: b["doc_count"] for b in aggs.get("by_type", {}).get("buckets", [])},
            "source": "iocs_phishing",
        }
    except Exception:
        return {"total": 0, "source": "error"}
