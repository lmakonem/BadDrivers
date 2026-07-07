"""
Alerts aggregation endpoint — pulls alerts from all sources into a unified feed.

Aggregates from: IOC threat types, dark web brand matches, credential exposures,
ASM vulnerabilities, brand protection alerts.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.deps import get_current_user
from app.core.database import get_db
from app.core.ownership import get_owned_domains
from app.models.user import User
from app.services.elasticsearch import es_service

logger = logging.getLogger(__name__)

router = APIRouter()

ALERT_STATUS_INDEX = "alert_status"
VALID_ALERT_STATUSES = {"new", "acknowledged", "investigating", "resolved"}


@router.get("/feed")
async def get_alerts_feed(
    severity: Optional[str] = Query(None, description="Filter: critical, high, medium, low"),
    alert_type: Optional[str] = Query(None, description="Filter: c2, malware, phishing, credential_leak, brand_abuse, vulnerability, darkweb_mention"),
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Unified alerts feed aggregated from all intelligence sources.

    Returns alerts sorted by severity and recency.
    """
    await es_service.connect()
    if not es_service.client:
        return {"items": [], "total": 0}

    alerts = []

    # 1. IOC-based alerts (high-risk indicators from last 24h)
    try:
        ioc_result = await es_service.client.search(
            index="iocs",
            body={
                "query": {
                    "bool": {
                        "filter": [
                            {"term": {"active": True}},
                            {"range": {"risk_score": {"gte": 70}}},
                        ]
                    }
                },
                "aggs": {
                    "by_threat": {
                        "terms": {"field": "threat_type.keyword", "size": 10},
                        "aggs": {
                            "recent": {"top_hits": {"size": 1, "sort": [{"created_at": "desc"}]}},
                            "count": {"value_count": {"field": "indicator.keyword"}},
                        },
                    }
                },
                "size": 0,
            },
        )
        for bucket in ioc_result.get("aggregations", {}).get("by_threat", {}).get("buckets", []):
            threat = bucket["key"]
            count = bucket["doc_count"]
            recent = bucket["recent"]["hits"]["hits"][0]["_source"] if bucket["recent"]["hits"]["hits"] else {}

            sev = "critical" if threat in ("c2", "botnet") else "high" if threat in ("malware", "phishing") else "medium"
            alerts.append({
                "id": f"ioc-{threat}",
                "type": threat,
                "title": f"{count:,} {threat.upper()} indicators active",
                "description": f"Active {threat} threats detected across monitored feeds. Latest: {recent.get('indicator', 'N/A')}",
                "severity": sev,
                "source": recent.get("source", "threat_feeds"),
                "timestamp": recent.get("created_at", datetime.now(timezone.utc).isoformat()),
                "indicator_count": count,
            })
    except Exception as e:
        if "index_not_found" not in str(e):
            logger.warning(f"IOC alerts error: {e}")

    # 2. Credential exposure alerts (scoped to the caller's owned domains).
    # credential_exposures is a global breach corpus; non-admins must only see
    # counts for domains they monitor — mirror the scoping in credentials.py.
    cred_query = {"match_all": {}}
    include_creds = True
    if not current_user.is_admin:
        owned = await get_owned_domains(current_user, db)
        if owned:
            cred_query = {"bool": {"filter": [{"terms": {"domain": sorted(owned)}}]}}
        else:
            # Owns no domains → contribute nothing (no platform-wide leak).
            include_creds = False

    if include_creds:
        try:
            cred_result = await es_service.client.search(
                index="credential_exposures",
                body={
                    "query": cred_query,
                    "aggs": {
                        "by_severity": {"terms": {"field": "severity.keyword"}},
                        "vip_count": {"filter": {"term": {"vip_match": True}}},
                        "recent": {"top_hits": {"size": 1, "sort": [{"discovered_at": "desc"}]}},
                        "total": {"value_count": {"field": "email.keyword"}},
                    },
                    "size": 0,
                },
            )
            aggs = cred_result.get("aggregations", {})
            total_creds = aggs.get("total", {}).get("value", 0)
            vip_count = aggs.get("vip_count", {}).get("doc_count", 0)

            if total_creds > 0:
                recent = aggs.get("recent", {}).get("hits", {}).get("hits", [{}])[0].get("_source", {})
                alerts.append({
                    "id": "cred-exposure",
                    "type": "credential_leak",
                    "title": f"{total_creds:,} credential exposures detected",
                    "description": f"Leaked credentials found across breach databases. {vip_count} VIP matches.",
                    "severity": "critical" if vip_count > 0 else "high",
                    "source": "credential_monitoring",
                    "timestamp": recent.get("discovered_at", datetime.now(timezone.utc).isoformat()),
                    "indicator_count": total_creds,
                })
        except Exception:
            pass

    # 3. Dark web alerts
    try:
        dw_result = await es_service.client.search(
            index="darkweb_posts",
            body={
                "query": {"exists": {"field": "brand_matches"}},
                "aggs": {
                    "with_brands": {
                        "filter": {"script": {"script": "doc['brand_matches'].length > 0"}},
                    },
                    "recent": {"top_hits": {"size": 1, "sort": [{"discovered_at": "desc"}]}},
                },
                "size": 0,
            },
        )
        dw_total = dw_result["hits"]["total"]["value"]
        if dw_total > 0:
            recent = dw_result.get("aggregations", {}).get("recent", {}).get("hits", {}).get("hits", [{}])[0].get("_source", {})
            alerts.append({
                "id": "darkweb-mention",
                "type": "darkweb_mention",
                "title": f"{dw_total} dark web posts with brand mentions",
                "description": f"Brand terms detected on dark web sites. Latest from: {recent.get('source_type', 'unknown')}",
                "severity": "high",
                "source": "dark_web_monitoring",
                "timestamp": recent.get("discovered_at", datetime.now(timezone.utc).isoformat()),
                "indicator_count": dw_total,
            })
    except Exception:
        pass

    # Filter
    if severity:
        alerts = [a for a in alerts if a["severity"] == severity]
    if alert_type:
        alerts = [a for a in alerts if a["type"] == alert_type]

    # Merge persisted per-user status (default "new" if never touched).
    alert_ids = [a["id"] for a in alerts]
    if alert_ids:
        status_map: dict = {}
        try:
            mget = await es_service.client.mget(
                index=ALERT_STATUS_INDEX,
                body={"ids": [f"{current_user.id}:{aid}" for aid in alert_ids]},
            )
            for doc in mget.get("docs", []):
                if doc.get("found"):
                    src = doc["_source"]
                    status_map[src["alert_id"]] = src.get("status", "new")
        except Exception:
            # index may not exist yet — treat all as "new"
            pass
        for a in alerts:
            a["status"] = status_map.get(a["id"], "new")

    # Sort: critical > high > medium > low, then by timestamp
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    alerts.sort(key=lambda a: (severity_order.get(a["severity"], 4), a.get("timestamp", "")))

    return {
        "items": alerts[:limit],
        "total": len(alerts),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@router.patch("/{alert_id}/status")
async def update_alert_status(
    alert_id: str,
    status: str = Body(..., embed=True),
    current_user: User = Depends(get_current_user),
):
    """Persist the current user's status for an aggregated alert."""
    if status not in VALID_ALERT_STATUSES:
        raise HTTPException(status_code=422, detail="Invalid status")

    await es_service.connect()
    if not es_service.client:
        raise HTTPException(status_code=503, detail="Elasticsearch unavailable")

    doc_id = f"{current_user.id}:{alert_id}"
    await es_service.client.index(
        index=ALERT_STATUS_INDEX,
        id=doc_id,
        document={
            "user_id": current_user.id,
            "alert_id": alert_id,
            "status": status,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        },
        refresh="wait_for",
    )
    return {"alert_id": alert_id, "status": status, "updated_at": datetime.now(timezone.utc).isoformat()}
