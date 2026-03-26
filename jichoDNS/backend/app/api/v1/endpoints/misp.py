"""
MISP integration endpoints.

Provides search, event viewing, and correlation against
the external MISP instance at misp.afisac.africa.
"""

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from app.services.misp import misp_client

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/status")
async def misp_status():
    """Check MISP connection status."""
    if not misp_client.enabled:
        return {"connected": False, "reason": "MISP not configured"}
    try:
        version = await misp_client.get_version()
        return {
            "connected": "error" not in version,
            "version": version.get("version"),
            "perm_sync": version.get("perm_sync"),
        }
    except Exception as e:
        return {"connected": False, "reason": str(e)}


@router.get("/search")
async def misp_search(
    value: str = Query(..., min_length=2, description="IOC value to search"),
    type: Optional[str] = Query(None, description="MISP type: ip-dst, domain, url, md5, sha256"),
    limit: int = Query(50, ge=1, le=500),
):
    """Search MISP for attributes matching a value."""
    if not misp_client.enabled:
        raise HTTPException(503, "MISP integration not configured")

    attrs = await misp_client.search_attributes(
        value=value,
        type_attribute=type,
        limit=limit,
    )
    return {"count": len(attrs), "attributes": attrs}


@router.get("/events")
async def misp_events(
    last: str = Query("30d", description="Time window: 1d, 7d, 30d, 90d"),
    limit: int = Query(20, ge=1, le=100),
    page: int = Query(1, ge=1),
):
    """List recent MISP events."""
    if not misp_client.enabled:
        raise HTTPException(503, "MISP integration not configured")

    events = await misp_client.search_events(last=last, limit=limit, page=page)
    return {"count": len(events), "events": events}


@router.get("/events/{event_id}")
async def misp_event_detail(event_id: str):
    """Get full MISP event with all attributes and tags."""
    if not misp_client.enabled:
        raise HTTPException(503, "MISP integration not configured")

    event = await misp_client.get_event(event_id)
    if not event:
        raise HTTPException(404, "Event not found")
    return event


@router.get("/correlate/{value}")
async def misp_correlate(
    value: str,
    limit: int = Query(50, ge=1, le=200),
):
    """
    Find all MISP events containing a given IOC.

    Useful for understanding the context of an indicator —
    which campaigns, threat actors, or malware families it's associated with.
    """
    if not misp_client.enabled:
        raise HTTPException(503, "MISP integration not configured")

    attrs = await misp_client.search_attributes(value=value, limit=limit)

    # Group by event_id
    events_seen = {}
    for attr in attrs:
        eid = attr.get("event_id")
        if eid and eid not in events_seen:
            events_seen[eid] = {
                "event_id": eid,
                "event_info": attr.get("Event", {}).get("info", ""),
                "event_org": attr.get("Event", {}).get("org_id", ""),
                "attributes_matched": 0,
                "tags": [],
            }
        if eid in events_seen:
            events_seen[eid]["attributes_matched"] += 1
            for tag in attr.get("Tag", []):
                tag_name = tag.get("name", "")
                if tag_name and tag_name not in events_seen[eid]["tags"]:
                    events_seen[eid]["tags"].append(tag_name)

    return {
        "value": value,
        "total_attributes": len(attrs),
        "total_events": len(events_seen),
        "events": list(events_seen.values()),
    }
