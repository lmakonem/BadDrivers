"""RIPE Atlas endpoints - DNS measurements from African probes."""

from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query
from starlette.status import HTTP_501_NOT_IMPLEMENTED
from pydantic import BaseModel
from datetime import datetime

router = APIRouter()


class ProbeInfo(BaseModel):
    id: int
    country_code: str
    asn: int
    asn_name: Optional[str] = None
    city: Optional[str] = None
    latitude: float
    longitude: float
    is_anchor: bool
    status: str


class ProbeListResponse(BaseModel):
    items: List[ProbeInfo]
    total: int


@router.get("/probes", response_model=ProbeListResponse)
async def list_african_probes(
    country: Optional[str] = Query(None, description="Filter by country code"),
    status: str = Query("Connected", description="Probe status filter"),
):
    """
    List RIPE Atlas probes in African countries.
    """
    raise HTTPException(
        status_code=HTTP_501_NOT_IMPLEMENTED,
        detail="RIPE Atlas probe listing is not implemented yet.",
    )


@router.get("/probes/{probe_id}", response_model=ProbeInfo)
async def get_probe(probe_id: int):
    """Get information about a specific probe."""
    # RIPE Atlas integration not implemented — fail honestly instead of
    # returning a fabricated probe record.
    raise HTTPException(
        status_code=HTTP_501_NOT_IMPLEMENTED,
        detail="RIPE Atlas probe lookup is not implemented yet.",
    )


class MeasurementRequest(BaseModel):
    target: str
    query_type: str = "A"
    probe_countries: List[str] = ["KE", "ZA", "NG", "EG", "MA"]
    probe_count: int = 10


@router.post("/measurements")
async def create_measurement(request: MeasurementRequest):
    """
    Create a new DNS measurement using African probes.
    
    Requires RIPE Atlas API key with measurement credits.
    """
    # Not implemented — do NOT report success for a measurement that was
    # never created.
    raise HTTPException(
        status_code=HTTP_501_NOT_IMPLEMENTED,
        detail="RIPE Atlas measurement creation is not implemented yet.",
    )


@router.get("/measurements/{measurement_id}/results")
async def get_measurement_results(measurement_id: int):
    """Get results from a DNS measurement."""
    raise HTTPException(
        status_code=HTTP_501_NOT_IMPLEMENTED,
        detail="RIPE Atlas measurement results are not implemented yet.",
    )
