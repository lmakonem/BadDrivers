"""Health check endpoints."""

from fastapi import APIRouter
from datetime import datetime

router = APIRouter()


@router.get("/health")
async def health_check():
    """Basic health check — minimal info."""
    return {"status": "ok"}


@router.get("/health/ready")
async def readiness_check():
    """Readiness check — minimal info."""
    return {"status": "ok"}
