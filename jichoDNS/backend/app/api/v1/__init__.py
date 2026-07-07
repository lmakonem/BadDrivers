"""API v1 router."""

from fastapi import APIRouter, Depends

from app.api.deps import get_current_user, require_tier
from app.api.v1.endpoints import (
    admin,
    alerts_api,
    auth,
    billing,
    credentials,
    darkweb_intel,
    indicators,
    intel,
    misp,
    public,
    regions,
    analysis,
    atlas,
    search,
    websocket,
    forms,
    darkweb,
    reports,
    asm,
    brand,
)

router = APIRouter()

# ── Public endpoints (no auth) ────────────────────────────────────────────────
router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
router.include_router(forms.router, prefix="/forms", tags=["Forms"])

# Public map data — limited, capped, no full IOC listing
router.include_router(public.router, tags=["Public"])

# Billing — webhook must be public, checkout auth is in-endpoint
router.include_router(billing.router, prefix="/billing", tags=["Billing"])

# WebSocket — public for live map on landing page
router.include_router(websocket.router, tags=["WebSocket"])

# ── Protected endpoints (JWT required) ────────────────────────────────────────
_auth = [Depends(get_current_user)]

# Full indicator/region/analysis access requires login
router.include_router(
    indicators.router, prefix="/indicators", tags=["Indicators"],
    dependencies=_auth,
)
router.include_router(
    regions.router, prefix="/regions", tags=["Regions"],
    dependencies=_auth,
)
router.include_router(
    analysis.router, prefix="/analysis", tags=["Analysis"],
    dependencies=_auth,
)
router.include_router(
    admin.router, prefix="/admin", tags=["Admin"],
    dependencies=_auth,
)
router.include_router(
    atlas.router, prefix="/atlas", tags=["RIPE Atlas"],
    dependencies=_auth,
)
router.include_router(
    darkweb.router, prefix="/darkweb", tags=["Dark Web Monitoring"],
    dependencies=[*_auth, Depends(require_tier("professional"))],
)
router.include_router(
    reports.router, prefix="/reports", tags=["Threat Reports"],
    dependencies=_auth,
)
router.include_router(
    asm.router, prefix="/asm", tags=["Attack Surface Management"],
    dependencies=[*_auth, Depends(require_tier("enterprise"))],
)
router.include_router(
    brand.router, prefix="/brand", tags=["Brand Protection"],
    dependencies=[*_auth, Depends(require_tier("professional"))],
)
router.include_router(
    intel.router, prefix="/intel", tags=["Intelligence"],
    dependencies=[*_auth, Depends(require_tier("professional"))],
)
router.include_router(
    search.router, prefix="/search", tags=["Search"],
    dependencies=_auth,
)
router.include_router(
    alerts_api.router, prefix="/alerts", tags=["Alerts"],
    dependencies=_auth,
)
router.include_router(
    credentials.router, prefix="/credentials", tags=["Credentials"],
    dependencies=_auth,
)
router.include_router(
    darkweb_intel.router, prefix="/darkweb-intel", tags=["Dark Web Intel"],
    dependencies=[*_auth, Depends(require_tier("professional"))],
)
router.include_router(
    misp.router, prefix="/misp", tags=["MISP"],
    dependencies=_auth,
)
