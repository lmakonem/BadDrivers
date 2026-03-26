"""
JichoDNS API - Main FastAPI Application

Africa-focused DNS threat intelligence platform.
"""

from contextlib import asynccontextmanager
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import ORJSONResponse

from app.core.config import settings
from app.core.logging import setup_logging
from app.core.database import init_db, close_db
from app.api.v1 import router as api_v1_router
from app.api.health import router as health_router
from app.services.elasticsearch import es_service

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for startup/shutdown events."""
    # Startup
    setup_logging()
    logger.info("Starting JichoDNS API...")

    # Initialize PostgreSQL tables (users, api_keys, etc.)
    try:
        await init_db()
        logger.info("PostgreSQL tables initialized")
    except Exception as e:
        logger.warning(f"Could not initialize PostgreSQL: {e}")

    # Initialize Elasticsearch connection
    try:
        await es_service.connect()
        logger.info("Connected to Elasticsearch")
    except Exception as e:
        logger.warning(f"Could not connect to Elasticsearch: {e}")
    
    yield
    
    # Shutdown
    logger.info("Shutting down JichoDNS API...")
    await es_service.close()
    await close_db()


app = FastAPI(
    title="JichoDNS API",
    description="Africa-focused DNS threat intelligence platform.",
    version="0.1.0",
    # Disable public docs — served via /api-docs frontend page for paying users
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    default_response_class=ORJSONResponse,
    lifespan=lifespan,
)

# Serve OpenAPI docs only to authenticated admin/paid users
from fastapi import Request, Depends
from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html
from fastapi.responses import JSONResponse
from app.api.deps import get_current_user


def _has_auth(request: Request) -> bool:
    """Check if request has valid auth (bearer token or admin session cookie)."""
    # Check Authorization header
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer ") and len(auth_header) > 20:
        from app.core.security import decode_token
        payload = decode_token(auth_header[7:])
        if payload and payload.get("type") == "access":
            return True
    # Check admin session cookie
    try:
        admin_id = request.session.get("admin_user_id")
        if admin_id:
            return True
    except Exception:
        pass
    return False


@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui(request: Request):
    """Swagger UI — requires auth."""
    if not _has_auth(request):
        return JSONResponse({"detail": "Authentication required. Use /api-docs page."}, status_code=401)
    return get_swagger_ui_html(openapi_url="/openapi.json", title="JichoDNS API Docs")


@app.get("/redoc", include_in_schema=False)
async def custom_redoc(request: Request):
    """ReDoc — requires auth."""
    if not _has_auth(request):
        return JSONResponse({"detail": "Authentication required."}, status_code=401)
    return get_redoc_html(openapi_url="/openapi.json", title="JichoDNS API Docs")


@app.get("/openapi.json", include_in_schema=False)
async def custom_openapi(request: Request):
    """OpenAPI schema — requires auth."""
    if not _has_auth(request):
        return JSONResponse({"detail": "Authentication required."}, status_code=401)
    from fastapi.openapi.utils import get_openapi
    if not app.openapi_schema:
        app.openapi_schema = get_openapi(
            title=app.title, version=app.version,
            description=app.description, routes=app.routes,
        )
    return JSONResponse(app.openapi_schema)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# Include routers
app.include_router(health_router, tags=["Health"])
app.include_router(api_v1_router, prefix="/api/v1")

# Mount SQLAdmin panel at /admin
from app.admin import setup_admin
setup_admin(app)


@app.get("/", include_in_schema=False)
async def root():
    """Root endpoint with API information."""
    return {
        "name": "JichoDNS API",
        "version": "0.1.0",
        "description": "Africa-focused DNS threat intelligence platform",
        "docs": "/docs",
        "health": "/health",
        "api": "/api/v1",
    }



