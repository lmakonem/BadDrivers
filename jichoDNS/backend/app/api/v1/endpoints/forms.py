"""
Form submission endpoints — demo requests, contact, newsletter, enterprise quotes.

All submissions are persisted to PostgreSQL and visible in the admin panel.
"""

import logging
import uuid
from datetime import datetime
from enum import Enum
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
# Reuse the shared Redis limiter from app.core.ratelimit: client_ip() for the
# real (Cloudflare-fronted) source IP, and its shared async Redis client.
from app.core.ratelimit import _get_redis, client_ip
from app.models.form_submission import FormSubmission

logger = logging.getLogger(__name__)

router = APIRouter()


# ── Anti-abuse rate limiting ──────────────────────────────────────────────────
# These POST routes are public and unauthenticated, so they are a spam/abuse
# target. Apply a simple per-source-IP fixed-window limit that mirrors the
# existing login limiter pattern. FAIL-OPEN: any Redis problem allows the
# request so a Redis outage never blocks legitimate submissions.

FORM_WINDOW_SECONDS = 3600   # 1-hour fixed window
MAX_FORMS_PER_IP = 10        # max submissions per source IP per window


async def rate_limit_forms(request: Request) -> None:
    """FastAPI dependency: throttle public form POSTs per source IP.

    Raises HTTP 429 (with Retry-After) when an IP exceeds MAX_FORMS_PER_IP in
    the current window; allows the request on any Redis error (fail-open).
    """
    r = _get_redis()
    if r is None:
        return  # fail-open — Redis unavailable
    key = f"form_submit:ip:{client_ip(request)}"
    try:
        n = await r.incr(key)
        if int(n) == 1:
            # Set TTL only on first hit so the window doesn't slide forward.
            await r.expire(key, FORM_WINDOW_SECONDS)
        if int(n) > MAX_FORMS_PER_IP:
            ttl = await r.ttl(key)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many submissions from this address. Please try again later.",
                headers={"Retry-After": str(max(int(ttl or 0), 1))},
            )
    except HTTPException:
        raise
    except Exception as e:  # pragma: no cover - defensive
        logger.error("form-ratelimit: check failed, allowing request: %s", e)
        return  # fail-open


# ── Enums ─────────────────────────────────────────────────────────────────────

class CompanySize(str, Enum):
    SMALL = "1-10"
    MEDIUM = "11-50"
    LARGE = "51-200"
    ENTERPRISE = "201-1000"
    LARGE_ENTERPRISE = "1000+"


class BudgetRange(str, Enum):
    UNDER_5K = "under_5k"
    RANGE_5K_10K = "5k-10k"
    RANGE_10K_25K = "10k-25k"
    RANGE_25K_50K = "25k-50k"
    OVER_50K = "over_50k"
    CUSTOM = "custom"


# ── Request schemas ───────────────────────────────────────────────────────────

class DemoRequest(BaseModel):
    first_name: str = Field(..., min_length=1, max_length=100)
    last_name: str = Field(..., min_length=1, max_length=100)
    email: EmailStr
    company: str = Field(..., min_length=1, max_length=200)
    job_title: str = Field(..., min_length=1, max_length=150)
    phone: Optional[str] = Field(None, max_length=30)
    company_size: CompanySize
    message: Optional[str] = Field(None, max_length=2000)

    @field_validator("phone")
    @classmethod
    def validate_phone(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        cleaned = v.replace(" ", "").replace("-", "").replace("(", "").replace(")", "")
        if cleaned and not cleaned.lstrip("+").isdigit():
            raise ValueError("Invalid phone number")
        return v


class ContactRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    email: EmailStr
    subject: str = Field(..., min_length=1, max_length=300)
    message: str = Field(..., min_length=10, max_length=5000)


class SubscribeRequest(BaseModel):
    email: EmailStr


class QuoteRequest(BaseModel):
    first_name: str = Field(..., min_length=1, max_length=100)
    last_name: str = Field(..., min_length=1, max_length=100)
    email: EmailStr
    company: str = Field(..., min_length=1, max_length=200)
    phone: Optional[str] = Field(None, max_length=30)
    requirements: str = Field(..., min_length=20, max_length=5000)
    budget_range: BudgetRange

    @field_validator("phone")
    @classmethod
    def validate_phone(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        cleaned = v.replace(" ", "").replace("-", "").replace("(", "").replace(")", "")
        if cleaned and not cleaned.lstrip("+").isdigit():
            raise ValueError("Invalid phone number")
        return v


# ── Response schemas ──────────────────────────────────────────────────────────

class FormSubmissionResponse(BaseModel):
    success: bool
    message: str
    submission_id: str
    submitted_at: str


class SubscriptionResponse(BaseModel):
    success: bool
    message: str
    email: str
    subscribed_at: str


# ── Helper ────────────────────────────────────────────────────────────────────

async def _store(
    db: AsyncSession,
    form_type: str,
    email: str,
    name: str | None,
    payload: dict,
) -> FormSubmission:
    sid = str(uuid.uuid4())
    sub = FormSubmission(
        form_type=form_type,
        email=email.lower(),
        name=name,
        status="unread",
        submission_id=sid,
        payload=payload,
    )
    db.add(sub)
    await db.flush()
    await db.refresh(sub)
    return sub


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post(
    "/demo",
    response_model=FormSubmissionResponse,
    status_code=201,
    dependencies=[Depends(rate_limit_forms)],
)
async def request_demo(req: DemoRequest, db: AsyncSession = Depends(get_db)):
    payload = req.model_dump()
    payload["company_size"] = req.company_size.value
    sub = await _store(
        db, "demo", req.email,
        f"{req.first_name} {req.last_name}", payload,
    )
    logger.info(f"Demo request from {req.company} — {sub.submission_id}")
    return FormSubmissionResponse(
        success=True,
        message="Thank you! Our team will contact you within 24-48 hours to schedule your demo.",
        submission_id=sub.submission_id,
        submitted_at=sub.created_at.isoformat() + "Z",
    )


@router.post(
    "/contact",
    response_model=FormSubmissionResponse,
    status_code=201,
    dependencies=[Depends(rate_limit_forms)],
)
async def contact_us(req: ContactRequest, db: AsyncSession = Depends(get_db)):
    sub = await _store(db, "contact", req.email, req.name, req.model_dump())
    logger.info(f"Contact from {req.name} — {req.subject}")
    return FormSubmissionResponse(
        success=True,
        message="Thank you for reaching out! We'll respond within 24-48 business hours.",
        submission_id=sub.submission_id,
        submitted_at=sub.created_at.isoformat() + "Z",
    )


@router.post(
    "/subscribe",
    response_model=SubscriptionResponse,
    status_code=201,
    dependencies=[Depends(rate_limit_forms)],
)
async def subscribe(req: SubscribeRequest, db: AsyncSession = Depends(get_db)):
    email = req.email.lower()
    # Check for existing
    result = await db.execute(
        select(FormSubmission).where(
            FormSubmission.form_type == "newsletter",
            FormSubmission.email == email,
        )
    )
    existing = result.scalar_one_or_none()
    if existing:
        return SubscriptionResponse(
            success=True,
            message="You're already subscribed!",
            email=email,
            subscribed_at=existing.created_at.isoformat() + "Z",
        )

    sub = await _store(db, "newsletter", email, None, {"email": email})
    logger.info(f"Newsletter subscription: {email}")
    return SubscriptionResponse(
        success=True,
        message="Successfully subscribed! You'll receive threat intelligence updates.",
        email=email,
        subscribed_at=sub.created_at.isoformat() + "Z",
    )


@router.post(
    "/quote",
    response_model=FormSubmissionResponse,
    status_code=201,
    dependencies=[Depends(rate_limit_forms)],
)
async def request_quote(req: QuoteRequest, db: AsyncSession = Depends(get_db)):
    payload = req.model_dump()
    payload["budget_range"] = req.budget_range.value
    sub = await _store(
        db, "quote", req.email,
        f"{req.first_name} {req.last_name}", payload,
    )
    logger.info(f"Enterprise quote from {req.company} — {sub.submission_id}")
    return FormSubmissionResponse(
        success=True,
        message="Thank you! Our enterprise team will contact you within 24 hours.",
        submission_id=sub.submission_id,
        submitted_at=sub.created_at.isoformat() + "Z",
    )
