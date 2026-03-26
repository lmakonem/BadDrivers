"""
Admin endpoints — view users, form submissions, system stats.

All endpoints require admin authentication.
"""

import logging
from datetime import datetime
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.api.deps import get_current_admin
from app.models.user import User
from app.models.form_submission import FormSubmission

logger = logging.getLogger(__name__)

router = APIRouter()


# ── Response schemas ──────────────────────────────────────────────────────────

class UserOut(BaseModel):
    id: int
    email: str
    name: Optional[str]
    organization: Optional[str]
    is_active: bool
    is_verified: bool
    is_admin: bool
    tier: str
    api_calls_today: int
    api_calls_month: int
    created_at: datetime

    class Config:
        from_attributes = True


class UsersListResponse(BaseModel):
    items: List[UserOut]
    total: int
    page: int
    page_size: int


class FormSubmissionOut(BaseModel):
    id: int
    form_type: str
    email: str
    name: Optional[str]
    status: str
    submission_id: str
    payload: Optional[dict]
    created_at: datetime

    class Config:
        from_attributes = True


class FormSubmissionsListResponse(BaseModel):
    items: List[FormSubmissionOut]
    total: int
    page: int
    page_size: int


class AdminStatsResponse(BaseModel):
    total_users: int
    active_users: int
    total_submissions: int
    unread_submissions: int
    users_by_tier: dict
    submissions_by_type: dict


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/stats", response_model=AdminStatsResponse)
async def get_admin_stats(
    _admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """Overview stats for the admin dashboard."""
    # User counts
    total_users = await db.scalar(select(func.count(User.id)))
    active_users = await db.scalar(
        select(func.count(User.id)).where(User.is_active == True)
    )
    # Tier breakdown
    tier_rows = await db.execute(
        select(User.tier, func.count(User.id)).group_by(User.tier)
    )
    users_by_tier = {row[0]: row[1] for row in tier_rows}

    # Submission counts
    total_subs = await db.scalar(select(func.count(FormSubmission.id)))
    unread_subs = await db.scalar(
        select(func.count(FormSubmission.id)).where(FormSubmission.status == "unread")
    )
    type_rows = await db.execute(
        select(FormSubmission.form_type, func.count(FormSubmission.id))
        .group_by(FormSubmission.form_type)
    )
    subs_by_type = {row[0]: row[1] for row in type_rows}

    return AdminStatsResponse(
        total_users=total_users or 0,
        active_users=active_users or 0,
        total_submissions=total_subs or 0,
        unread_submissions=unread_subs or 0,
        users_by_tier=users_by_tier,
        submissions_by_type=subs_by_type,
    )


@router.get("/users", response_model=UsersListResponse)
async def list_users(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    _admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """List all registered users (paginated)."""
    total = await db.scalar(select(func.count(User.id)))
    result = await db.execute(
        select(User)
        .order_by(desc(User.created_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    users = result.scalars().all()
    return UsersListResponse(
        items=users,
        total=total or 0,
        page=page,
        page_size=page_size,
    )


@router.get("/submissions", response_model=FormSubmissionsListResponse)
async def list_submissions(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    form_type: Optional[str] = Query(None, description="Filter by type: demo, contact, quote, newsletter"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status: unread, read, replied, archived"),
    _admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """List all form submissions (paginated, filterable)."""
    q = select(FormSubmission)
    count_q = select(func.count(FormSubmission.id))

    if form_type:
        q = q.where(FormSubmission.form_type == form_type)
        count_q = count_q.where(FormSubmission.form_type == form_type)
    if status_filter:
        q = q.where(FormSubmission.status == status_filter)
        count_q = count_q.where(FormSubmission.status == status_filter)

    total = await db.scalar(count_q)
    result = await db.execute(
        q.order_by(desc(FormSubmission.created_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    subs = result.scalars().all()
    return FormSubmissionsListResponse(
        items=subs,
        total=total or 0,
        page=page,
        page_size=page_size,
    )


@router.patch("/submissions/{submission_id}/status")
async def update_submission_status(
    submission_id: str,
    new_status: str = Query(..., description="New status: read, replied, archived"),
    _admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """Mark a submission as read / replied / archived."""
    if new_status not in ("unread", "read", "replied", "archived"):
        raise HTTPException(400, "Invalid status")
    result = await db.execute(
        select(FormSubmission).where(FormSubmission.submission_id == submission_id)
    )
    sub = result.scalar_one_or_none()
    if not sub:
        raise HTTPException(404, "Submission not found")
    sub.status = new_status
    await db.flush()
    return {"success": True, "submission_id": submission_id, "status": new_status}


@router.patch("/users/{user_id}/promote")
async def promote_to_admin(
    user_id: int,
    _admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """Promote a user to admin."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")
    user.is_admin = True
    await db.flush()
    return {"success": True, "user_id": user_id, "is_admin": True}


@router.patch("/users/{user_id}/tier")
async def update_user_tier(
    user_id: int,
    tier: str = Query(..., description="New tier: free, professional, enterprise"),
    _admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """Change a user's subscription tier."""
    if tier not in ("free", "professional", "enterprise"):
        raise HTTPException(400, "Invalid tier")
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")
    user.tier = tier
    await db.flush()
    return {"success": True, "user_id": user_id, "tier": tier}
