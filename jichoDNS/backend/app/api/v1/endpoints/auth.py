"""Authentication endpoints: register, login, refresh, me."""

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import (
    hash_password,
    verify_password,
    dummy_verify,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_token_subject,
)
from app.core.ratelimit import (
    check_login_allowed,
    record_login_failure,
    clear_login_failures,
    client_ip,
)
from app.models.user import User
from app.api.deps import get_current_user

router = APIRouter()


# ── Request / Response schemas ────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    name: Optional[str] = None
    organization: Optional[str] = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds


class UserResponse(BaseModel):
    id: int
    email: str
    name: Optional[str]
    organization: Optional[str]
    is_active: bool
    is_verified: bool
    is_admin: bool
    tier: str
    created_at: datetime

    class Config:
        from_attributes = True


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/register", status_code=status.HTTP_202_ACCEPTED)
async def register(body: RegisterRequest, db: AsyncSession = Depends(get_db)):
    """
    Register a new user account.

    To avoid account enumeration this endpoint returns the SAME generic 202
    response and takes ~the same time whether or not the email was already
    registered. The client completes sign-in via POST /login afterwards.
    """
    # Hash first so the duplicate path costs the same bcrypt as the create path
    # (equal timing → no enumeration by response time).
    hashed = hash_password(body.password)

    result = await db.execute(select(User).where(User.email == body.email))
    existing = result.scalar_one_or_none()

    if existing is None:
        user = User(
            email=body.email,
            hashed_password=hashed,
            name=body.name,
            organization=body.organization,
            is_active=True,
            is_verified=False,
            is_admin=False,
            tier="free",
            daily_api_limit=100,
            monthly_api_limit=3000,
        )
        db.add(user)
        try:
            await db.flush()
        except IntegrityError:
            # Lost a race — the email was registered concurrently. Same reply.
            await db.rollback()

    return {
        "message": "If the email address is valid, the account is ready. "
                   "You can now sign in.",
    }


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, request: Request, db: AsyncSession = Depends(get_db)):
    """
    Authenticate with email + password and receive JWT tokens.

    Protected against brute force (per-account + per-IP lockout via Redis) and
    against user-enumeration by timing (a bcrypt is always run).
    """
    ip = client_ip(request)

    retry_after = await check_login_allowed(body.email, ip)
    if retry_after is not None:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Please try again later.",
            headers={"Retry-After": str(retry_after)},
        )

    result = await db.execute(select(User).where(User.email == body.email))
    user = result.scalar_one_or_none()

    # Always spend one bcrypt: verify the real hash when present, otherwise burn
    # equivalent CPU against a dummy hash so a missing account and a wrong
    # password are indistinguishable by response time.
    if user and user.hashed_password:
        password_ok = verify_password(body.password, user.hashed_password)
    else:
        dummy_verify()
        password_ok = False

    if not user or not user.hashed_password or not password_ok:
        await record_login_failure(body.email, ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled.",
        )

    await clear_login_failures(body.email, ip)

    from app.core.config import settings

    token_data = {"sub": str(user.id), "email": user.email}
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(body: RefreshRequest, db: AsyncSession = Depends(get_db)):
    """
    Exchange a valid refresh token for a new access + refresh token pair.
    """
    payload = decode_token(body.refresh_token, require_type="refresh")
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token.",
        )

    user_id = get_token_subject(payload)
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token payload.",
        )
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive.",
        )

    from app.core.config import settings

    token_data = {"sub": str(user.id), "email": user.email}
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    """
    Return the profile for the currently authenticated user.
    """
    return current_user
