"""Authentication endpoints: register, login, refresh, me."""

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import (
    hash_password,
    verify_password,
    dummy_verify,
    create_access_token,
    create_refresh_token,
    create_email_verification_token,
    decode_token,
    get_token_subject,
    token_remaining_seconds,
)
from app.core.ratelimit import (
    check_login_allowed,
    record_login_failure,
    clear_login_failures,
    check_register_allowed,
    check_email_resend_allowed,
    deny_token,
    is_token_denied,
    client_ip,
)
from app.models.user import User
from app.api.deps import get_current_user, bearer_scheme
from app.services.email_service import send_verification_email

router = APIRouter()


def normalize_email(email: str) -> str:
    """
    Canonical form for storage and lookup: trimmed + lowercased.

    Email local parts are case-sensitive per RFC 5321, but no real provider
    treats them that way — while mobile keyboards auto-capitalize the first
    letter. Without this, a user who registers as "Name@x.com" can never log
    in as "name@x.com" (and could register both as separate accounts).
    """
    return email.strip().lower()


# ── Request / Response schemas ────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    # Length caps match the VARCHAR(255) columns — without them an oversized
    # value raises DataError past the IntegrityError handler (a 500).
    name: Optional[str] = Field(default=None, max_length=255)
    organization: Optional[str] = Field(default=None, max_length=255)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    # Optional: the client sends its refresh token so it can be revoked too.
    # The access token is read from the Authorization header.
    refresh_token: Optional[str] = None


class VerifyEmailRequest(BaseModel):
    token: str


class ResendVerificationRequest(BaseModel):
    email: EmailStr


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
async def register(
    body: RegisterRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """
    Register a new user account.

    To avoid account enumeration this endpoint returns the SAME generic 202
    response and takes ~the same time whether or not the email was already
    registered. The client completes sign-in via POST /login afterwards.
    A verification email is dispatched AFTER the response (BackgroundTasks),
    so mail latency/failures neither slow registration nor leak timing.

    Per-IP rate limited to stop mass/bulk signup and blind existence probing.
    """
    ip = client_ip(request)
    retry_after = await check_register_allowed(ip)
    if retry_after is not None:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many registration attempts. Please try again later.",
            headers={"Retry-After": str(retry_after)},
        )

    email = normalize_email(body.email)

    # Hash first so the duplicate path costs the same bcrypt as the create path
    # (equal timing → no enumeration by response time).
    hashed = hash_password(body.password)

    result = await db.execute(select(User).where(User.email == email))
    existing = result.scalar_one_or_none()

    if existing is None:
        user = User(
            email=email,
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
        else:
            token = create_email_verification_token(user.id, email)
            background_tasks.add_task(
                send_verification_email, email, body.name, token
            )

    return {
        "message": "If the email address is valid, the account is ready. "
                   "Check your inbox for a verification email — you can sign "
                   "in right away.",
    }


@router.post("/verify-email")
async def verify_email(body: VerifyEmailRequest, db: AsyncSession = Depends(get_db)):
    """
    Confirm an email address from the signed token sent in the verification
    email. Idempotent: re-verifying an already-verified account succeeds.
    Deliberately a POST (the frontend page submits it) so mail scanners that
    prefetch GET links cannot consume/act on the token.
    """
    payload = decode_token(body.token, require_type="email_verify")
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification link. "
                   "Request a new verification email.",
        )

    user_id = get_token_subject(payload)
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification token payload.",
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    # The token must still match the account's current email — an address
    # change after issuance invalidates old verification links.
    if (
        not user
        or not user.is_active
        or normalize_email(user.email) != normalize_email(payload.get("email") or "")
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification link. "
                   "Request a new verification email.",
        )

    if not user.is_verified:
        user.is_verified = True
        await db.flush()

    return {"message": "Email verified. Your account is fully active."}


@router.post("/resend-verification", status_code=status.HTTP_202_ACCEPTED)
async def resend_verification(
    body: ResendVerificationRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """
    Re-send the verification email. Anti-enumeration: always the same generic
    202 whether or not the account exists / is already verified. Per-IP rate
    limited (unauthenticated mail-sending endpoint).
    """
    ip = client_ip(request)
    retry_after = await check_email_resend_allowed(ip)
    if retry_after is not None:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please try again later.",
            headers={"Retry-After": str(retry_after)},
        )

    email = normalize_email(body.email)
    result = await db.execute(
        select(User).where(func.lower(User.email) == email)
    )
    user = result.scalars().first()

    if user and user.is_active and not user.is_verified:
        token = create_email_verification_token(user.id, email)
        background_tasks.add_task(send_verification_email, email, user.name, token)

    return {
        "message": "If an unverified account exists for that address, a new "
                   "verification email has been sent.",
    }


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, request: Request, db: AsyncSession = Depends(get_db)):
    """
    Authenticate with email + password and receive JWT tokens.

    Protected against brute force (per-account + per-IP lockout via Redis) and
    against user-enumeration by timing (a bcrypt is always run).
    """
    ip = client_ip(request)
    email = normalize_email(body.email)

    retry_after = await check_login_allowed(email, ip)
    if retry_after is not None:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Please try again later.",
            headers={"Retry-After": str(retry_after)},
        )

    # Case-insensitive match tolerates rows created before emails were
    # normalized to lowercase at registration time.
    result = await db.execute(
        select(User).where(func.lower(User.email) == email)
    )
    user = result.scalars().first()

    # Always spend one bcrypt: verify the real hash when present, otherwise burn
    # equivalent CPU against a dummy hash so a missing account and a wrong
    # password are indistinguishable by response time.
    if user and user.hashed_password:
        password_ok = verify_password(body.password, user.hashed_password)
    else:
        dummy_verify()
        password_ok = False

    if not user or not user.hashed_password or not password_ok:
        await record_login_failure(email, ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled.",
        )

    from app.core.config import settings as _settings

    if _settings.REQUIRE_EMAIL_VERIFICATION and not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email address not verified. Check your inbox or request "
                   "a new verification email.",
        )

    await clear_login_failures(email, ip)

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

    if await is_token_denied(payload.get("jti")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has been revoked. Please sign in again.",
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


@router.post("/logout")
async def logout(
    body: LogoutRequest,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
):
    """
    Revoke this session's tokens server-side (a real kill switch — JWTs are
    otherwise valid until expiry, so client-side logout alone leaves a stolen
    refresh token live for days).

    Deliberately token-bearing rather than auth-gated: possessing a token is the
    authority to revoke it, and an *expired* access token must still be able to
    kill its refresh token. Idempotent — always 200, nothing to reveal. Each
    revoked jti is denylisted only for its own remaining lifetime.
    """
    # Access token from the Authorization header (revoked only if still valid;
    # an already-expired one needs no denylisting).
    if credentials:
        access_payload = decode_token(credentials.credentials, require_type="access")
        if access_payload:
            await deny_token(access_payload.get("jti"),
                             token_remaining_seconds(access_payload))

    # Refresh token from the body — the important one (7-day life).
    if body.refresh_token:
        refresh_payload = decode_token(body.refresh_token, require_type="refresh")
        if refresh_payload:
            await deny_token(refresh_payload.get("jti"),
                             token_remaining_seconds(refresh_payload))

    return {"message": "Logged out."}
