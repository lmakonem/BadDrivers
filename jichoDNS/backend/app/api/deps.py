"""
Shared FastAPI dependencies for authentication and authorization.
"""

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import decode_token, get_token_subject
from app.core.ratelimit import is_token_denied
from app.models.user import User

# HTTP Bearer scheme — expects "Authorization: Bearer <token>"
bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Validate the JWT access token and return the authenticated User.

    Raises 401 if:
      - No token provided
      - Token is invalid or expired
      - Token type is not "access"
      - User not found or inactive
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_token(credentials.credentials, require_type="access")
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if await is_token_denied(payload.get("jti")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = get_token_subject(payload)
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


async def get_current_admin(
    current_user: User = Depends(get_current_user),
) -> User:
    """Require the current user to be an admin."""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required.",
        )
    return current_user


# ── Subscription tier gating ──────────────────────────────────────────────────
# Tier ordering: free < professional < enterprise. Admins bypass all tier gates.
TIER_RANK = {
    "free": 0,
    "professional": 1,
    "enterprise": 2,
}


def require_tier(min_tier: str):
    """
    Build a FastAPI dependency that requires the current user's subscription
    tier to be at least ``min_tier`` (or the user to be an admin).

    Tier rank: free(0) < professional(1) < enterprise(2). Unknown/None tiers
    are treated as free. Admins always pass. Raises 403 otherwise.
    """
    required_rank = TIER_RANK.get(min_tier, 0)

    async def _tier_dependency(
        current_user: User = Depends(get_current_user),
    ) -> User:
        if current_user.is_admin:
            return current_user
        user_rank = TIER_RANK.get(current_user.tier or "free", 0)
        if user_rank < required_rank:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Upgrade to {min_tier} to access this.",
            )
        return current_user

    return _tier_dependency


async def get_optional_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User | None:
    """
    Return the current user if a valid token is provided, or None otherwise.
    Useful for endpoints that behave differently for authed vs anon users.
    """
    if credentials is None:
        return None

    payload = decode_token(credentials.credentials, require_type="access")
    if not payload:
        return None

    if await is_token_denied(payload.get("jti")):
        return None

    user_id = get_token_subject(payload)
    if user_id is None:
        return None

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        return None

    return user
