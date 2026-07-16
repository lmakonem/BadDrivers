"""
Security utilities: password hashing, JWT tokens, API key management.
"""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings


# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)


# Pre-computed bcrypt hash of a random value. Verifying a submitted password
# against this burns ~one bcrypt of CPU without ever matching, so the login
# path takes the same time whether or not the account exists — this defeats
# user-enumeration by response timing.
_DUMMY_PASSWORD_HASH = pwd_context.hash(secrets.token_urlsafe(32))


def dummy_verify() -> None:
    """Run one bcrypt verification and discard the result (timing equalizer)."""
    pwd_context.verify("timing-equalizer", _DUMMY_PASSWORD_HASH)


# JWT Tokens
def create_access_token(
    data: dict,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create a JWT access token."""
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES
        )
    
    # jti: a unique token id so a specific token can be revoked (logout) via the
    # Redis denylist without rotating SECRET_KEY (which would kill every session).
    to_encode.update({"exp": expire, "type": "access", "jti": secrets.token_hex(16)})
    if settings.JWT_AUDIENCE:
        to_encode["aud"] = settings.JWT_AUDIENCE
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(data: dict) -> str:
    """Create a JWT refresh token."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(
        days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS
    )
    to_encode.update({"exp": expire, "type": "refresh", "jti": secrets.token_hex(16)})
    if settings.JWT_AUDIENCE:
        to_encode["aud"] = settings.JWT_AUDIENCE
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def token_remaining_seconds(payload: dict) -> int:
    """
    Seconds until a decoded token's `exp`, clamped to >= 0. Used to bound a
    denylist entry's TTL so it self-expires exactly when the token would anyway
    (a revoked token never needs to outlive its own expiry in Redis).
    """
    exp = payload.get("exp")
    if not exp:
        return 0
    remaining = int(exp) - int(datetime.now(timezone.utc).timestamp())
    return max(remaining, 0)


def create_email_verification_token(user_id: int, email: str) -> str:
    """
    Create a short-lived, single-purpose JWT proving control of an email inbox.

    Carries type="email_verify" so it can never be replayed as an access or
    refresh token (decode_token enforces the type claim), and embeds the email
    it was issued for so verification can be invalidated by an address change.
    """
    expire = datetime.now(timezone.utc) + timedelta(
        hours=settings.EMAIL_VERIFICATION_EXPIRE_HOURS
    )
    to_encode = {
        "sub": str(user_id),
        "email": email,
        "exp": expire,
        "type": "email_verify",
    }
    if settings.JWT_AUDIENCE:
        to_encode["aud"] = settings.JWT_AUDIENCE
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_token(
    token: str,
    require_type: Optional[str] = None,
) -> Optional[dict]:
    """
    Decode and validate a JWT.

    Args:
        token: the encoded JWT.
        require_type: if given (e.g. "access" or "refresh"), the token's "type"
            claim must match exactly or None is returned.

    Returns the claims dict, or None if the signature/expiry/audience/type is invalid.
    """
    audience = settings.JWT_AUDIENCE or None
    options = {} if audience else {"verify_aud": False}
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            audience=audience,
            options=options,
        )
    except JWTError:
        return None

    if require_type is not None and payload.get("type") != require_type:
        return None
    return payload


def get_token_subject(payload: dict) -> Optional[int]:
    """
    Safely extract the integer user id from a token's "sub" claim.

    Returns None if "sub" is missing or not an integer (guards int() against
    TypeError/ValueError so a malformed token yields 401, never a 500).
    """
    sub = payload.get("sub")
    if sub is None:
        return None
    try:
        return int(sub)
    except (TypeError, ValueError):
        return None


# API Keys
def generate_api_key() -> tuple[str, str, str]:
    """
    Generate a new API key.
    
    Returns:
        tuple: (full_key, key_prefix, key_hash)
        - full_key: The complete API key to give to the user (shown only once)
        - key_prefix: First 12 chars for identification (jdns_live_xxx)
        - key_hash: SHA-256 hash for storage
    """
    # Generate 32 random bytes = 64 hex chars
    random_part = secrets.token_hex(32)
    
    # Format: jdns_live_<random>
    full_key = f"jdns_live_{random_part}"
    key_prefix = full_key[:12]  # jdns_live_xx
    key_hash = hashlib.sha256(full_key.encode()).hexdigest()
    
    return full_key, key_prefix, key_hash


def hash_api_key(api_key: str) -> str:
    """Hash an API key for comparison."""
    return hashlib.sha256(api_key.encode()).hexdigest()


def get_api_key_prefix(api_key: str) -> str:
    """Extract the prefix from an API key for identification."""
    return api_key[:12] if len(api_key) >= 12 else api_key
