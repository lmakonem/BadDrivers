"""User and API key models."""

from datetime import datetime
from typing import Optional, List
from sqlalchemy import String, Boolean, Integer, DateTime, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin


class User(Base, TimestampMixin):
    """
    User account model.
    
    Supports both registered users and API-only accounts.
    """
    
    __tablename__ = "users"
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    
    # Identity
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    hashed_password: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    
    # Profile
    name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    organization: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    
    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    
    # Subscription tier: free, professional, enterprise
    tier: Mapped[str] = mapped_column(String(32), default="free")
    
    # API limits
    daily_api_limit: Mapped[int] = mapped_column(Integer, default=100)
    monthly_api_limit: Mapped[int] = mapped_column(Integer, default=3000)
    
    # Usage tracking
    api_calls_today: Mapped[int] = mapped_column(Integer, default=0)
    api_calls_month: Mapped[int] = mapped_column(Integer, default=0)
    last_api_call: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    
    # Relationships
    api_keys: Mapped[List["APIKey"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    
    def __repr__(self) -> str:
        return f"<User {self.email}>"


class APIKey(Base, TimestampMixin):
    """
    API key model for programmatic access.
    
    Keys are hashed before storage for security.
    """
    
    __tablename__ = "api_keys"
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    
    # Key data (prefix is stored for identification, hash for verification)
    key_prefix: Mapped[str] = mapped_column(String(8), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    
    # Metadata
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    
    # Permissions/Scopes
    scopes: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)  # comma-separated
    
    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    
    # Expiration
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    
    # Usage tracking
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    usage_count: Mapped[int] = mapped_column(Integer, default=0)
    
    # Relationship
    user: Mapped["User"] = relationship(back_populates="api_keys")
    
    __table_args__ = (
        Index("ix_api_keys_prefix_active", "key_prefix", "is_active"),
    )
    
    def __repr__(self) -> str:
        return f"<APIKey {self.key_prefix}...>"
