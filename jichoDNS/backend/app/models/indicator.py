"""Indicator models for threat intelligence."""

from datetime import datetime
from typing import Optional, List
from sqlalchemy import String, Float, Boolean, Integer, Text, ForeignKey, Index, ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import JSONB

from .base import Base, TimestampMixin


class Indicator(Base, TimestampMixin):
    """
    Indicator of Compromise (IOC) model.
    
    Stores domains, IPs, URLs, and hashes from threat feeds.
    """
    
    __tablename__ = "indicators"
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    
    # Core indicator data
    indicator: Mapped[str] = mapped_column(String(2048), nullable=False, index=True)
    indicator_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    threat_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    
    # Scoring
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    
    # Source information
    source: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    source_url: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    
    # Timing
    first_seen: Mapped[Optional[datetime]] = mapped_column(nullable=True)
    last_seen: Mapped[Optional[datetime]] = mapped_column(nullable=True, index=True)
    
    # Geographic/Network context
    country_code: Mapped[Optional[str]] = mapped_column(String(2), nullable=True, index=True)
    asn: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, index=True)
    asn_org: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    
    # Tags and extra data
    tags: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String), nullable=True)
    extra_data: Mapped[Optional[dict]] = mapped_column("metadata", JSONB, nullable=True)
    
    # Status
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    
    # Relationships
    scores: Mapped[List["IndicatorScore"]] = relationship(back_populates="indicator_rel")
    
    __table_args__ = (
        Index("ix_indicators_indicator_source", "indicator", "source", unique=True),
        Index("ix_indicators_threat_country", "threat_type", "country_code"),
        Index("ix_indicators_active_last_seen", "active", "last_seen"),
    )
    
    def __repr__(self) -> str:
        return f"<Indicator {self.indicator_type}:{self.indicator[:50]}>"


class IndicatorScore(Base, TimestampMixin):
    """
    ML-generated scores for indicators.
    
    Stores probability scores from the Vertex AI classifier.
    """
    
    __tablename__ = "indicator_scores"
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    indicator_id: Mapped[int] = mapped_column(ForeignKey("indicators.id"), nullable=False, index=True)
    
    # ML Scores (probabilities)
    c2_probability: Mapped[float] = mapped_column(Float, default=0.0)
    exfil_probability: Mapped[float] = mapped_column(Float, default=0.0)
    phishing_probability: Mapped[float] = mapped_column(Float, default=0.0)
    benign_probability: Mapped[float] = mapped_column(Float, default=0.0)
    
    # Model info
    model_version: Mapped[str] = mapped_column(String(64), nullable=True)
    
    # Analysis features
    entropy: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    dga_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    is_dga: Mapped[bool] = mapped_column(Boolean, default=False)
    has_impossible_ngrams: Mapped[bool] = mapped_column(Boolean, default=False)
    
    # Relationship
    indicator_rel: Mapped["Indicator"] = relationship(back_populates="scores")
    
    def __repr__(self) -> str:
        return f"<IndicatorScore indicator_id={self.indicator_id}>"
