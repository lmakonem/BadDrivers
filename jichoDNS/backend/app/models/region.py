"""Region models for geographic threat data."""

from datetime import datetime
from typing import Optional
from sqlalchemy import String, Float, Integer, Index
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin


class RegionScore(Base, TimestampMixin):
    """
    Aggregated threat scores by region (country or ASN).
    
    Updated periodically by aggregation workers.
    """
    
    __tablename__ = "region_scores"
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    
    # Region identification
    region_type: Mapped[str] = mapped_column(String(16), nullable=False)  # 'country' or 'asn'
    region_id: Mapped[str] = mapped_column(String(32), nullable=False)  # country code or ASN number
    region_name: Mapped[str] = mapped_column(String(256), nullable=False)
    
    # Risk scores (0.0 - 1.0)
    c2_risk: Mapped[float] = mapped_column(Float, default=0.0)
    exfil_risk: Mapped[float] = mapped_column(Float, default=0.0)
    phishing_risk: Mapped[float] = mapped_column(Float, default=0.0)
    overall_risk: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    
    # Indicator counts
    indicator_count: Mapped[int] = mapped_column(Integer, default=0)
    c2_count: Mapped[int] = mapped_column(Integer, default=0)
    exfil_count: Mapped[int] = mapped_column(Integer, default=0)
    phishing_count: Mapped[int] = mapped_column(Integer, default=0)
    
    # Geographic data (for map rendering)
    latitude: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    longitude: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    
    # For ASNs - parent country
    country_code: Mapped[Optional[str]] = mapped_column(String(2), nullable=True, index=True)
    
    # Timestamp of the aggregation
    aggregated_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)
    
    __table_args__ = (
        Index("ix_region_scores_type_id", "region_type", "region_id", unique=True),
        Index("ix_region_scores_type_risk", "region_type", "overall_risk"),
    )
    
    def __repr__(self) -> str:
        return f"<RegionScore {self.region_type}:{self.region_id}>"
