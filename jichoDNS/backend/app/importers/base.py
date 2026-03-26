"""
Base importer class for threat intelligence feeds.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class IndicatorType(str, Enum):
    """Types of indicators of compromise."""
    DOMAIN = "domain"
    IP = "ip"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"


class ThreatType(str, Enum):
    """Types of threats."""
    C2 = "c2"
    EXFILTRATION = "exfil"
    PHISHING = "phishing"
    MALWARE = "malware"
    BOTNET = "botnet"
    UNKNOWN = "unknown"


@dataclass
class Indicator:
    """Normalized indicator from any feed."""
    indicator: str
    indicator_type: IndicatorType
    threat_type: ThreatType
    source: str
    source_url: Optional[str] = None
    confidence: float = 0.5
    tags: List[str] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "indicator": self.indicator,
            "indicator_type": self.indicator_type.value,
            "threat_type": self.threat_type.value,
            "source": self.source,
            "source_url": self.source_url,
            "confidence": self.confidence,
            "tags": self.tags,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "metadata": self.metadata,
        }


@dataclass
class ImportResult:
    """Result of an import operation."""
    source: str
    success: bool
    total_fetched: int = 0
    total_imported: int = 0
    total_duplicates: int = 0
    total_errors: int = 0
    error_message: Optional[str] = None
    duration_seconds: float = 0.0
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "success": self.success,
            "total_fetched": self.total_fetched,
            "total_imported": self.total_imported,
            "total_duplicates": self.total_duplicates,
            "total_errors": self.total_errors,
            "error_message": self.error_message,
            "duration_seconds": self.duration_seconds,
            "timestamp": self.timestamp.isoformat(),
        }


class BaseImporter(ABC):
    """
    Base class for all feed importers.
    
    Subclasses must implement:
    - fetch(): Fetch raw data from the feed
    - parse(): Parse raw data into Indicator objects
    """
    
    name: str = "base"
    url: str = ""
    update_interval_minutes: int = 60
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.name}")
    
    @abstractmethod
    async def fetch(self) -> Any:
        """
        Fetch raw data from the feed source.
        
        Returns:
            Raw data from the feed (format depends on the feed)
        """
        pass
    
    @abstractmethod
    async def parse(self, raw_data: Any) -> List[Indicator]:
        """
        Parse raw data into normalized Indicator objects.
        
        Args:
            raw_data: Raw data from fetch()
            
        Returns:
            List of Indicator objects
        """
        pass
    
    async def import_feed(self) -> tuple[ImportResult, List[Indicator]]:
        """
        Full import pipeline: fetch, parse, and return results.
        
        Returns:
            Tuple of (ImportResult with statistics, List of indicators)
        """
        import time
        start_time = time.time()
        
        try:
            self.logger.info(f"Starting import from {self.name}")
            
            # Fetch data
            raw_data = await self.fetch()
            
            # Parse data
            indicators = await self.parse(raw_data)
            
            duration = time.time() - start_time
            
            self.logger.info(
                f"Import from {self.name} completed: "
                f"{len(indicators)} indicators in {duration:.2f}s"
            )
            
            return ImportResult(
                source=self.name,
                success=True,
                total_fetched=len(indicators),
                total_imported=len(indicators),
                duration_seconds=duration,
            ), indicators
            
        except Exception as e:
            duration = time.time() - start_time
            self.logger.error(f"Import from {self.name} failed: {e}")
            
            return ImportResult(
                source=self.name,
                success=False,
                error_message=str(e),
                duration_seconds=duration,
            ), []
