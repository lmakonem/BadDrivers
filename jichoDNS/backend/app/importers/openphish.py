"""
OpenPhish feed importer.

OpenPhish provides a free community phishing URL feed.
"""

import aiohttp
from datetime import datetime
from typing import List, Any
from urllib.parse import urlparse

from .base import BaseImporter, Indicator, IndicatorType, ThreatType


class OpenPhishImporter(BaseImporter):
    """
    Import phishing URLs from OpenPhish.
    
    Feed URL: https://openphish.com/feed.txt
    Updates: Every 12 hours
    Content: Active phishing URLs (free community feed)
    """
    
    name = "openphish"
    url = "https://openphish.com/feed.txt"
    update_interval_minutes = 30  # Check every 30 minutes
    
    async def fetch(self) -> Any:
        """Fetch the text feed from OpenPhish."""
        headers = {
            "User-Agent": "JichoDNS/1.0 (Africa DNS Threat Intelligence)"
        }
        async with aiohttp.ClientSession() as session:
            async with session.get(self.url, headers=headers, timeout=60) as response:
                response.raise_for_status()
                return await response.text()
    
    async def parse(self, raw_data: Any) -> List[Indicator]:
        """Parse OpenPhish text data (one URL per line)."""
        indicators = []
        now = datetime.utcnow()
        
        if not isinstance(raw_data, str):
            self.logger.warning("OpenPhish returned unexpected format")
            return indicators
        
        lines = raw_data.strip().split("\n")
        
        for line in lines:
            url = line.strip()
            if not url or url.startswith("#"):
                continue
            
            try:
                # Extract domain from URL
                parsed = urlparse(url)
                domain = parsed.netloc
                if ":" in domain:
                    domain = domain.split(":")[0]
                
                # Create URL indicator
                indicators.append(Indicator(
                    indicator=url,
                    indicator_type=IndicatorType.URL,
                    threat_type=ThreatType.PHISHING,
                    source=self.name,
                    source_url="https://openphish.com/",
                    confidence=0.85,
                    tags=["openphish", "phishing"],
                    first_seen=now,
                    last_seen=now,
                ))
                
                # Also create domain indicator
                if domain and not self._is_ip(domain):
                    indicators.append(Indicator(
                        indicator=domain,
                        indicator_type=IndicatorType.DOMAIN,
                        threat_type=ThreatType.PHISHING,
                        source=self.name,
                        confidence=0.75,
                        tags=["openphish", "phishing"],
                        first_seen=now,
                        last_seen=now,
                    ))
                    
            except Exception as e:
                self.logger.warning(f"Error parsing OpenPhish URL: {e}")
                continue
        
        return indicators
    
    def _is_ip(self, s: str) -> bool:
        """Check if string is an IP address."""
        parts = s.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
