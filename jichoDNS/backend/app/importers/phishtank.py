"""
PhishTank feed importer.

PhishTank provides community-driven phishing URL data.
Note: PhishTank API access requires registration and has strict rate limits.
The public feed may be unreliable - we use OpenPhish as a backup.
"""

import aiohttp
import gzip
import io
from datetime import datetime
from typing import List, Any, Optional
from urllib.parse import urlparse
import os

from .base import BaseImporter, Indicator, IndicatorType, ThreatType


class PhishTankImporter(BaseImporter):
    """
    Import phishing URLs from PhishTank.
    
    Feed URL: http://data.phishtank.com/data/{api_key}/online-valid.json.gz
    Updates: Hourly (strict rate limit)
    Content: Verified phishing URLs
    
    Requires PHISHTANK_API_KEY environment variable for reliable access.
    Falls back to public feed which may be rate-limited.
    """
    
    name = "phishtank"
    update_interval_minutes = 60  # Hourly to avoid rate limits
    
    def __init__(self):
        super().__init__()
        self.api_key = os.environ.get("PHISHTANK_API_KEY", "")
    
    @property
    def url(self):
        if self.api_key:
            return f"http://data.phishtank.com/data/{self.api_key}/online-valid.json.gz"
        return "http://data.phishtank.com/data/online-valid.json.gz"
    
    async def fetch(self) -> Any:
        """Fetch the JSON feed from PhishTank."""
        headers = {
            "User-Agent": "phishtank/JichoDNS (https://jichodns.africa)",
            "Accept": "application/json, application/gzip",
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.url, headers=headers, timeout=180, allow_redirects=True) as response:
                    if response.status == 404:
                        self.logger.warning("PhishTank feed not available (404)")
                        return []
                    
                    if response.status == 509:
                        self.logger.warning("PhishTank rate limit exceeded")
                        return []
                    
                    response.raise_for_status()
                    
                    content_type = response.headers.get("content-type", "")
                    
                    # Check if response is JSON or gzipped
                    if "gzip" in content_type or self.url.endswith(".gz"):
                        data = await response.read()
                        try:
                            decompressed = gzip.decompress(data)
                            import json
                            return json.loads(decompressed.decode("utf-8"))
                        except gzip.BadGzipFile:
                            # Not actually gzipped, try as JSON
                            return await response.json()
                    else:
                        # Check if response is actually JSON (not an error page)
                        data = await response.read()
                        if data[:4] in [b'\xff\xd8\xff\xe0', b'\x89PNG', b'GIF8']:
                            self.logger.warning("PhishTank returned an image (likely error/captcha)")
                            return []
                        
                        import json
                        return json.loads(data.decode("utf-8"))
                        
        except aiohttp.ClientResponseError as e:
            self.logger.error(f"PhishTank HTTP error: {e.status}")
            return []
        except Exception as e:
            self.logger.error(f"PhishTank fetch error: {e}")
            return []
    
    async def parse(self, raw_data: Any) -> List[Indicator]:
        """Parse PhishTank JSON data."""
        indicators = []
        
        if not raw_data:
            return indicators
        
        # PhishTank returns a list of phishing entries
        if not isinstance(raw_data, list):
            self.logger.warning("PhishTank returned unexpected format")
            return indicators
        
        for item in raw_data:
            try:
                url = item.get("url", "")
                if not url:
                    continue
                
                # Extract domain from URL
                try:
                    parsed = urlparse(url)
                    domain = parsed.netloc
                    if ":" in domain:
                        domain = domain.split(":")[0]
                except Exception:
                    domain = None
                
                # Parse dates
                first_seen = self._parse_date(item.get("submission_time"))
                verified_at = self._parse_date(item.get("verification_time"))
                
                # Create URL indicator
                indicators.append(Indicator(
                    indicator=url,
                    indicator_type=IndicatorType.URL,
                    threat_type=ThreatType.PHISHING,
                    source=self.name,
                    source_url=item.get("phish_detail_url"),
                    confidence=0.9 if item.get("verified") == "yes" else 0.7,
                    tags=self._build_tags(item),
                    first_seen=first_seen,
                    last_seen=verified_at or first_seen,
                    metadata={
                        "phish_id": item.get("phish_id"),
                        "verified": item.get("verified"),
                        "target": item.get("target"),
                        "online": item.get("online"),
                    },
                ))
                
                # Also create domain indicator
                if domain and not self._is_ip(domain):
                    indicators.append(Indicator(
                        indicator=domain,
                        indicator_type=IndicatorType.DOMAIN,
                        threat_type=ThreatType.PHISHING,
                        source=self.name,
                        confidence=0.8 if item.get("verified") == "yes" else 0.6,
                        tags=self._build_tags(item),
                        first_seen=first_seen,
                        last_seen=verified_at or first_seen,
                    ))
                    
            except Exception as e:
                self.logger.warning(f"Error parsing PhishTank item: {e}")
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
    
    def _build_tags(self, item: dict) -> List[str]:
        """Build tags from item data."""
        tags = ["phishtank", "phishing"]
        if item.get("target"):
            target = item["target"].lower().replace(" ", "-")
            tags.append(f"target:{target}")
        if item.get("verified") == "yes":
            tags.append("verified")
        return list(set(tags))
    
    def _parse_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse date string to datetime."""
        if not date_str:
            return None
        try:
            # PhishTank format: "2026-03-16T18:00:00+00:00"
            return datetime.fromisoformat(date_str)
        except ValueError:
            pass
        try:
            return datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S+00:00")
        except ValueError:
            pass
        return None
