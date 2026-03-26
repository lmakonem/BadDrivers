"""
AbuseIPDB feed importer.

AbuseIPDB provides IP reputation data from community reports.
Free tier: 1,000 lookups/day, blacklist endpoint available.
"""

import aiohttp
import os
from datetime import datetime
from typing import List, Any, Optional

from .base import BaseImporter, Indicator, IndicatorType, ThreatType


class AbuseIPDBImporter(BaseImporter):
    """
    Import malicious IPs from AbuseIPDB blacklist.
    
    Feed URL: https://api.abuseipdb.com/api/v2/blacklist
    Updates: Daily (we poll every hour)
    Content: IPs with high abuse confidence scores
    
    Requires ABUSEIPDB_API_KEY environment variable.
    """
    
    name = "abuseipdb"
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    update_interval_minutes = 60
    
    def __init__(self):
        super().__init__()
        self.api_key = os.environ.get("ABUSEIPDB_API_KEY", "")
    
    async def fetch(self) -> Any:
        """Fetch the blacklist from AbuseIPDB."""
        if not self.api_key:
            raise ValueError("ABUSEIPDB_API_KEY environment variable not set")
        
        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
        }
        
        params = {
            "confidenceMinimum": 90,  # Only high-confidence entries
            "limit": 10000,  # Max allowed
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.get(
                self.url, 
                headers=headers, 
                params=params, 
                timeout=120
            ) as response:
                response.raise_for_status()
                data = await response.json()
                return data.get("data", [])
    
    async def parse(self, raw_data: Any) -> List[Indicator]:
        """Parse AbuseIPDB blacklist data."""
        indicators = []
        now = datetime.utcnow()
        
        for item in raw_data:
            try:
                ip = item.get("ipAddress", "")
                if not ip:
                    continue
                
                # Get abuse confidence score (0-100)
                confidence = item.get("abuseConfidenceScore", 0) / 100.0
                
                # Determine threat type from category
                threat_type = self._infer_threat_type(item)
                
                # Parse last reported date
                last_reported = self._parse_date(item.get("lastReportedAt"))
                
                # Build tags
                tags = ["abuseipdb"]
                if item.get("countryCode"):
                    tags.append(f"country:{item['countryCode'].lower()}")
                if item.get("usageType"):
                    tags.append(item["usageType"].lower().replace(" ", "-"))
                
                indicators.append(Indicator(
                    indicator=ip,
                    indicator_type=IndicatorType.IP,
                    threat_type=threat_type,
                    source=self.name,
                    source_url=f"https://www.abuseipdb.com/check/{ip}",
                    confidence=confidence,
                    tags=tags,
                    first_seen=last_reported or now,
                    last_seen=last_reported or now,
                    metadata={
                        "abuse_confidence_score": item.get("abuseConfidenceScore"),
                        "country_code": item.get("countryCode"),
                        "usage_type": item.get("usageType"),
                        "isp": item.get("isp"),
                        "domain": item.get("domain"),
                        "total_reports": item.get("totalReports"),
                        "num_distinct_users": item.get("numDistinctUsers"),
                    },
                ))
                
            except Exception as e:
                self.logger.warning(f"Error parsing AbuseIPDB item: {e}")
                continue
        
        return indicators
    
    def _infer_threat_type(self, item: dict) -> ThreatType:
        """Infer threat type from AbuseIPDB data."""
        # AbuseIPDB doesn't provide detailed categorization in blacklist
        # Default to C2 for high-confidence malicious IPs
        usage_type = (item.get("usageType") or "").lower()
        
        if "hosting" in usage_type or "data center" in usage_type:
            return ThreatType.C2  # Likely C2 infrastructure
        
        return ThreatType.MALWARE
    
    def _parse_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse date string to datetime."""
        if not date_str:
            return None
        try:
            return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        except ValueError:
            pass
        try:
            return datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S+00:00")
        except ValueError:
            pass
        return None
