"""
AlienVault OTX feed importer.

AlienVault Open Threat Exchange provides community-driven threat intelligence.
Free API access with registration.
"""

import aiohttp
import os
from datetime import datetime
from typing import List, Any, Optional

from .base import BaseImporter, Indicator, IndicatorType, ThreatType


class AlienVaultOTXImporter(BaseImporter):
    """
    Import IOCs from AlienVault OTX.
    
    Feed URL: https://otx.alienvault.com/api/v1/pulses/subscribed
    Updates: Real-time (we poll every 10 minutes)
    Content: Community IOCs from subscribed pulses
    
    Requires OTX_API_KEY environment variable.
    """
    
    name = "alienvault_otx"
    base_url = "https://otx.alienvault.com/api/v1"
    update_interval_minutes = 10
    
    def __init__(self):
        super().__init__()
        self.api_key = os.environ.get("OTX_API_KEY", "")
    
    async def fetch(self) -> Any:
        """Fetch recent pulses from AlienVault OTX."""
        if not self.api_key:
            raise ValueError("OTX_API_KEY environment variable not set")
        
        headers = {
            "X-OTX-API-KEY": self.api_key,
            "Accept": "application/json",
        }
        
        all_indicators = []
        
        async with aiohttp.ClientSession() as session:
            # Get subscribed pulses modified in last day
            url = f"{self.base_url}/pulses/subscribed?modified_since=1 days ago&limit=50"
            
            async with session.get(url, headers=headers, timeout=120) as response:
                response.raise_for_status()
                data = await response.json()
                
                pulses = data.get("results", [])
                self.logger.info(f"Fetched {len(pulses)} pulses from OTX")
                
                # For each pulse, extract indicators
                for pulse in pulses:
                    pulse_indicators = pulse.get("indicators", [])
                    for ind in pulse_indicators:
                        ind["pulse_name"] = pulse.get("name", "")
                        ind["pulse_id"] = pulse.get("id", "")
                        ind["pulse_tags"] = pulse.get("tags", [])
                        ind["pulse_created"] = pulse.get("created", "")
                        ind["pulse_modified"] = pulse.get("modified", "")
                    all_indicators.extend(pulse_indicators)
        
        return all_indicators
    
    async def parse(self, raw_data: Any) -> List[Indicator]:
        """Parse OTX indicator data."""
        indicators = []
        
        for item in raw_data:
            try:
                ioc_value = item.get("indicator", "")
                ioc_type = item.get("type", "").lower()
                
                if not ioc_value:
                    continue
                
                # Map OTX type to our type
                indicator_type = self._map_ioc_type(ioc_type)
                if not indicator_type:
                    continue
                
                # Determine threat type from context
                threat_type = self._infer_threat_type(item)
                
                # Parse dates
                created = self._parse_date(item.get("created") or item.get("pulse_created"))
                
                # Build tags
                tags = ["alienvault", "otx"]
                if item.get("pulse_tags"):
                    tags.extend([t.lower() for t in item["pulse_tags"][:5]])
                
                indicators.append(Indicator(
                    indicator=ioc_value,
                    indicator_type=indicator_type,
                    threat_type=threat_type,
                    source=self.name,
                    source_url=f"https://otx.alienvault.com/pulse/{item.get('pulse_id', '')}",
                    confidence=0.7,
                    tags=list(set(tags)),
                    first_seen=created,
                    last_seen=created,
                    metadata={
                        "pulse_name": item.get("pulse_name"),
                        "pulse_id": item.get("pulse_id"),
                        "otx_id": item.get("id"),
                        "description": item.get("description", "")[:200],
                    },
                ))
                
            except Exception as e:
                self.logger.warning(f"Error parsing OTX item: {e}")
                continue
        
        return indicators
    
    def _map_ioc_type(self, ioc_type: str) -> Optional[IndicatorType]:
        """Map OTX indicator type to our IndicatorType enum."""
        mapping = {
            "domain": IndicatorType.DOMAIN,
            "hostname": IndicatorType.DOMAIN,
            "ipv4": IndicatorType.IP,
            "ipv6": IndicatorType.IP,
            "url": IndicatorType.URL,
            "uri": IndicatorType.URL,
            "filehash-md5": IndicatorType.HASH_MD5,
            "filehash-sha1": IndicatorType.HASH_SHA1,
            "filehash-sha256": IndicatorType.HASH_SHA256,
        }
        return mapping.get(ioc_type)
    
    def _infer_threat_type(self, item: dict) -> ThreatType:
        """Infer threat type from pulse context."""
        pulse_name = (item.get("pulse_name") or "").lower()
        tags = [t.lower() for t in (item.get("pulse_tags") or [])]
        description = (item.get("description") or "").lower()
        
        text = f"{pulse_name} {' '.join(tags)} {description}"
        
        if any(w in text for w in ["c2", "c&c", "command and control", "botnet", "rat"]):
            return ThreatType.C2
        if any(w in text for w in ["phish", "credential", "login"]):
            return ThreatType.PHISHING
        if any(w in text for w in ["malware", "trojan", "ransomware", "payload"]):
            return ThreatType.MALWARE
        if any(w in text for w in ["exfil", "data theft", "stealer"]):
            return ThreatType.EXFILTRATION
        
        return ThreatType.UNKNOWN
    
    def _parse_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse date string to datetime."""
        if not date_str:
            return None
        try:
            return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        except ValueError:
            pass
        try:
            return datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%f")
        except ValueError:
            pass
        try:
            return datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            pass
        return None
