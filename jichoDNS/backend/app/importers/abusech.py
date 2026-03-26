"""
Abuse.ch feed importers.

Abuse.ch provides several free threat intelligence feeds:
- URLhaus: Malicious URLs
- ThreatFox: IOCs for malware
- Feodo Tracker: Botnet C2 servers
"""

import aiohttp
from datetime import datetime
from typing import List, Any, Optional
from urllib.parse import urlparse

from .base import BaseImporter, Indicator, IndicatorType, ThreatType


class URLhausImporter(BaseImporter):
    """
    Import malicious URLs from URLhaus (abuse.ch).
    
    Feed URL: https://urlhaus.abuse.ch/downloads/json_recent/
    Updates: Every 5 minutes
    Content: Recently added malicious URLs
    """
    
    name = "urlhaus"
    url = "https://urlhaus.abuse.ch/downloads/json_recent/"
    update_interval_minutes = 5
    
    async def fetch(self) -> Any:
        """Fetch the JSON feed from URLhaus."""
        async with aiohttp.ClientSession() as session:
            async with session.get(self.url, timeout=60) as response:
                response.raise_for_status()
                return await response.json()
    
    async def parse(self, raw_data: Any) -> List[Indicator]:
        """Parse URLhaus JSON data."""
        indicators = []
        
        # URLhaus returns a dict where keys are IDs and values are lists with one item
        if isinstance(raw_data, dict):
            items = []
            for url_id, url_list in raw_data.items():
                if isinstance(url_list, list) and url_list:
                    item = url_list[0]
                    item["id"] = url_id
                    items.append(item)
        else:
            items = raw_data
        
        for item in items:
            try:
                url = item.get("url", "")
                if not url:
                    continue
                
                # Extract domain from URL
                parsed = urlparse(url)
                domain = parsed.netloc
                # Remove port if present
                if ":" in domain:
                    domain = domain.split(":")[0]
                
                # Determine threat type
                threat_type = self._map_threat_type(item.get("threat", ""))
                
                # Parse dates
                first_seen = self._parse_date(item.get("dateadded"))
                last_seen = self._parse_date(item.get("last_online")) or first_seen
                
                # Create URL indicator
                indicators.append(Indicator(
                    indicator=url,
                    indicator_type=IndicatorType.URL,
                    threat_type=threat_type,
                    source=self.name,
                    source_url=item.get("urlhaus_link", f"https://urlhaus.abuse.ch/url/{item.get('id', '')}"),
                    confidence=0.8,
                    tags=self._build_tags(item),
                    first_seen=first_seen,
                    last_seen=last_seen,
                    metadata={
                        "urlhaus_id": item.get("id"),
                        "url_status": item.get("url_status"),
                        "threat": item.get("threat"),
                        "reporter": item.get("reporter"),
                    },
                ))
                
                # Also create domain indicator if valid (not an IP)
                if domain and not self._is_ip(domain):
                    indicators.append(Indicator(
                        indicator=domain,
                        indicator_type=IndicatorType.DOMAIN,
                        threat_type=threat_type,
                        source=self.name,
                        confidence=0.7,
                        tags=self._build_tags(item),
                        first_seen=first_seen,
                        last_seen=last_seen,
                    ))
                    
            except Exception as e:
                self.logger.warning(f"Error parsing URLhaus item: {e}")
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
    
    def _map_threat_type(self, threat: str) -> ThreatType:
        """Map URLhaus threat type to our ThreatType enum."""
        threat_lower = threat.lower()
        if "c2" in threat_lower or "c&c" in threat_lower:
            return ThreatType.C2
        if "phish" in threat_lower:
            return ThreatType.PHISHING
        if "malware" in threat_lower:
            return ThreatType.MALWARE
        return ThreatType.UNKNOWN
    
    def _build_tags(self, item: dict) -> List[str]:
        """Build tags from item data."""
        tags = ["urlhaus"]
        if item.get("threat"):
            tags.append(item["threat"].lower().replace("_", "-"))
        if item.get("tags"):
            if isinstance(item["tags"], list):
                tags.extend(t.lower() for t in item["tags"])
            elif isinstance(item["tags"], str):
                tags.extend(t.strip().lower() for t in item["tags"].split(","))
        return list(set(tags))
    
    def _parse_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse date string to datetime."""
        if not date_str:
            return None
        try:
            # Try ISO format first
            return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        except ValueError:
            pass
        try:
            # URLhaus format: "2026-03-16 18:03:19 UTC"
            return datetime.strptime(date_str.replace(" UTC", ""), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass
        return None


class ThreatFoxImporter(BaseImporter):
    """
    Import IOCs from ThreatFox (abuse.ch).
    
    Feed URL: https://threatfox.abuse.ch/export/json/recent/
    Updates: Every 5 minutes
    Content: Recently added IOCs (IPs, domains, URLs, hashes)
    """
    
    name = "threatfox"
    url = "https://threatfox.abuse.ch/export/json/recent/"
    update_interval_minutes = 5
    
    async def fetch(self) -> Any:
        """Fetch the JSON feed from ThreatFox."""
        async with aiohttp.ClientSession() as session:
            async with session.get(self.url, timeout=60) as response:
                response.raise_for_status()
                return await response.json()
    
    async def parse(self, raw_data: Any) -> List[Indicator]:
        """Parse ThreatFox JSON data."""
        indicators = []
        
        # ThreatFox returns a dict where keys are IDs and values are lists with one item
        if isinstance(raw_data, dict):
            items = []
            for ioc_id, ioc_list in raw_data.items():
                if isinstance(ioc_list, list) and ioc_list:
                    item = ioc_list[0]
                    item["id"] = ioc_id
                    items.append(item)
        else:
            items = raw_data
        
        for item in items:
            try:
                ioc = item.get("ioc_value", "") or item.get("ioc", "")
                ioc_type = item.get("ioc_type", "").lower()
                
                if not ioc:
                    continue
                
                # Map IOC type
                indicator_type = self._map_ioc_type(ioc_type)
                if not indicator_type:
                    continue
                
                # Determine threat type
                threat_type = self._map_threat_type(item.get("threat_type", ""))
                
                # Parse dates
                first_seen = self._parse_date(item.get("first_seen_utc") or item.get("first_seen"))
                last_seen = self._parse_date(item.get("last_seen_utc") or item.get("last_seen")) or first_seen
                
                # Get confidence level
                confidence = item.get("confidence_level", 50)
                if isinstance(confidence, int):
                    confidence = min(confidence / 100, 1.0)
                
                indicators.append(Indicator(
                    indicator=ioc,
                    indicator_type=indicator_type,
                    threat_type=threat_type,
                    source=self.name,
                    source_url=f"https://threatfox.abuse.ch/ioc/{item.get('id', '')}",
                    confidence=confidence,
                    tags=self._build_tags(item),
                    first_seen=first_seen,
                    last_seen=last_seen,
                    metadata={
                        "threatfox_id": item.get("id"),
                        "malware": item.get("malware"),
                        "malware_alias": item.get("malware_alias"),
                        "malware_printable": item.get("malware_printable"),
                        "reporter": item.get("reporter"),
                    },
                ))
                
            except Exception as e:
                self.logger.warning(f"Error parsing ThreatFox item: {e}")
                continue
        
        return indicators
    
    def _map_ioc_type(self, ioc_type: str) -> Optional[IndicatorType]:
        """Map ThreatFox IOC type to our IndicatorType enum."""
        mapping = {
            "domain": IndicatorType.DOMAIN,
            "ip:port": IndicatorType.IP,
            "ip": IndicatorType.IP,
            "url": IndicatorType.URL,
            "md5_hash": IndicatorType.HASH_MD5,
            "sha256_hash": IndicatorType.HASH_SHA256,
            "sha1_hash": IndicatorType.HASH_SHA1,
        }
        return mapping.get(ioc_type)
    
    def _map_threat_type(self, threat: str) -> ThreatType:
        """Map ThreatFox threat type to our ThreatType enum."""
        threat_lower = threat.lower()
        if "c2" in threat_lower or "botnet" in threat_lower:
            return ThreatType.C2
        if "payload" in threat_lower:
            return ThreatType.MALWARE
        return ThreatType.MALWARE  # Default to malware for ThreatFox
    
    def _build_tags(self, item: dict) -> List[str]:
        """Build tags from item data."""
        tags = ["threatfox"]
        if item.get("malware"):
            tags.append(item["malware"].lower().replace(".", "-"))
        if item.get("tags"):
            if isinstance(item["tags"], list):
                tags.extend(t.lower() for t in item["tags"])
            elif isinstance(item["tags"], str):
                tags.extend(t.strip().lower() for t in item["tags"].split(","))
        return list(set(tags))
    
    def _parse_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse date string to datetime."""
        if not date_str:
            return None
        try:
            return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        except ValueError:
            pass
        try:
            # ThreatFox format: "2026-03-16 18:09:55"
            return datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass
        try:
            return datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S UTC")
        except ValueError:
            pass
        return None


class FeodoTrackerImporter(BaseImporter):
    """
    Import botnet C2 servers from Feodo Tracker (abuse.ch).

    Uses the full JSON feed (not the recommended-only blocklist) to capture
    all known Feodo/Dridex/Emotet/QakBot/AsyncRAT C2 servers including
    offline ones that may come back online.

    Feed URL: https://feodotracker.abuse.ch/downloads/ipblocklist.json
    Updates: Every 5 minutes
    """

    name = "feodotracker"
    # Full feed — not just "recommended" which only has 2 entries
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    update_interval_minutes = 5

    async def fetch(self) -> Any:
        """Fetch the JSON feed from Feodo Tracker."""
        async with aiohttp.ClientSession() as session:
            async with session.get(
                self.url,
                timeout=aiohttp.ClientTimeout(total=60),
                headers={"User-Agent": "JichoSec-ThreatIntel/1.0"},
            ) as response:
                response.raise_for_status()
                return await response.json(content_type=None)
    
    async def parse(self, raw_data: Any) -> List[Indicator]:
        """Parse Feodo Tracker JSON data."""
        indicators = []
        
        for item in raw_data:
            try:
                ip = item.get("ip_address", "")
                if not ip:
                    continue
                
                # Parse dates
                first_seen = self._parse_date(item.get("first_seen"))
                last_seen = self._parse_date(item.get("last_online")) or first_seen
                
                indicators.append(Indicator(
                    indicator=ip,
                    indicator_type=IndicatorType.IP,
                    threat_type=ThreatType.C2,
                    source=self.name,
                    source_url="https://feodotracker.abuse.ch/",
                    confidence=0.9,  # Feodo Tracker is high confidence
                    tags=self._build_tags(item),
                    first_seen=first_seen,
                    last_seen=last_seen,
                    metadata={
                        "port": item.get("port"),
                        "malware": item.get("malware"),
                        "status": item.get("status"),
                        "hostname": item.get("hostname"),
                        "as_number": item.get("as_number"),
                        "as_name": item.get("as_name"),
                        "country": item.get("country"),
                    },
                ))
                
                # Also create domain indicator if hostname exists
                hostname = item.get("hostname")
                if hostname and hostname != ip:
                    indicators.append(Indicator(
                        indicator=hostname,
                        indicator_type=IndicatorType.DOMAIN,
                        threat_type=ThreatType.C2,
                        source=self.name,
                        confidence=0.85,
                        tags=self._build_tags(item),
                        first_seen=first_seen,
                        last_seen=last_seen,
                    ))
                    
            except Exception as e:
                self.logger.warning(f"Error parsing Feodo item: {e}")
                continue
        
        return indicators
    
    def _build_tags(self, item: dict) -> List[str]:
        """Build tags from item data."""
        tags = ["feodotracker", "c2", "botnet"]
        if item.get("malware"):
            tags.append(item["malware"].lower())
        if item.get("country"):
            tags.append(f"country:{item['country'].lower()}")
        return list(set(tags))
    
    def _parse_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse date string to datetime."""
        if not date_str:
            return None
        try:
            return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        except ValueError:
            pass
        try:
            return datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass
        return None
