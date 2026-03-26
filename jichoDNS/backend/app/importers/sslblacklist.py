"""
Abuse.ch SSL Blacklist importer.

SSL Blacklist (SSLBL) tracks malicious SSL certificates and JA3 fingerprints.
"""

import aiohttp
import csv
import io
from datetime import datetime
from typing import List, Any, Optional

from .base import BaseImporter, Indicator, IndicatorType, ThreatType


class SSLBlacklistImporter(BaseImporter):
    """
    Import malicious SSL certificate SHA1 fingerprints from SSLBL.
    
    Feed URL: https://sslbl.abuse.ch/blacklist/sslblacklist.csv
    Updates: Continuous (we poll every 15 minutes)
    Content: SHA1 fingerprints of malicious SSL certificates
    """
    
    name = "sslbl"
    url = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"
    update_interval_minutes = 15
    
    async def fetch(self) -> Any:
        """Fetch the SSL blacklist from abuse.ch."""
        async with aiohttp.ClientSession() as session:
            async with session.get(self.url, timeout=60) as response:
                response.raise_for_status()
                return await response.text()
    
    async def parse(self, raw_data: Any) -> List[Indicator]:
        """Parse SSL blacklist CSV data."""
        indicators = []
        
        # Parse CSV (skip comment lines starting with #)
        lines = [line for line in raw_data.strip().split("\n") if line and not line.startswith("#")]
        
        if not lines:
            return indicators
        
        for line in lines:
            try:
                # CSV format: Listingdate,SHA1,Listingreason
                parts = line.split(",", 2)
                if len(parts) < 3:
                    continue
                
                listing_date = parts[0].strip()
                sha1_hash = parts[1].strip()
                reason = parts[2].strip()
                
                if not sha1_hash or len(sha1_hash) != 40:
                    continue
                
                first_seen = self._parse_date(listing_date)
                
                # Extract malware name from reason
                malware = reason.replace(" C&C", "").replace(" C2", "").strip()
                
                tags = ["sslbl", "malicious-ssl", "c2"]
                if malware:
                    tags.append(malware.lower().replace(" ", "-"))
                
                indicators.append(Indicator(
                    indicator=sha1_hash,
                    indicator_type=IndicatorType.HASH_SHA1,
                    threat_type=ThreatType.C2,
                    source=self.name,
                    source_url="https://sslbl.abuse.ch/",
                    confidence=0.9,
                    tags=tags,
                    first_seen=first_seen,
                    last_seen=first_seen,
                    metadata={
                        "listing_reason": reason,
                        "malware": malware,
                        "ssl_cert_sha1": True,
                    },
                ))
                
            except Exception as e:
                self.logger.warning(f"Error parsing SSLBL row: {e}")
                continue
        
        return indicators
    
    def _parse_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse date string to datetime."""
        if not date_str:
            return None
        try:
            # Format: 2026-03-16 18:00:00
            return datetime.strptime(date_str.strip(), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass
        return None


class JA3FingerprintImporter(BaseImporter):
    """
    Import malicious JA3 fingerprints from SSLBL.
    
    Feed URL: https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv
    Updates: Continuous (we poll every 30 minutes)
    Content: JA3 fingerprints of known malware
    """
    
    name = "sslbl_ja3"
    url = "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv"
    update_interval_minutes = 30
    
    async def fetch(self) -> Any:
        """Fetch the JA3 fingerprint list from abuse.ch."""
        async with aiohttp.ClientSession() as session:
            async with session.get(self.url, timeout=60) as response:
                response.raise_for_status()
                return await response.text()
    
    async def parse(self, raw_data: Any) -> List[Indicator]:
        """Parse JA3 fingerprint CSV data."""
        indicators = []
        now = datetime.utcnow()
        
        # Parse CSV (skip comment lines starting with #)
        lines = [line for line in raw_data.strip().split("\n") if line and not line.startswith("#")]
        
        if not lines:
            return indicators
        
        for line in lines:
            try:
                # CSV format: ja3_md5,firstseen,lastseen,malware
                parts = line.split(",")
                if len(parts) < 4:
                    continue
                
                ja3_hash = parts[0].strip()
                first_seen_str = parts[1].strip()
                last_seen_str = parts[2].strip()
                malware = parts[3].strip()
                
                if not ja3_hash or len(ja3_hash) != 32:
                    continue
                
                first_seen = self._parse_date(first_seen_str)
                last_seen = self._parse_date(last_seen_str)
                
                tags = ["sslbl", "ja3", "fingerprint"]
                if malware:
                    tags.append(malware.lower().replace(".", "-"))
                
                indicators.append(Indicator(
                    indicator=ja3_hash,
                    indicator_type=IndicatorType.HASH_MD5,  # JA3 is MD5
                    threat_type=ThreatType.MALWARE,
                    source=self.name,
                    source_url="https://sslbl.abuse.ch/ja3-fingerprints/",
                    confidence=0.9,
                    tags=tags,
                    first_seen=first_seen or now,
                    last_seen=last_seen or first_seen or now,
                    metadata={
                        "malware": malware,
                        "ja3_fingerprint": True,
                    },
                ))
                
            except Exception as e:
                self.logger.warning(f"Error parsing JA3 row: {e}")
                continue
        
        return indicators
    
    def _parse_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse date string to datetime."""
        if not date_str:
            return None
        try:
            return datetime.strptime(date_str.strip(), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass
        try:
            return datetime.strptime(date_str.strip(), "%Y-%m-%d")
        except ValueError:
            pass
        return None
