"""GeoIP service for IP address geolocation using local MaxMind database."""

import re
import logging
import os
from pathlib import Path
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

# Regex patterns for extracting IPs
IP_PATTERN = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

# Try to import geoip2
try:
    import geoip2.database
    import geoip2.errors
    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False
    logger.warning("geoip2 package not installed. GeoIP lookups will be disabled.")


class GeoIPService:
    """
    Service for IP geolocation using local MaxMind GeoLite2 database.
    
    Download the database from:
    https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
    
    Or use the direct download (requires license key):
    https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=YOUR_KEY&suffix=tar.gz
    """
    
    # Default paths to look for the database
    DB_PATHS = [
        "/app/data/GeoLite2-City.mmdb",
        "/data/GeoLite2-City.mmdb",
        "./data/GeoLite2-City.mmdb",
        os.path.expanduser("~/GeoLite2-City.mmdb"),
        "/usr/share/GeoIP/GeoLite2-City.mmdb",
    ]
    
    def __init__(self, db_path: Optional[str] = None):
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.reader = None
        self.db_path = None
        
        if not GEOIP2_AVAILABLE:
            logger.warning("GeoIP2 not available - lookups disabled")
            return
        
        # Find database file
        paths_to_check = [db_path] if db_path else self.DB_PATHS
        
        for path in paths_to_check:
            if path and Path(path).exists():
                try:
                    self.reader = geoip2.database.Reader(path)
                    self.db_path = path
                    logger.info(f"Loaded GeoIP database from {path}")
                    break
                except Exception as e:
                    logger.warning(f"Failed to load GeoIP database from {path}: {e}")
        
        if not self.reader:
            logger.warning(f"GeoIP database not found. Checked paths: {paths_to_check}")
    
    def extract_ip(self, value: str) -> Optional[str]:
        """Extract IP address from URL, domain, or raw IP."""
        match = IP_PATTERN.search(value)
        if match:
            ip = match.group(1)
            # Validate IP
            parts = ip.split('.')
            if all(0 <= int(p) <= 255 for p in parts):
                # Skip private/reserved IPs
                if self._is_public_ip(ip):
                    return ip
        return None
    
    def _is_public_ip(self, ip: str) -> bool:
        """Check if IP is public (not private/reserved)."""
        parts = [int(p) for p in ip.split('.')]
        
        # Private ranges
        if parts[0] == 10:  # 10.0.0.0/8
            return False
        if parts[0] == 172 and 16 <= parts[1] <= 31:  # 172.16.0.0/12
            return False
        if parts[0] == 192 and parts[1] == 168:  # 192.168.0.0/16
            return False
        if parts[0] == 127:  # Loopback
            return False
        if parts[0] == 0:  # Reserved
            return False
        if parts[0] >= 224:  # Multicast/Reserved
            return False
        
        return True
    
    def lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Look up geolocation for an IP address (synchronous).
        
        Returns:
            Dict with country_code, country, city, lat, lon, asn, org
            or None if lookup fails
        """
        # Check cache first
        if ip in self.cache:
            return self.cache[ip]
        
        if not self.reader:
            return None
        
        try:
            response = self.reader.city(ip)
            
            result = {
                "country_code": response.country.iso_code,
                "country": response.country.name,
                "city": response.city.name if response.city else None,
                "lat": response.location.latitude,
                "lon": response.location.longitude,
                "asn": None,  # City database doesn't include ASN
                "org": None,
            }
            
            # Cache the result
            self.cache[ip] = result
            return result
            
        except geoip2.errors.AddressNotFoundError:
            logger.debug(f"IP not found in GeoIP database: {ip}")
        except Exception as e:
            logger.debug(f"GeoIP lookup failed for {ip}: {e}")
        
        return None
    
    async def lookup_async(self, ip: str) -> Optional[Dict[str, Any]]:
        """Async wrapper for lookup (database is actually sync but fast)."""
        return self.lookup(ip)
    
    def enrich_indicator_sync(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        """
        Enrich an indicator with geolocation data (synchronous).
        
        Args:
            indicator: The IOC value (URL, IP, domain)
            indicator_type: Type of indicator
            
        Returns:
            Dict with country_code, and other geo fields
        """
        ip = self.extract_ip(indicator)
        if not ip:
            return {}
        
        geo = self.lookup(ip)
        if geo:
            return {
                "country_code": geo.get("country_code"),
                "asn": geo.get("asn"),
                "asn_org": geo.get("org"),
                "ip_address": ip,
                "latitude": geo.get("lat"),
                "longitude": geo.get("lon"),
            }
        
        return {"ip_address": ip}
    
    async def enrich_indicator(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        """Async wrapper for enrich_indicator_sync."""
        return self.enrich_indicator_sync(indicator, indicator_type)
    
    def bulk_lookup(self, ips: list[str]) -> Dict[str, Dict[str, Any]]:
        """
        Look up geolocation for multiple IPs efficiently.
        
        Returns:
            Dict mapping IP to geo data
        """
        results = {}
        for ip in ips:
            geo = self.lookup(ip)
            if geo:
                results[ip] = geo
        return results
    
    def clear_cache(self):
        """Clear the GeoIP cache."""
        self.cache.clear()
    
    def close(self):
        """Close the database reader."""
        if self.reader:
            self.reader.close()
            self.reader = None
    
    @property
    def is_available(self) -> bool:
        """Check if GeoIP lookups are available."""
        return self.reader is not None


# Singleton instance
geoip_service = GeoIPService()
