"""
crt.sh Certificate Transparency importer.

crt.sh provides access to Certificate Transparency logs.
Used to find related domains via SSL certificates.
"""

import aiohttp
from datetime import datetime
from typing import List, Any, Optional
import os

from .base import BaseImporter, Indicator, IndicatorType, ThreatType


class CertificateTransparencyImporter(BaseImporter):
    """
    Import suspicious domains from Certificate Transparency logs.
    
    This importer monitors for certificates issued to suspicious domains
    that may be typosquatting African brands.
    
    Feed URL: https://crt.sh/?q=%.{domain}&output=json
    Updates: Every 30 minutes
    Content: Recently issued certificates for monitored domains
    """
    
    name = "crtsh"
    update_interval_minutes = 30
    
    # African brands and domains to monitor for typosquatting
    MONITORED_PATTERNS = [
        # Mobile money & payments
        "mpesa", "m-pesa", "safaricom", "airtel", "mtn", 
        "vodacom", "orange", "equity", "kcb", "dtb",
        # Banks
        "standardbank", "fnb", "nedbank", "absa", "capitec",
        "stanbic", "ncba", "cooperative", "familybank",
        # Telcos
        "telkom", "cell-c", "rain", "tigo", "glo",
        # E-commerce
        "jumia", "takealot", "kilimall", "masoko",
    ]
    
    async def fetch(self) -> Any:
        """Fetch certificates from crt.sh for monitored patterns."""
        all_certs = []
        
        async with aiohttp.ClientSession() as session:
            for pattern in self.MONITORED_PATTERNS[:10]:  # Limit to avoid rate limits
                try:
                    url = f"https://crt.sh/?q=%25{pattern}%25&output=json"
                    
                    async with session.get(url, timeout=60) as response:
                        if response.status == 200:
                            certs = await response.json()
                            # Only get recent certs (last 7 days processed by parse)
                            for cert in certs[:100]:  # Limit per pattern
                                cert["search_pattern"] = pattern
                            all_certs.extend(certs[:100])
                        else:
                            self.logger.warning(f"crt.sh returned {response.status} for {pattern}")
                            
                except aiohttp.ClientError as e:
                    self.logger.warning(f"Error fetching crt.sh for {pattern}: {e}")
                    continue
                except Exception as e:
                    self.logger.warning(f"Unexpected error for {pattern}: {e}")
                    continue
        
        return all_certs
    
    async def parse(self, raw_data: Any) -> List[Indicator]:
        """Parse crt.sh certificate data."""
        indicators = []
        seen_domains = set()
        now = datetime.utcnow()
        
        for cert in raw_data:
            try:
                # Get domain from certificate common name
                common_name = cert.get("common_name", "").lower().strip()
                name_value = cert.get("name_value", "").lower().strip()
                
                # Parse entry timestamp
                entry_time = self._parse_date(cert.get("entry_timestamp"))
                
                # Only process recent certificates (last 7 days)
                if entry_time:
                    age_days = (now - entry_time).days
                    if age_days > 7:
                        continue
                
                # Process both common_name and name_value (SANs)
                domains = set()
                if common_name and not common_name.startswith("*"):
                    domains.add(common_name)
                
                # name_value can have multiple domains
                for domain in name_value.split("\n"):
                    domain = domain.strip()
                    if domain and not domain.startswith("*"):
                        domains.add(domain)
                
                for domain in domains:
                    if domain in seen_domains:
                        continue
                    seen_domains.add(domain)
                    
                    # Check if this looks suspicious (potential typosquat)
                    pattern = cert.get("search_pattern", "")
                    if not self._is_suspicious(domain, pattern):
                        continue
                    
                    tags = ["crtsh", "certificate-transparency", "potential-typosquat"]
                    tags.append(f"pattern:{pattern}")
                    
                    indicators.append(Indicator(
                        indicator=domain,
                        indicator_type=IndicatorType.DOMAIN,
                        threat_type=ThreatType.PHISHING,
                        source=self.name,
                        source_url=f"https://crt.sh/?q={domain}",
                        confidence=0.6,  # Lower confidence - needs verification
                        tags=tags,
                        first_seen=entry_time or now,
                        last_seen=entry_time or now,
                        metadata={
                            "issuer_name": cert.get("issuer_name"),
                            "not_before": cert.get("not_before"),
                            "not_after": cert.get("not_after"),
                            "serial_number": cert.get("serial_number"),
                            "search_pattern": pattern,
                        },
                    ))
                    
            except Exception as e:
                self.logger.warning(f"Error parsing crt.sh cert: {e}")
                continue
        
        return indicators
    
    def _is_suspicious(self, domain: str, pattern: str) -> bool:
        """
        Check if domain is suspicious (potential typosquat).
        
        Exclude legitimate domains while flagging potential imposters.
        """
        domain_lower = domain.lower()
        
        # Skip if it's the exact legitimate domain
        legitimate_suffixes = [
            ".co.ke", ".co.za", ".com", ".org", ".net", ".africa",
            ".co.tz", ".co.ug", ".ng", ".gh", ".eg"
        ]
        
        # Check for suspicious patterns
        suspicious_indicators = [
            "-login", "-secure", "-verify", "-update", "-account",
            "-service", "-support", "-help", "-alert", "-confirm",
            "login-", "secure-", "verify-", "update-", "account-",
            "www-", "-www", "mobile-", "-mobile",
        ]
        
        # If domain contains suspicious keywords, flag it
        for indicator in suspicious_indicators:
            if indicator in domain_lower:
                return True
        
        # If domain has unusual TLD for African services
        unusual_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".click"]
        for tld in unusual_tlds:
            if domain_lower.endswith(tld):
                return True
        
        # If pattern is in domain but with suspicious modifications
        if pattern in domain_lower:
            # Check for number substitutions (e.g., mpesa1, safaricom0)
            import re
            if re.search(rf"{pattern}\d", domain_lower) or re.search(rf"\d{pattern}", domain_lower):
                return True
        
        return False
    
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
