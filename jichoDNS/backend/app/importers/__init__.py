"""
JichoDNS Feed Importers

This module contains importers for various threat intelligence feeds.
Each importer fetches data from a source and normalizes it to a common format.

All indicators are normalized to show on the threat map with:
- indicator: The IOC value (domain, IP, URL, hash)
- indicator_type: Type of IOC (domain, ip, url, hash_*)
- threat_type: Classification (c2, phishing, malware, exfil, botnet)
- source: Feed source name
- confidence: Score 0-1
- tags: List of categorization tags
- first_seen/last_seen: Timestamps
- metadata: Source-specific extra data

GeoIP enrichment happens at storage time via elasticsearch.py
"""

from .base import BaseImporter, ImportResult, Indicator, IndicatorType, ThreatType

# Abuse.ch feeds
from .abusech import URLhausImporter, ThreatFoxImporter, FeodoTrackerImporter
from .malwarebazaar import MalwareBazaarImporter
from .sslblacklist import SSLBlacklistImporter, JA3FingerprintImporter

# Phishing feeds
from .phishtank import PhishTankImporter
from .openphish import OpenPhishImporter

# Community intelligence
from .alienvault import AlienVaultOTXImporter
from .abuseipdb import AbuseIPDBImporter

# Certificate & typosquatting
from .crtsh import CertificateTransparencyImporter
from .dnstwist import DNSTwistImporter

__all__ = [
    # Base classes
    "BaseImporter",
    "ImportResult",
    "Indicator",
    "IndicatorType",
    "ThreatType",
    
    # Abuse.ch feeds
    "URLhausImporter",
    "ThreatFoxImporter",
    "FeodoTrackerImporter",
    "MalwareBazaarImporter",
    "SSLBlacklistImporter",
    "JA3FingerprintImporter",
    
    # Phishing feeds
    "PhishTankImporter",
    "OpenPhishImporter",
    
    # Community intelligence
    "AlienVaultOTXImporter",
    "AbuseIPDBImporter",
    
    # Certificate & typosquatting
    "CertificateTransparencyImporter",
    "DNSTwistImporter",
]

# Registry of all available importers for easy iteration
IMPORTER_REGISTRY = {
    # High frequency (every 5 min)
    "urlhaus": URLhausImporter,
    "threatfox": ThreatFoxImporter,
    "feodotracker": FeodoTrackerImporter,

    # Medium frequency (every 15 min)
    "malwarebazaar": MalwareBazaarImporter,
    "sslbl": SSLBlacklistImporter,
    "sslbl_ja3": JA3FingerprintImporter,
    "openphish": OpenPhishImporter,
    "crtsh": CertificateTransparencyImporter,
    
    # Lower frequency (hourly)
    "phishtank": PhishTankImporter,
    "abuseipdb": AbuseIPDBImporter,
    "alienvault_otx": AlienVaultOTXImporter,
    
    # Slow (every 6 hours)
    "dnstwist": DNSTwistImporter,
}
