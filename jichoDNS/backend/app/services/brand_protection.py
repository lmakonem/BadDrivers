"""
Brand Protection Service - Typosquatting detection and brand monitoring.

Provides comprehensive brand protection capabilities for African brands including:
- Typosquatting detection using dnstwist algorithms
- Brand abuse monitoring
- Phishing domain similarity checking
- Lookalike domain discovery
"""

import logging
import asyncio
import hashlib
from datetime import datetime
from typing import List, Dict, Any, Optional, Set
from enum import Enum
from dataclasses import dataclass
import re
import socket
import difflib

from pydantic import BaseModel, Field
from elasticsearch import AsyncElasticsearch

from app.core.config import settings

logger = logging.getLogger(__name__)


# =============================================================================
# Pydantic Models
# =============================================================================

class AlertSeverity(str, Enum):
    """Alert severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertType(str, Enum):
    """Types of brand protection alerts."""
    TYPOSQUAT_DETECTED = "typosquat_detected"
    DOMAIN_REGISTERED = "domain_registered"
    PHISHING_DETECTED = "phishing_detected"
    SOCIAL_IMPERSONATION = "social_impersonation"
    FAKE_APP = "fake_app"
    SSL_CERTIFICATE = "ssl_certificate"
    BRAND_MENTION = "brand_mention"


class TyposquatTechnique(str, Enum):
    """Typosquatting generation techniques."""
    BITSQUATTING = "bitsquatting"
    HOMOGLYPH = "homoglyph"
    HYPHENATION = "hyphenation"
    INSERTION = "insertion"
    OMISSION = "omission"
    REPETITION = "repetition"
    REPLACEMENT = "replacement"
    SUBDOMAIN = "subdomain"
    TRANSPOSITION = "transposition"
    VOWEL_SWAP = "vowel_swap"
    ADDITION = "addition"
    TLD_SWAP = "tld_swap"
    CYRILLIC = "cyrillic"


class BrandMonitor(BaseModel):
    """Brand monitoring configuration."""
    id: str = Field(..., description="Unique identifier for the brand monitor")
    brand_name: str = Field(..., description="Name of the brand to monitor")
    domains: List[str] = Field(default_factory=list, description="Official domains for the brand")
    keywords: List[str] = Field(default_factory=list, description="Keywords to monitor")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    active: bool = Field(default=True)
    alert_email: Optional[str] = Field(None, description="Email for alerts")
    scan_frequency_hours: int = Field(default=24, description="How often to scan")
    last_scan_at: Optional[datetime] = None
    typosquat_count: int = Field(default=0, description="Number of detected typosquats")
    owner_user_id: Optional[int] = Field(default=None, description="Owning JichoDNS user id")
    country_code: Optional[str] = Field(default=None, description="Brand country (ISO-3166 alpha-2)")
    industry: Optional[str] = Field(default=None, description="Brand industry sector")


class TyposquatDomain(BaseModel):
    """A typosquat domain variant."""
    original: str = Field(..., description="Original legitimate domain")
    variant: str = Field(..., description="Generated typosquat variant")
    technique: TyposquatTechnique = Field(..., description="Technique used to generate variant")
    is_registered: bool = Field(default=False, description="Whether domain is registered")
    registrar: Optional[str] = Field(None, description="Domain registrar if registered")
    registration_date: Optional[datetime] = Field(None)
    expiration_date: Optional[datetime] = Field(None)
    ip_address: Optional[str] = Field(None, description="Resolved IP address")
    mx_records: List[str] = Field(default_factory=list, description="Mail exchange records")
    risk_score: float = Field(default=0.0, ge=0, le=100, description="Risk score 0-100")
    has_ssl: bool = Field(default=False, description="Has SSL certificate")
    has_website: bool = Field(default=False, description="Has active website")
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    country_code: Optional[str] = Field(None, description="Server country")


class BrandAlert(BaseModel):
    """Brand protection alert."""
    id: str = Field(..., description="Unique alert identifier")
    brand_id: str = Field(..., description="Associated brand monitor ID")
    alert_type: AlertType = Field(..., description="Type of alert")
    severity: AlertSeverity = Field(..., description="Alert severity")
    title: str = Field(..., description="Alert title")
    details: Dict[str, Any] = Field(default_factory=dict, description="Alert details")
    domain: Optional[str] = Field(None, description="Associated domain")
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    acknowledged: bool = Field(default=False)
    acknowledged_at: Optional[datetime] = None
    acknowledged_by: Optional[str] = None


class PhishingDomain(BaseModel):
    """Phishing domain analysis result."""
    domain: str = Field(..., description="Analyzed domain")
    target_brand: str = Field(..., description="Target brand being impersonated")
    legitimate_domain: str = Field(..., description="Legitimate brand domain")
    similarity_score: float = Field(..., ge=0, le=1, description="Similarity score 0-1")
    visual_similarity: float = Field(default=0.0, ge=0, le=1)
    text_similarity: float = Field(default=0.0, ge=0, le=1)
    is_phishing: bool = Field(default=False)
    risk_level: AlertSeverity = Field(default=AlertSeverity.LOW)
    techniques_detected: List[str] = Field(default_factory=list)
    status: str = Field(default="active", description="Domain status")
    checked_at: datetime = Field(default_factory=datetime.utcnow)


# =============================================================================
# Pre-configured African Brands
# =============================================================================

AFRICAN_BRANDS: Dict[str, Dict[str, Any]] = {
    # Mobile Money & Telecom
    "mpesa": {
        "brand_name": "M-Pesa",
        "domains": ["safaricom.co.ke", "mpesa.co.ke", "mpesa.com"],
        "keywords": ["mpesa", "m-pesa", "mobile money", "safaricom", "lipa"],
        "country": "KE",
    },
    "safaricom": {
        "brand_name": "Safaricom",
        "domains": ["safaricom.co.ke", "safaricom.com"],
        "keywords": ["safaricom", "saf", "skiza", "bonga"],
        "country": "KE",
    },
    "mtn": {
        "brand_name": "MTN",
        "domains": ["mtn.com", "mtn.co.za", "mtn.com.gh", "mtn.co.ug", "mtn.com.ng"],
        "keywords": ["mtn", "mobile money", "momo", "ayoba"],
        "country": "ZA",
    },
    "airtel": {
        "brand_name": "Airtel",
        "domains": ["airtel.com", "airtel.co.ke", "airtel.com.ng", "airtel.co.ug"],
        "keywords": ["airtel", "airtel money", "wynk"],
        "country": "IN",
    },
    "vodacom": {
        "brand_name": "Vodacom",
        "domains": ["vodacom.co.za", "vodacom.com", "vodacom.co.tz"],
        "keywords": ["vodacom", "vodapay", "airtime"],
        "country": "ZA",
    },
    "glo": {
        "brand_name": "Glo",
        "domains": ["gloworld.com", "glo.com.ng"],
        "keywords": ["glo", "globacom", "glo mobile"],
        "country": "NG",
    },
    "etisalat": {
        "brand_name": "Etisalat/9mobile",
        "domains": ["9mobile.com.ng", "etisalat.ae"],
        "keywords": ["9mobile", "etisalat", "9ja"],
        "country": "NG",
    },
    
    # Banks - Kenya
    "equitybank": {
        "brand_name": "Equity Bank",
        "domains": ["equitybankgroup.com", "equitybank.co.ke"],
        "keywords": ["equity", "equity bank", "eazzy"],
        "country": "KE",
    },
    "kcb": {
        "brand_name": "KCB Bank",
        "domains": ["kcbgroup.com", "kcb.co.ke"],
        "keywords": ["kcb", "kcb bank", "kcb mpesa"],
        "country": "KE",
    },
    "coop": {
        "brand_name": "Co-operative Bank",
        "domains": ["co-opbank.co.ke"],
        "keywords": ["coop bank", "cooperative", "mcoop"],
        "country": "KE",
    },
    "absa_ke": {
        "brand_name": "Absa Kenya",
        "domains": ["absabank.co.ke", "absa.co.ke"],
        "keywords": ["absa", "barclays kenya"],
        "country": "KE",
    },
    
    # Banks - South Africa
    "standardbank": {
        "brand_name": "Standard Bank",
        "domains": ["standardbank.co.za", "standardbank.com"],
        "keywords": ["standard bank", "stanbic"],
        "country": "ZA",
    },
    "fnb": {
        "brand_name": "First National Bank",
        "domains": ["fnb.co.za", "fnb.com"],
        "keywords": ["fnb", "first national bank", "fnb banking app"],
        "country": "ZA",
    },
    "nedbank": {
        "brand_name": "Nedbank",
        "domains": ["nedbank.co.za", "nedbank.com"],
        "keywords": ["nedbank", "old mutual"],
        "country": "ZA",
    },
    "capitec": {
        "brand_name": "Capitec",
        "domains": ["capitecbank.co.za"],
        "keywords": ["capitec", "capitec bank"],
        "country": "ZA",
    },
    "absa": {
        "brand_name": "Absa Bank",
        "domains": ["absa.co.za", "absa.com"],
        "keywords": ["absa", "absa bank"],
        "country": "ZA",
    },
    
    # Banks - Nigeria
    "gtbank": {
        "brand_name": "GTBank",
        "domains": ["gtbank.com", "gtbank.com.ng"],
        "keywords": ["gtbank", "guarantee trust", "gt"],
        "country": "NG",
    },
    "zenith": {
        "brand_name": "Zenith Bank",
        "domains": ["zenithbank.com", "zenithbank.com.ng"],
        "keywords": ["zenith", "zenith bank"],
        "country": "NG",
    },
    "firstbank_ng": {
        "brand_name": "First Bank Nigeria",
        "domains": ["firstbanknigeria.com"],
        "keywords": ["firstbank", "first bank nigeria"],
        "country": "NG",
    },
    "accessbank": {
        "brand_name": "Access Bank",
        "domains": ["accessbankplc.com"],
        "keywords": ["access bank", "accessbank"],
        "country": "NG",
    },
    "uba": {
        "brand_name": "United Bank for Africa",
        "domains": ["ubagroup.com"],
        "keywords": ["uba", "united bank africa"],
        "country": "NG",
    },
    
    # E-commerce
    "jumia": {
        "brand_name": "Jumia",
        "domains": ["jumia.com", "jumia.co.ke", "jumia.com.ng", "jumia.co.za"],
        "keywords": ["jumia", "jumia pay", "jumia food"],
        "country": "NG",
    },
    "takealot": {
        "brand_name": "Takealot",
        "domains": ["takealot.com"],
        "keywords": ["takealot", "mr d food"],
        "country": "ZA",
    },
    "konga": {
        "brand_name": "Konga",
        "domains": ["konga.com"],
        "keywords": ["konga", "kongapay"],
        "country": "NG",
    },
    "kilimall": {
        "brand_name": "Kilimall",
        "domains": ["kilimall.co.ke", "kilimall.com"],
        "keywords": ["kilimall"],
        "country": "KE",
    },
    
    # Payment Services
    "paystack": {
        "brand_name": "Paystack",
        "domains": ["paystack.com"],
        "keywords": ["paystack", "payment"],
        "country": "NG",
    },
    "flutterwave": {
        "brand_name": "Flutterwave",
        "domains": ["flutterwave.com"],
        "keywords": ["flutterwave", "rave"],
        "country": "NG",
    },
    "chipper": {
        "brand_name": "Chipper Cash",
        "domains": ["chippercash.com"],
        "keywords": ["chipper", "chipper cash"],
        "country": "US",
    },
}


# =============================================================================
# Homoglyph mappings for confusable characters
# =============================================================================

HOMOGLYPHS: Dict[str, List[str]] = {
    'a': ['а', 'ạ', 'å', 'ä', 'á', 'à', 'ã', 'â', '@', '4'],
    'b': ['ḃ', 'ḅ', 'ь', '6', 'ƀ'],
    'c': ['с', 'ç', 'ć', 'ĉ', 'ċ', '('],
    'd': ['ḋ', 'ḍ', 'ḏ', 'ɗ', 'đ'],
    'e': ['е', 'ë', 'é', 'è', 'ê', 'ẹ', '3', 'ę', 'ė'],
    'f': ['ƒ', 'ḟ'],
    'g': ['ġ', 'ǵ', 'ğ', 'ĝ', '9', 'ǧ'],
    'h': ['һ', 'ḥ', 'ḧ', 'ĥ', 'ħ'],
    'i': ['і', 'í', 'ì', 'î', 'ï', 'ı', '1', 'l', '!', '|'],
    'j': ['ј', 'ĵ'],
    'k': ['κ', 'ķ', 'ḳ', 'ḵ'],
    'l': ['ӏ', 'ḷ', 'ĺ', 'ļ', 'ł', '1', 'i', '|'],
    'm': ['м', 'ṁ', 'ṃ', 'rn'],
    'n': ['п', 'ṅ', 'ṇ', 'ń', 'ñ', 'ň'],
    'o': ['о', 'ö', 'ó', 'ò', 'ô', 'õ', '0', 'ọ', 'ø', 'ő'],
    'p': ['р', 'ṗ', 'ρ'],
    'q': ['ԛ', 'ɋ'],
    'r': ['г', 'ṙ', 'ṛ', 'ř', 'ŕ'],
    's': ['ѕ', 'ṡ', 'ṣ', 'ś', 'š', '5', '$'],
    't': ['ṫ', 'ṭ', 'ť', 'ţ', '7', '+'],
    'u': ['υ', 'ü', 'ú', 'ù', 'û', 'ụ', 'ű', 'ų'],
    'v': ['ν', 'ṿ', 'ⅴ'],
    'w': ['ω', 'ẁ', 'ẃ', 'ẅ', 'ŵ', 'vv'],
    'x': ['х', 'ẋ', 'ẍ', '×'],
    'y': ['у', 'ý', 'ÿ', 'ŷ', 'ỳ'],
    'z': ['ẑ', 'ẓ', 'ż', 'ź', 'ž', '2'],
}

# Common African TLDs and variations
AFRICAN_TLDS = [
    'co.ke', 'co.za', 'com.ng', 'co.ug', 'co.tz', 'com.gh', 'com.eg',
    'co.zw', 'co.bw', 'com.et', 'com.rw', 'co.mz', 'co.ao',
]

COMMON_TLDS = [
    'com', 'net', 'org', 'io', 'co', 'app', 'dev', 'online', 'site',
    'shop', 'store', 'pay', 'bank', 'money', 'africa', 'xyz', 'info',
]


# =============================================================================
# Brand Protection Service
# =============================================================================

class BrandProtectionService:
    """Service for brand protection and typosquatting detection."""
    
    def __init__(self):
        self.es_client: Optional[AsyncElasticsearch] = None
        self.brand_index = "brand_monitors"
        self.typosquat_index = "typosquat_domains"
        self.alert_index = "brand_alerts"
        
    async def connect(self):
        """Initialize Elasticsearch connection."""
        if self.es_client is None:
            es_url = settings.ELASTICSEARCH_URL
            if es_url:
                self.es_client = AsyncElasticsearch(
                    [es_url],
                    verify_certs=False,
                    request_timeout=30,
                )
                await self._ensure_indices()
                logger.info("Brand Protection Service connected to Elasticsearch")
    
    async def close(self):
        """Close Elasticsearch connection."""
        if self.es_client:
            await self.es_client.close()
            self.es_client = None
    
    async def _ensure_indices(self):
        """Create indices if they don't exist."""
        if not self.es_client:
            return
            
        # Brand monitors index
        brand_mapping = {
            "mappings": {
                "properties": {
                    "id": {"type": "keyword"},
                    "brand_name": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                    "domains": {"type": "keyword"},
                    "keywords": {"type": "keyword"},
                    "created_at": {"type": "date"},
                    "updated_at": {"type": "date"},
                    "active": {"type": "boolean"},
                    "alert_email": {"type": "keyword"},
                    "scan_frequency_hours": {"type": "integer"},
                    "last_scan_at": {"type": "date"},
                    "typosquat_count": {"type": "integer"},
                    "owner_user_id": {"type": "integer"},
                }
            }
        }

        # Typosquat domains index
        typosquat_mapping = {
            "mappings": {
                "properties": {
                    "original": {"type": "keyword"},
                    "variant": {"type": "keyword"},
                    "technique": {"type": "keyword"},
                    "is_registered": {"type": "boolean"},
                    "registrar": {"type": "keyword"},
                    "registration_date": {"type": "date"},
                    "expiration_date": {"type": "date"},
                    "ip_address": {"type": "ip"},
                    "mx_records": {"type": "keyword"},
                    "risk_score": {"type": "float"},
                    "has_ssl": {"type": "boolean"},
                    "has_website": {"type": "boolean"},
                    "detected_at": {"type": "date"},
                    "country_code": {"type": "keyword"},
                }
            }
        }
        
        # Brand alerts index
        alert_mapping = {
            "mappings": {
                "properties": {
                    "id": {"type": "keyword"},
                    "brand_id": {"type": "keyword"},
                    "alert_type": {"type": "keyword"},
                    "severity": {"type": "keyword"},
                    "title": {"type": "text"},
                    "details": {"type": "object", "enabled": False},
                    "domain": {"type": "keyword"},
                    "detected_at": {"type": "date"},
                    "acknowledged": {"type": "boolean"},
                    "acknowledged_at": {"type": "date"},
                    "acknowledged_by": {"type": "keyword"},
                }
            }
        }
        
        try:
            for index, mapping in [
                (self.brand_index, brand_mapping),
                (self.typosquat_index, typosquat_mapping),
                (self.alert_index, alert_mapping),
            ]:
                if not await self.es_client.indices.exists(index=index):
                    await self.es_client.indices.create(index=index, body=mapping)
                    logger.info(f"Created index: {index}")
        except Exception as e:
            logger.error(f"Error creating indices: {e}")
    
    # -------------------------------------------------------------------------
    # Typosquatting Detection (dnstwist algorithms)
    # -------------------------------------------------------------------------
    
    def detect_typosquatting(self, domain: str, check_dns: bool = False) -> List[TyposquatDomain]:
        """
        Generate and check typosquat variants for a domain.
        
        Uses dnstwist-style algorithms:
        - Character omission
        - Character swap (transposition)
        - Character replacement
        - Homoglyph substitution
        - TLD variations
        - Hyphenation
        - Bit flipping
        
        Args:
            domain: The legitimate domain to check
            check_dns: Whether to resolve DNS (slower but more info)
            
        Returns:
            List of TyposquatDomain objects
        """
        # Extract domain parts
        domain = domain.lower().strip()
        if domain.startswith('http://') or domain.startswith('https://'):
            domain = re.sub(r'^https?://', '', domain)
        domain = domain.split('/')[0]  # Remove path
        
        parts = domain.split('.')
        if len(parts) < 2:
            return []
            
        # Handle multi-part TLDs like co.ke
        if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in AFRICAN_TLDS:
            sld = '.'.join(parts[:-2])
            tld = f"{parts[-2]}.{parts[-1]}"
        else:
            sld = '.'.join(parts[:-1])
            tld = parts[-1]
        
        # Get base domain name (without TLD)
        base_name = parts[0] if len(parts) > 0 else domain
        
        variants: List[TyposquatDomain] = []
        seen: Set[str] = {domain}
        
        def add_variant(variant: str, technique: TyposquatTechnique):
            """Add a variant if not already seen."""
            variant = variant.lower()
            if variant and variant not in seen and variant != domain:
                seen.add(variant)
                typosquat = TyposquatDomain(
                    original=domain,
                    variant=variant,
                    technique=technique,
                    risk_score=self._calculate_risk_score(domain, variant, technique),
                )
                
                if check_dns:
                    self._resolve_domain(typosquat)
                    
                variants.append(typosquat)
        
        # 1. Character Omission
        for i in range(len(base_name)):
            variant = base_name[:i] + base_name[i+1:]
            if variant:
                add_variant(f"{variant}.{tld}", TyposquatTechnique.OMISSION)
        
        # 2. Character Transposition (swap adjacent)
        for i in range(len(base_name) - 1):
            swapped = list(base_name)
            swapped[i], swapped[i+1] = swapped[i+1], swapped[i]
            add_variant(f"{''.join(swapped)}.{tld}", TyposquatTechnique.TRANSPOSITION)
        
        # 3. Character Replacement (adjacent keys)
        keyboard_neighbors = {
            'q': 'wa', 'w': 'qeas', 'e': 'wrd', 'r': 'etf', 't': 'ryg',
            'y': 'tuh', 'u': 'yij', 'i': 'uok', 'o': 'ipl', 'p': 'ol',
            'a': 'qsz', 's': 'awdx', 'd': 'sefc', 'f': 'dgvr', 'g': 'fhtb',
            'h': 'gyjn', 'j': 'hukm', 'k': 'jil', 'l': 'kop',
            'z': 'asx', 'x': 'zscd', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn',
            'n': 'bhjm', 'm': 'njk',
        }
        for i, char in enumerate(base_name):
            if char in keyboard_neighbors:
                for neighbor in keyboard_neighbors[char]:
                    variant = base_name[:i] + neighbor + base_name[i+1:]
                    add_variant(f"{variant}.{tld}", TyposquatTechnique.REPLACEMENT)
        
        # 4. Homoglyph Substitution
        for i, char in enumerate(base_name):
            if char in HOMOGLYPHS:
                for glyph in HOMOGLYPHS[char][:3]:  # Limit to top 3
                    variant = base_name[:i] + glyph + base_name[i+1:]
                    add_variant(f"{variant}.{tld}", TyposquatTechnique.HOMOGLYPH)
        
        # 5. Character Insertion
        common_chars = 'aeiourns'
        for i in range(len(base_name) + 1):
            for char in common_chars:
                variant = base_name[:i] + char + base_name[i:]
                add_variant(f"{variant}.{tld}", TyposquatTechnique.INSERTION)
        
        # 6. Character Repetition
        for i, char in enumerate(base_name):
            if char.isalpha():
                variant = base_name[:i] + char + char + base_name[i+1:]
                add_variant(f"{variant}.{tld}", TyposquatTechnique.REPETITION)
        
        # 7. Hyphenation
        for i in range(1, len(base_name)):
            variant = base_name[:i] + '-' + base_name[i:]
            add_variant(f"{variant}.{tld}", TyposquatTechnique.HYPHENATION)
        
        # 8. TLD Variations
        for alt_tld in COMMON_TLDS + AFRICAN_TLDS:
            if alt_tld != tld:
                add_variant(f"{base_name}.{alt_tld}", TyposquatTechnique.TLD_SWAP)
        
        # 9. Character Addition (at end)
        for char in 'sxz123':
            add_variant(f"{base_name}{char}.{tld}", TyposquatTechnique.ADDITION)
        
        # 10. Vowel Swap
        vowels = 'aeiou'
        for i, char in enumerate(base_name):
            if char in vowels:
                for vowel in vowels:
                    if vowel != char:
                        variant = base_name[:i] + vowel + base_name[i+1:]
                        add_variant(f"{variant}.{tld}", TyposquatTechnique.VOWEL_SWAP)
        
        # 11. Bitsquatting (1-bit flip in ASCII)
        for i, char in enumerate(base_name):
            for bit in range(8):
                flipped = chr(ord(char) ^ (1 << bit))
                if flipped.isalnum() and flipped.isprintable():
                    variant = base_name[:i] + flipped + base_name[i+1:]
                    add_variant(f"{variant}.{tld}", TyposquatTechnique.BITSQUATTING)
        
        # 12. Subdomain tricks
        add_variant(f"{base_name}.{domain}", TyposquatTechnique.SUBDOMAIN)
        add_variant(f"www-{base_name}.{tld}", TyposquatTechnique.SUBDOMAIN)
        add_variant(f"{base_name}-login.{tld}", TyposquatTechnique.SUBDOMAIN)
        add_variant(f"secure-{base_name}.{tld}", TyposquatTechnique.SUBDOMAIN)
        
        # Sort by risk score
        variants.sort(key=lambda x: x.risk_score, reverse=True)
        
        return variants
    
    def _calculate_risk_score(
        self, 
        original: str, 
        variant: str, 
        technique: TyposquatTechnique
    ) -> float:
        """Calculate risk score for a typosquat variant."""
        score = 0.0
        
        # Technique-based scoring
        technique_scores = {
            TyposquatTechnique.HOMOGLYPH: 30,      # Very deceptive
            TyposquatTechnique.TRANSPOSITION: 25,   # Common typo
            TyposquatTechnique.OMISSION: 25,        # Common typo
            TyposquatTechnique.REPLACEMENT: 20,     # Adjacent key
            TyposquatTechnique.INSERTION: 15,
            TyposquatTechnique.REPETITION: 15,
            TyposquatTechnique.VOWEL_SWAP: 15,
            TyposquatTechnique.HYPHENATION: 10,
            TyposquatTechnique.TLD_SWAP: 20,
            TyposquatTechnique.ADDITION: 10,
            TyposquatTechnique.BITSQUATTING: 25,
            TyposquatTechnique.SUBDOMAIN: 20,
            TyposquatTechnique.CYRILLIC: 35,
        }
        score += technique_scores.get(technique, 10)
        
        # String similarity bonus
        similarity = difflib.SequenceMatcher(None, original, variant).ratio()
        score += similarity * 30  # Up to 30 points for high similarity
        
        # TLD risk
        variant_tld = variant.split('.')[-1] if '.' in variant else ''
        high_risk_tlds = {'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'click'}
        if variant_tld in high_risk_tlds:
            score += 15
        
        return min(score, 100)
    
    def _resolve_domain(self, typosquat: TyposquatDomain):
        """Resolve DNS for a domain to check if registered."""
        try:
            ip = socket.gethostbyname(typosquat.variant)
            typosquat.is_registered = True
            typosquat.ip_address = ip
            typosquat.risk_score = min(typosquat.risk_score + 30, 100)
        except socket.gaierror:
            typosquat.is_registered = False
        except Exception as e:
            logger.debug(f"DNS resolution error for {typosquat.variant}: {e}")
    
    # -------------------------------------------------------------------------
    # Brand Monitoring
    # -------------------------------------------------------------------------
    
    async def monitor_brand(
        self,
        brand_name: str,
        keywords: List[str],
        domains: Optional[List[str]] = None,
        alert_email: Optional[str] = None,
        owner_user_id: Optional[int] = None,
    ) -> BrandMonitor:
        """
        Set up monitoring for a brand.
        
        Args:
            brand_name: Name of the brand
            keywords: Keywords to monitor
            domains: Official brand domains
            alert_email: Email for alerts
            
        Returns:
            BrandMonitor configuration
        """
        await self.connect()
        
        # Generate unique ID — scoped per owner so two tenants monitoring the
        # same brand/domains get distinct monitor documents.
        brand_id = hashlib.sha256(
            f"{owner_user_id}:{brand_name}:{','.join(sorted(domains or []))}".encode()
        ).hexdigest()[:16]
        
        # Check if pre-configured African brand
        brand_key = brand_name.lower().replace(' ', '').replace('-', '')
        if brand_key in AFRICAN_BRANDS:
            preset = AFRICAN_BRANDS[brand_key]
            if not domains:
                domains = preset['domains']
            keywords = list(set(keywords + preset.get('keywords', [])))
        
        monitor = BrandMonitor(
            id=brand_id,
            brand_name=brand_name,
            domains=domains or [],
            keywords=keywords,
            alert_email=alert_email,
            owner_user_id=owner_user_id,
        )
        
        # Store in Elasticsearch
        if self.es_client:
            try:
                await self.es_client.index(
                    index=self.brand_index,
                    id=brand_id,
                    body=monitor.model_dump(mode='json'),
                )
                logger.info(f"Brand monitor created: {brand_name} ({brand_id})")
            except Exception as e:
                logger.error(f"Error storing brand monitor: {e}")
        
        return monitor
    
    async def get_brand_monitor(self, brand_id: str) -> Optional[BrandMonitor]:
        """Get a brand monitor by ID."""
        await self.connect()
        
        if not self.es_client:
            return None
            
        try:
            result = await self.es_client.get(index=self.brand_index, id=brand_id)
            return BrandMonitor(**result['_source'])
        except Exception as e:
            logger.error(f"Error getting brand monitor: {e}")
            return None
    
    async def list_brand_monitors(
        self, 
        active_only: bool = True,
        limit: int = 50,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """List all brand monitors."""
        await self.connect()
        
        if not self.es_client:
            return {"monitors": [], "total": 0}
        
        try:
            query = {"match_all": {}}
            if active_only:
                query = {"term": {"active": True}}
            
            result = await self.es_client.search(
                index=self.brand_index,
                body={
                    "query": query,
                    "sort": [{"created_at": "desc"}],
                    "from": offset,
                    "size": limit,
                }
            )
            
            monitors = [
                BrandMonitor(**hit['_source']) 
                for hit in result['hits']['hits']
            ]
            
            return {
                "monitors": monitors,
                "total": result['hits']['total']['value'],
            }
        except Exception as e:
            logger.error(f"Error listing brand monitors: {e}")
            return {"monitors": [], "total": 0}
    
    # -------------------------------------------------------------------------
    # Phishing Similarity Check
    # -------------------------------------------------------------------------
    
    def check_phishing_similarity(
        self, 
        domain: str, 
        legitimate_domain: str
    ) -> PhishingDomain:
        """
        Check visual and text similarity between domains.
        
        Uses multiple similarity metrics to detect phishing attempts.
        
        Args:
            domain: Suspicious domain to check
            legitimate_domain: Known legitimate domain
            
        Returns:
            PhishingDomain with similarity analysis
        """
        domain = domain.lower().strip()
        legitimate_domain = legitimate_domain.lower().strip()
        
        # Extract base names
        def get_base(d: str) -> str:
            d = re.sub(r'^https?://', '', d)
            d = d.split('/')[0].split(':')[0]
            parts = d.split('.')
            # Handle co.ke style TLDs
            if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in AFRICAN_TLDS:
                return '.'.join(parts[:-2])
            return '.'.join(parts[:-1]) if len(parts) > 1 else d
        
        base_domain = get_base(domain)
        base_legitimate = get_base(legitimate_domain)
        
        # Text similarity using SequenceMatcher
        text_similarity = difflib.SequenceMatcher(
            None, base_domain, base_legitimate
        ).ratio()
        
        # Visual similarity (homoglyph detection)
        visual_similarity = self._calculate_visual_similarity(base_domain, base_legitimate)
        
        # Overall similarity
        similarity_score = (text_similarity * 0.6) + (visual_similarity * 0.4)
        
        # Detect techniques used
        techniques = []
        
        # Check for homoglyphs
        if self._contains_homoglyphs(base_domain):
            techniques.append("homoglyph_substitution")
            
        # Check for character transposition
        if self._is_transposition(base_domain, base_legitimate):
            techniques.append("character_transposition")
        
        # Check for missing/extra characters
        len_diff = abs(len(base_domain) - len(base_legitimate))
        if len_diff == 1:
            techniques.append("character_omission_or_addition")
        
        # Check for hyphen insertion
        if '-' in base_domain and '-' not in base_legitimate:
            techniques.append("hyphen_insertion")
        
        # Check for TLD abuse
        domain_tld = domain.split('.')[-1]
        legit_tld = legitimate_domain.split('.')[-1]
        if domain_tld != legit_tld:
            techniques.append("tld_variation")
        
        # Determine risk level
        if similarity_score >= 0.9:
            risk_level = AlertSeverity.CRITICAL
            is_phishing = True
        elif similarity_score >= 0.8:
            risk_level = AlertSeverity.HIGH
            is_phishing = True
        elif similarity_score >= 0.6:
            risk_level = AlertSeverity.MEDIUM
            is_phishing = similarity_score >= 0.7
        else:
            risk_level = AlertSeverity.LOW
            is_phishing = False
        
        # Extract brand name from legitimate domain
        target_brand = base_legitimate.split('.')[0] if '.' in base_legitimate else base_legitimate
        
        return PhishingDomain(
            domain=domain,
            target_brand=target_brand,
            legitimate_domain=legitimate_domain,
            similarity_score=round(similarity_score, 4),
            visual_similarity=round(visual_similarity, 4),
            text_similarity=round(text_similarity, 4),
            is_phishing=is_phishing,
            risk_level=risk_level,
            techniques_detected=techniques,
        )
    
    def _calculate_visual_similarity(self, s1: str, s2: str) -> float:
        """Calculate visual similarity accounting for homoglyphs."""
        if not s1 or not s2:
            return 0.0
            
        # Normalize homoglyphs to their base characters
        def normalize(s: str) -> str:
            result = []
            for char in s:
                normalized = char
                for base, glyphs in HOMOGLYPHS.items():
                    if char in glyphs:
                        normalized = base
                        break
                result.append(normalized)
            return ''.join(result)
        
        norm1 = normalize(s1)
        norm2 = normalize(s2)
        
        # If normalized versions match, high visual similarity
        if norm1 == norm2:
            return 0.95
            
        return difflib.SequenceMatcher(None, norm1, norm2).ratio()
    
    def _contains_homoglyphs(self, s: str) -> bool:
        """Check if string contains homoglyph characters."""
        all_glyphs = set()
        for glyphs in HOMOGLYPHS.values():
            all_glyphs.update(glyphs)
        return any(char in all_glyphs for char in s)
    
    def _is_transposition(self, s1: str, s2: str) -> bool:
        """Check if s1 is a transposition of s2."""
        if len(s1) != len(s2):
            return False
        diffs = sum(1 for a, b in zip(s1, s2) if a != b)
        return diffs == 2 and sorted(s1) == sorted(s2)
    
    # -------------------------------------------------------------------------
    # Lookalike Domain Discovery
    # -------------------------------------------------------------------------
    
    async def get_lookalike_domains(
        self, 
        domain: str,
        check_registration: bool = True,
        limit: int = 100,
    ) -> List[TyposquatDomain]:
        """
        Find registered lookalike domains.
        
        Generates variants and checks which ones are actually registered.
        
        Args:
            domain: Domain to find lookalikes for
            check_registration: Whether to check DNS registration
            limit: Maximum variants to return
            
        Returns:
            List of registered lookalike domains
        """
        # Generate all variants
        variants = self.detect_typosquatting(domain, check_dns=False)
        
        if check_registration:
            # Check registration in parallel (with rate limiting)
            registered = []
            batch_size = 10
            
            for i in range(0, min(len(variants), limit * 2), batch_size):
                batch = variants[i:i + batch_size]
                
                # Resolve DNS in parallel
                tasks = []
                for v in batch:
                    tasks.append(asyncio.to_thread(self._resolve_domain, v))
                
                await asyncio.gather(*tasks, return_exceptions=True)
                
                # Collect registered domains
                for v in batch:
                    if v.is_registered:
                        registered.append(v)
                        if len(registered) >= limit:
                            break
                
                if len(registered) >= limit:
                    break
                
                # Rate limiting
                await asyncio.sleep(0.1)
            
            # Sort by risk score
            registered.sort(key=lambda x: x.risk_score, reverse=True)
            return registered[:limit]
        
        return variants[:limit]
    
    # -------------------------------------------------------------------------
    # Alert Management
    # -------------------------------------------------------------------------
    
    async def get_alerts(
        self,
        brand_id: Optional[str] = None,
        severity: Optional[AlertSeverity] = None,
        acknowledged: Optional[bool] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """Get brand protection alerts."""
        await self.connect()
        
        if not self.es_client:
            return {"alerts": [], "total": 0}
        
        try:
            must = []
            
            if brand_id:
                must.append({"term": {"brand_id": brand_id}})
            if severity:
                must.append({"term": {"severity": severity.value}})
            if acknowledged is not None:
                must.append({"term": {"acknowledged": acknowledged}})
            
            query = {"bool": {"must": must}} if must else {"match_all": {}}
            
            result = await self.es_client.search(
                index=self.alert_index,
                body={
                    "query": query,
                    "sort": [{"detected_at": "desc"}],
                    "from": offset,
                    "size": limit,
                }
            )
            
            alerts = [
                BrandAlert(**hit['_source'])
                for hit in result['hits']['hits']
            ]
            
            return {
                "alerts": alerts,
                "total": result['hits']['total']['value'],
            }
        except Exception as e:
            logger.error(f"Error getting alerts: {e}")
            return {"alerts": [], "total": 0}
    
    async def acknowledge_alert(
        self, 
        alert_id: str, 
        acknowledged_by: str
    ) -> bool:
        """Mark an alert as acknowledged."""
        await self.connect()
        
        if not self.es_client:
            return False
            
        try:
            await self.es_client.update(
                index=self.alert_index,
                id=alert_id,
                body={
                    "doc": {
                        "acknowledged": True,
                        "acknowledged_at": datetime.utcnow().isoformat(),
                        "acknowledged_by": acknowledged_by,
                    }
                }
            )
            return True
        except Exception as e:
            logger.error(f"Error acknowledging alert: {e}")
            return False
    
    # -------------------------------------------------------------------------
    # Typosquat Storage
    # -------------------------------------------------------------------------
    
    async def store_typosquats(
        self, 
        typosquats: List[TyposquatDomain]
    ) -> Dict[str, int]:
        """Store typosquat domains in Elasticsearch."""
        await self.connect()
        
        if not self.es_client:
            return {"success": 0, "errors": len(typosquats)}
        
        try:
            actions = []
            for t in typosquats:
                doc_id = hashlib.sha256(
                    f"{t.original}:{t.variant}".encode()
                ).hexdigest()[:20]
                
                actions.append({
                    "_index": self.typosquat_index,
                    "_id": doc_id,
                    "_source": t.model_dump(mode='json'),
                })
            
            from elasticsearch.helpers import async_bulk
            success, errors = await async_bulk(
                self.es_client,
                actions,
                raise_on_error=False,
                stats_only=True,
            )
            
            return {"success": success, "errors": errors}
        except Exception as e:
            logger.error(f"Error storing typosquats: {e}")
            return {"success": 0, "errors": len(typosquats)}
    
    async def get_stored_typosquats(
        self,
        original_domain: Optional[str] = None,
        registered_only: bool = False,
        min_risk_score: float = 0,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """Get stored typosquat domains."""
        await self.connect()
        
        if not self.es_client:
            return {"typosquats": [], "total": 0}
        
        try:
            must = []
            
            if original_domain:
                must.append({"term": {"original": original_domain}})
            if registered_only:
                must.append({"term": {"is_registered": True}})
            if min_risk_score > 0:
                must.append({"range": {"risk_score": {"gte": min_risk_score}}})
            
            query = {"bool": {"must": must}} if must else {"match_all": {}}
            
            result = await self.es_client.search(
                index=self.typosquat_index,
                body={
                    "query": query,
                    "sort": [{"risk_score": "desc"}],
                    "from": offset,
                    "size": limit,
                }
            )
            
            typosquats = [
                TyposquatDomain(**hit['_source'])
                for hit in result['hits']['hits']
            ]
            
            return {
                "typosquats": typosquats,
                "total": result['hits']['total']['value'],
            }
        except Exception as e:
            logger.error(f"Error getting typosquats: {e}")
            return {"typosquats": [], "total": 0}
    
    # -------------------------------------------------------------------------
    # Brand Report Generation
    # -------------------------------------------------------------------------
    
    async def generate_brand_report(self, brand_id: str) -> Dict[str, Any]:
        """
        Generate a comprehensive brand protection report.
        
        Args:
            brand_id: Brand monitor ID
            
        Returns:
            Complete report with all findings
        """
        monitor = await self.get_brand_monitor(brand_id)
        if not monitor:
            return {"error": "Brand monitor not found"}
        
        # Get all typosquats for brand domains
        all_typosquats = []
        for domain in monitor.domains:
            result = await self.get_stored_typosquats(original_domain=domain)
            all_typosquats.extend(result.get("typosquats", []))
        
        # Get alerts
        alerts_result = await self.get_alerts(brand_id=brand_id)
        
        # Generate stats
        registered_count = sum(1 for t in all_typosquats if t.is_registered)
        high_risk_count = sum(1 for t in all_typosquats if t.risk_score >= 70)
        
        severity_counts = {
            AlertSeverity.CRITICAL.value: 0,
            AlertSeverity.HIGH.value: 0,
            AlertSeverity.MEDIUM.value: 0,
            AlertSeverity.LOW.value: 0,
        }
        for alert in alerts_result.get("alerts", []):
            severity_counts[alert.severity.value] = severity_counts.get(alert.severity.value, 0) + 1
        
        # Technique breakdown
        technique_counts: Dict[str, int] = {}
        for t in all_typosquats:
            technique_counts[t.technique.value] = technique_counts.get(t.technique.value, 0) + 1
        
        return {
            "brand": monitor.model_dump(mode='json'),
            "generated_at": datetime.utcnow().isoformat(),
            "summary": {
                "total_typosquats": len(all_typosquats),
                "registered_domains": registered_count,
                "high_risk_domains": high_risk_count,
                "total_alerts": alerts_result.get("total", 0),
                "unacknowledged_alerts": sum(
                    1 for a in alerts_result.get("alerts", []) if not a.acknowledged
                ),
            },
            "alerts_by_severity": severity_counts,
            "typosquats_by_technique": technique_counts,
            "top_risk_domains": [
                t.model_dump(mode='json') 
                for t in sorted(all_typosquats, key=lambda x: x.risk_score, reverse=True)[:10]
            ],
            "recent_alerts": [
                a.model_dump(mode='json')
                for a in alerts_result.get("alerts", [])[:10]
            ],
        }
    
    # -------------------------------------------------------------------------
    # Suspicious Domain Check
    # -------------------------------------------------------------------------
    
    async def check_suspicious_domain(self, domain: str) -> Dict[str, Any]:
        """
        Check a domain against all monitored brands.
        
        Args:
            domain: Suspicious domain to check
            
        Returns:
            Analysis results including potential brand targets
        """
        results = {
            "domain": domain,
            "checked_at": datetime.utcnow().isoformat(),
            "is_suspicious": False,
            "potential_targets": [],
            "highest_similarity": 0.0,
            "recommended_action": None,
        }
        
        # Check against pre-configured African brands
        for brand_key, brand_info in AFRICAN_BRANDS.items():
            for legit_domain in brand_info['domains']:
                phishing_check = self.check_phishing_similarity(domain, legit_domain)
                
                if phishing_check.similarity_score > 0.5:
                    results["potential_targets"].append({
                        "brand": brand_info['brand_name'],
                        "legitimate_domain": legit_domain,
                        "similarity_score": phishing_check.similarity_score,
                        "visual_similarity": phishing_check.visual_similarity,
                        "text_similarity": phishing_check.text_similarity,
                        "is_phishing": phishing_check.is_phishing,
                        "risk_level": phishing_check.risk_level.value,
                        "techniques": phishing_check.techniques_detected,
                    })
                    
                    if phishing_check.similarity_score > results["highest_similarity"]:
                        results["highest_similarity"] = phishing_check.similarity_score
        
        # Sort by similarity
        results["potential_targets"].sort(
            key=lambda x: x["similarity_score"], 
            reverse=True
        )
        
        # Determine if suspicious
        if results["highest_similarity"] >= 0.7:
            results["is_suspicious"] = True
            results["recommended_action"] = "block"
        elif results["highest_similarity"] >= 0.5:
            results["is_suspicious"] = True
            results["recommended_action"] = "investigate"
        else:
            results["recommended_action"] = "allow"
        
        return results


# Singleton instance
brand_protection_service = BrandProtectionService()
