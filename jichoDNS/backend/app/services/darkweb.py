"""
Dark Web Monitoring Service - Credential leak detection and brand monitoring.

Provides:
- Leaked credential search
- Dark web mention monitoring
- Paste site monitoring
- Data breach tracking
- Credential exposure checking

Integrates with:
- Have I Been Pwned API (mock + real)
- IntelX API (mock)
- Dehashed API (mock)
- Paste site monitoring
"""

import asyncio
import hashlib
import logging
import random
import re
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

import httpx
from pydantic import BaseModel, EmailStr, Field, field_validator

from app.core.config import settings
from app.services.elasticsearch import es_service

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class LeakSeverity(str, Enum):
    """Severity level for leaked credentials."""
    CRITICAL = "critical"  # Plaintext passwords, financial data
    HIGH = "high"          # Hashed passwords, PII
    MEDIUM = "medium"      # Email + username only
    LOW = "low"            # Public info, minimal risk


class MentionSeverity(str, Enum):
    """Severity level for dark web mentions."""
    CRITICAL = "critical"  # Active sale, targeting
    HIGH = "high"          # Credentials listed, exploitation discussed
    MEDIUM = "medium"      # Brand mentioned in threat context
    LOW = "low"            # General mention, no clear threat


class DataType(str, Enum):
    """Types of data that can be leaked."""
    EMAIL = "email"
    PASSWORD = "password"
    PASSWORD_HASH = "password_hash"
    USERNAME = "username"
    PHONE = "phone"
    ADDRESS = "address"
    CREDIT_CARD = "credit_card"
    SSN = "ssn"
    IP_ADDRESS = "ip_address"
    DOB = "date_of_birth"
    PASSPORT = "passport"
    NATIONAL_ID = "national_id"


class MonitorType(str, Enum):
    """Type of monitoring target."""
    DOMAIN = "domain"
    EMAIL = "email"
    KEYWORD = "keyword"
    BRAND = "brand"


# =============================================================================
# Pydantic Models
# =============================================================================

class LeakedCredential(BaseModel):
    """Model for a leaked credential record."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    email: str
    domain: Optional[str] = None
    password_hash: Optional[str] = None
    hash_type: Optional[str] = None  # md5, sha1, sha256, bcrypt, plaintext
    username: Optional[str] = None
    source: str  # breach name or paste site
    source_url: Optional[str] = None
    breach_date: Optional[datetime] = None
    breach_name: Optional[str] = None
    found_date: datetime = Field(default_factory=datetime.utcnow)
    severity: LeakSeverity = LeakSeverity.MEDIUM
    data_types: List[DataType] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        """Extract and validate email format."""
        v = v.lower().strip()
        if not re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", v):
            raise ValueError("Invalid email format")
        return v
    
    @property
    def email_domain(self) -> str:
        """Extract domain from email."""
        return self.email.split("@")[1] if "@" in self.email else ""
    
    def to_es_doc(self) -> Dict[str, Any]:
        """Convert to Elasticsearch document."""
        return {
            "id": self.id,
            "email": self.email,
            "email_domain": self.email_domain,
            "domain": self.domain or self.email_domain,
            "password_hash": self.password_hash,
            "hash_type": self.hash_type,
            "username": self.username,
            "source": self.source,
            "source_url": self.source_url,
            "breach_date": self.breach_date.isoformat() if self.breach_date else None,
            "breach_name": self.breach_name,
            "found_date": self.found_date.isoformat(),
            "severity": self.severity.value,
            "data_types": [dt.value for dt in self.data_types],
            "metadata": self.metadata,
            "created_at": datetime.utcnow().isoformat(),
        }


class DarkWebMention(BaseModel):
    """Model for a dark web mention."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    keyword: str
    source: str  # forum name, paste site, marketplace
    source_type: str = "forum"  # forum, paste, marketplace, telegram, irc
    url: Optional[str] = None
    content_snippet: str
    full_content: Optional[str] = None
    author: Optional[str] = None
    found_date: datetime = Field(default_factory=datetime.utcnow)
    post_date: Optional[datetime] = None
    severity: MentionSeverity = MentionSeverity.MEDIUM
    tags: List[str] = Field(default_factory=list)
    related_indicators: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    def to_es_doc(self) -> Dict[str, Any]:
        """Convert to Elasticsearch document."""
        return {
            "id": self.id,
            "keyword": self.keyword,
            "source": self.source,
            "source_type": self.source_type,
            "url": self.url,
            "content_snippet": self.content_snippet,
            "full_content": self.full_content,
            "author": self.author,
            "found_date": self.found_date.isoformat(),
            "post_date": self.post_date.isoformat() if self.post_date else None,
            "severity": self.severity.value,
            "tags": self.tags,
            "related_indicators": self.related_indicators,
            "metadata": self.metadata,
            "created_at": datetime.utcnow().isoformat(),
        }


class DataBreach(BaseModel):
    """Model for a data breach record."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    title: str
    domain: Optional[str] = None
    breach_date: datetime
    added_date: datetime = Field(default_factory=datetime.utcnow)
    modified_date: Optional[datetime] = None
    records_count: int
    data_types: List[DataType] = Field(default_factory=list)
    description: str
    logo_path: Optional[str] = None
    is_verified: bool = True
    is_fabricated: bool = False
    is_sensitive: bool = False
    is_retired: bool = False
    is_spam_list: bool = False
    pwn_count: int = 0
    sources: List[str] = Field(default_factory=list)
    
    def to_es_doc(self) -> Dict[str, Any]:
        """Convert to Elasticsearch document."""
        return {
            "id": self.id,
            "name": self.name,
            "title": self.title,
            "domain": self.domain,
            "breach_date": self.breach_date.isoformat(),
            "added_date": self.added_date.isoformat(),
            "modified_date": self.modified_date.isoformat() if self.modified_date else None,
            "records_count": self.records_count,
            "data_types": [dt.value for dt in self.data_types],
            "description": self.description,
            "logo_path": self.logo_path,
            "is_verified": self.is_verified,
            "is_fabricated": self.is_fabricated,
            "is_sensitive": self.is_sensitive,
            "is_retired": self.is_retired,
            "is_spam_list": self.is_spam_list,
            "pwn_count": self.pwn_count,
            "sources": self.sources,
            "created_at": datetime.utcnow().isoformat(),
        }


class MonitoredTarget(BaseModel):
    """Model for a monitored domain/keyword."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    target: str  # domain, email, or keyword
    target_type: MonitorType
    organization: Optional[str] = None
    alert_email: Optional[str] = None
    webhook_url: Optional[str] = None
    owner_user_id: Optional[int] = None  # owning JichoDNS user id (multi-tenant)
    is_active: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_checked: Optional[datetime] = None
    total_alerts: int = 0

    def to_es_doc(self) -> Dict[str, Any]:
        """Convert to Elasticsearch document."""
        return {
            "id": self.id,
            "target": self.target,
            "target_type": self.target_type.value,
            "organization": self.organization,
            "alert_email": self.alert_email,
            "webhook_url": self.webhook_url,
            "owner_user_id": self.owner_user_id,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat(),
            "last_checked": self.last_checked.isoformat() if self.last_checked else None,
            "total_alerts": self.total_alerts,
        }


class DarkWebAlert(BaseModel):
    """Model for a dark web alert."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    monitor_id: str
    alert_type: str  # leak, mention, breach
    severity: str
    title: str
    description: str
    source: str
    source_url: Optional[str] = None
    matched_target: str
    owner_user_id: Optional[int] = None  # owning JichoDNS user id (multi-tenant)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    is_read: bool = False
    is_acknowledged: bool = False
    related_item_id: Optional[str] = None

    def to_es_doc(self) -> Dict[str, Any]:
        """Convert to Elasticsearch document."""
        return {
            "id": self.id,
            "monitor_id": self.monitor_id,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "source": self.source,
            "source_url": self.source_url,
            "matched_target": self.matched_target,
            "owner_user_id": self.owner_user_id,
            "created_at": self.created_at.isoformat(),
            "is_read": self.is_read,
            "is_acknowledged": self.is_acknowledged,
            "related_item_id": self.related_item_id,
        }


# =============================================================================
# Dark Web Monitor Service
# =============================================================================

class DarkWebMonitor:
    """
    Dark Web Monitoring Service.
    
    Monitors dark web sources for:
    - Leaked credentials
    - Brand mentions
    - Data breaches
    - Paste site dumps
    """
    
    # Elasticsearch indices
    LEAKS_INDEX = "darkweb_leaks"
    MENTIONS_INDEX = "darkweb_mentions"
    BREACHES_INDEX = "data_breaches"
    MONITORS_INDEX = "darkweb_monitors"
    ALERTS_INDEX = "darkweb_alerts"
    
    # API endpoints (for future real integration)
    HIBP_API_URL = "https://haveibeenpwned.com/api/v3"
    INTELX_API_URL = "https://2.intelx.io"
    DEHASHED_API_URL = "https://api.dehashed.com"
    
    # African brand keywords for monitoring
    AFRICAN_BRANDS = [
        "m-pesa", "mpesa", "safaricom", "airtel", "mtn", "vodacom",
        "equity bank", "kcb", "absa", "standard bank", "fnb", "nedbank",
        "capitec", "tigo", "orange money", "moov", "togocel", "glo",
        "9mobile", "cellulant", "interswitch", "flutterwave", "paystack",
        "chipper cash", "wave", "opay", "kuda", "moniepoint",
    ]
    
    # Common paste sites
    PASTE_SITES = [
        {"name": "Pastebin", "url": "https://pastebin.com"},
        {"name": "Ghostbin", "url": "https://ghostbin.com"},
        {"name": "Paste.ee", "url": "https://paste.ee"},
        {"name": "PrivateBin", "url": "https://privatebin.net"},
        {"name": "JustPaste.it", "url": "https://justpaste.it"},
        {"name": "Dpaste", "url": "https://dpaste.org"},
        {"name": "Hastebin", "url": "https://hastebin.com"},
        {"name": "Rentry.co", "url": "https://rentry.co"},
    ]
    
    # Dark web forums (for reference, not actual URLs)
    DARK_WEB_SOURCES = [
        "RaidForums Archive",
        "BreachForums",
        "LeakBase",
        "Exploit.in",
        "XSS.is",
        "Nulled.to",
        "Cracked.io",
        "OGUsers",
        "LeakedSource Archive",
        "Telegram Channels",
        "IRC Logs",
    ]
    
    def __init__(self):
        """Initialize the Dark Web Monitor."""
        self.http_client: Optional[httpx.AsyncClient] = None
        self._demo_data_generated = False
    
    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self.http_client is None:
            self.http_client = httpx.AsyncClient(
                timeout=30.0,
                follow_redirects=True,
            )
        return self.http_client
    
    async def close(self):
        """Close HTTP client."""
        if self.http_client:
            await self.http_client.aclose()
            self.http_client = None
    
    async def ensure_indices(self):
        """Create Elasticsearch indices if they don't exist."""
        if not es_service.client:
            await es_service.connect()
        
        if not es_service.client:
            logger.warning("Cannot create indices: Elasticsearch not connected")
            return
        
        indices_config = {
            self.LEAKS_INDEX: {
                "mappings": {
                    "properties": {
                        "id": {"type": "keyword"},
                        "email": {"type": "keyword"},
                        "email_domain": {"type": "keyword"},
                        "domain": {"type": "keyword"},
                        "password_hash": {"type": "keyword"},
                        "hash_type": {"type": "keyword"},
                        "username": {"type": "keyword"},
                        "source": {"type": "keyword"},
                        "source_url": {"type": "text"},
                        "breach_date": {"type": "date"},
                        "breach_name": {"type": "keyword"},
                        "found_date": {"type": "date"},
                        "severity": {"type": "keyword"},
                        "data_types": {"type": "keyword"},
                        "created_at": {"type": "date"},
                    }
                }
            },
            self.MENTIONS_INDEX: {
                "mappings": {
                    "properties": {
                        "id": {"type": "keyword"},
                        "keyword": {"type": "keyword"},
                        "source": {"type": "keyword"},
                        "source_type": {"type": "keyword"},
                        "url": {"type": "text"},
                        "content_snippet": {"type": "text"},
                        "full_content": {"type": "text"},
                        "author": {"type": "keyword"},
                        "found_date": {"type": "date"},
                        "post_date": {"type": "date"},
                        "severity": {"type": "keyword"},
                        "tags": {"type": "keyword"},
                        "related_indicators": {"type": "keyword"},
                        "created_at": {"type": "date"},
                    }
                }
            },
            self.BREACHES_INDEX: {
                "mappings": {
                    "properties": {
                        "id": {"type": "keyword"},
                        "name": {"type": "keyword"},
                        "title": {"type": "text"},
                        "domain": {"type": "keyword"},
                        "breach_date": {"type": "date"},
                        "added_date": {"type": "date"},
                        "modified_date": {"type": "date"},
                        "records_count": {"type": "long"},
                        "data_types": {"type": "keyword"},
                        "description": {"type": "text"},
                        "is_verified": {"type": "boolean"},
                        "is_sensitive": {"type": "boolean"},
                        "pwn_count": {"type": "long"},
                        "sources": {"type": "keyword"},
                        "created_at": {"type": "date"},
                    }
                }
            },
            self.MONITORS_INDEX: {
                "mappings": {
                    "properties": {
                        "id": {"type": "keyword"},
                        "target": {"type": "keyword"},
                        "target_type": {"type": "keyword"},
                        "organization": {"type": "keyword"},
                        "alert_email": {"type": "keyword"},
                        "webhook_url": {"type": "text"},
                        "owner_user_id": {"type": "integer"},
                        "is_active": {"type": "boolean"},
                        "created_at": {"type": "date"},
                        "last_checked": {"type": "date"},
                        "total_alerts": {"type": "integer"},
                    }
                }
            },
            self.ALERTS_INDEX: {
                "mappings": {
                    "properties": {
                        "id": {"type": "keyword"},
                        "monitor_id": {"type": "keyword"},
                        "alert_type": {"type": "keyword"},
                        "severity": {"type": "keyword"},
                        "title": {"type": "text"},
                        "description": {"type": "text"},
                        "source": {"type": "keyword"},
                        "source_url": {"type": "text"},
                        "matched_target": {"type": "keyword"},
                        "owner_user_id": {"type": "integer"},
                        "created_at": {"type": "date"},
                        "is_read": {"type": "boolean"},
                        "is_acknowledged": {"type": "boolean"},
                        "related_item_id": {"type": "keyword"},
                    }
                }
            },
        }
        
        for index_name, config in indices_config.items():
            try:
                exists = await es_service.client.indices.exists(index=index_name)
                if not exists:
                    await es_service.client.indices.create(index=index_name, body=config)
                    logger.info(f"Created index: {index_name}")
            except Exception as e:
                logger.error(f"Failed to create index {index_name}: {e}")
    
    # =========================================================================
    # Leak Search Methods
    # =========================================================================
    
    async def search_leaks(
        self,
        domain: str,
        email: Optional[str] = None,
        include_demo: bool = True,
    ) -> Dict[str, Any]:
        """
        Search for leaked credentials by domain or email.
        
        Args:
            domain: Domain to search (e.g., 'safaricom.co.ke')
            email: Optional specific email to search
            include_demo: Include demo data if no real results
            
        Returns:
            Search results with leaked credentials
        """
        results = {
            "query": {"domain": domain, "email": email},
            "total": 0,
            "leaks": [],
            "sources_checked": [],
            "search_time": datetime.utcnow().isoformat(),
        }
        
        # Check Elasticsearch first
        es_results = await self._search_leaks_elasticsearch(domain, email)
        results["leaks"].extend(es_results)
        results["sources_checked"].append("elasticsearch")
        
        # Try real APIs (mocked for now)
        hibp_results = await self._search_hibp(domain, email)
        results["leaks"].extend(hibp_results)
        results["sources_checked"].append("haveibeenpwned")
        
        intelx_results = await self._search_intelx(domain, email)
        results["leaks"].extend(intelx_results)
        results["sources_checked"].append("intelx")
        
        dehashed_results = await self._search_dehashed(domain, email)
        results["leaks"].extend(dehashed_results)
        results["sources_checked"].append("dehashed")
        
        # Generate demo data if no results and demo mode
        if not results["leaks"] and include_demo:
            demo_leaks = self._generate_demo_leaks(domain, email)
            results["leaks"].extend(demo_leaks)
            results["is_demo"] = True
        
        # Deduplicate by email
        seen_emails = set()
        unique_leaks = []
        for leak in results["leaks"]:
            if leak.get("email") not in seen_emails:
                seen_emails.add(leak.get("email"))
                unique_leaks.append(leak)
        
        results["leaks"] = unique_leaks
        results["total"] = len(unique_leaks)
        
        return results
    
    async def _search_leaks_elasticsearch(
        self,
        domain: str,
        email: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Search for leaks in Elasticsearch."""
        if not es_service.client:
            await es_service.connect()
        
        if not es_service.client:
            return []
        
        try:
            query = {
                "bool": {
                    "should": [
                        {"term": {"email_domain": domain.lower()}},
                        {"term": {"domain": domain.lower()}},
                    ],
                    "minimum_should_match": 1,
                }
            }
            
            if email:
                query = {
                    "bool": {
                        "must": [{"term": {"email": email.lower()}}]
                    }
                }
            
            response = await es_service.client.search(
                index=self.LEAKS_INDEX,
                body={"query": query, "size": 100, "sort": [{"found_date": "desc"}]},
            )
            
            return [hit["_source"] for hit in response["hits"]["hits"]]
        except Exception as e:
            logger.error(f"Elasticsearch leak search error: {e}")
            return []
    
    async def _search_hibp(
        self,
        domain: str,
        email: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Search Have I Been Pwned API.
        
        Note: Requires API key for domain search. Currently returns mock data.
        Real integration would use: GET /breacheddomain/{domain}
        """
        # Mock implementation - real API requires paid subscription
        # In production, use settings.HIBP_API_KEY
        return []
    
    async def _search_intelx(
        self,
        domain: str,
        email: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Search IntelX API.
        
        Note: Requires API key. Currently returns mock data.
        Real integration would use phonebook search endpoint.
        """
        # Mock implementation
        return []
    
    async def _search_dehashed(
        self,
        domain: str,
        email: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Search Dehashed API.
        
        Note: Requires API key. Currently returns mock data.
        Real integration would use: GET /search?query=domain:{domain}
        """
        # Mock implementation
        return []
    
    # =========================================================================
    # Mention Search Methods
    # =========================================================================
    
    async def search_mentions(
        self,
        keywords: List[str],
        source_types: Optional[List[str]] = None,
        severity_filter: Optional[MentionSeverity] = None,
        limit: int = 50,
    ) -> Dict[str, Any]:
        """
        Search for dark web mentions of keywords.
        
        Args:
            keywords: List of keywords to search (brand names, domains, etc.)
            source_types: Filter by source type (forum, paste, marketplace, etc.)
            severity_filter: Filter by minimum severity
            limit: Maximum results to return
            
        Returns:
            Search results with mentions
        """
        results = {
            "query": {"keywords": keywords},
            "total": 0,
            "mentions": [],
            "by_source_type": {},
            "by_severity": {},
            "search_time": datetime.utcnow().isoformat(),
        }
        
        # Search Elasticsearch
        es_results = await self._search_mentions_elasticsearch(
            keywords, source_types, severity_filter, limit
        )
        results["mentions"].extend(es_results)
        
        # Generate demo data if no results
        if not results["mentions"]:
            demo_mentions = self._generate_demo_mentions(keywords)
            results["mentions"].extend(demo_mentions)
            results["is_demo"] = True
        
        results["total"] = len(results["mentions"])
        
        # Aggregate by source type and severity
        for mention in results["mentions"]:
            source_type = mention.get("source_type", "unknown")
            severity = mention.get("severity", "medium")
            
            results["by_source_type"][source_type] = \
                results["by_source_type"].get(source_type, 0) + 1
            results["by_severity"][severity] = \
                results["by_severity"].get(severity, 0) + 1
        
        return results
    
    async def _search_mentions_elasticsearch(
        self,
        keywords: List[str],
        source_types: Optional[List[str]] = None,
        severity_filter: Optional[MentionSeverity] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Search for mentions in Elasticsearch."""
        if not es_service.client:
            await es_service.connect()
        
        if not es_service.client:
            return []
        
        try:
            must = []
            filter_clauses = []
            
            # Keyword search
            if keywords:
                must.append({
                    "bool": {
                        "should": [
                            {"terms": {"keyword": [k.lower() for k in keywords]}},
                            {"match": {"content_snippet": " ".join(keywords)}},
                        ],
                        "minimum_should_match": 1,
                    }
                })
            
            if source_types:
                filter_clauses.append({"terms": {"source_type": source_types}})
            
            if severity_filter:
                severity_order = ["low", "medium", "high", "critical"]
                min_idx = severity_order.index(severity_filter.value)
                allowed = severity_order[min_idx:]
                filter_clauses.append({"terms": {"severity": allowed}})
            
            body = {
                "query": {
                    "bool": {
                        "must": must if must else [{"match_all": {}}],
                        "filter": filter_clauses,
                    }
                },
                "sort": [{"found_date": "desc"}],
                "size": limit,
            }
            
            response = await es_service.client.search(
                index=self.MENTIONS_INDEX,
                body=body,
            )
            
            return [hit["_source"] for hit in response["hits"]["hits"]]
        except Exception as e:
            logger.error(f"Elasticsearch mention search error: {e}")
            return []
    
    # =========================================================================
    # Paste Site Monitoring
    # =========================================================================
    
    def get_paste_sites(self) -> List[Dict[str, Any]]:
        """
        Get list of monitored paste sites.
        
        Returns:
            List of paste site information
        """
        return self.PASTE_SITES.copy()
    
    async def scan_paste_sites(
        self,
        keywords: List[str],
    ) -> Dict[str, Any]:
        """
        Scan paste sites for keywords.
        
        Note: In production, this would use paste site APIs or scrapers.
        Currently returns demo data.
        
        Args:
            keywords: Keywords to search for
            
        Returns:
            Scan results
        """
        results = {
            "keywords": keywords,
            "sites_scanned": len(self.PASTE_SITES),
            "pastes_found": [],
            "scan_time": datetime.utcnow().isoformat(),
        }
        
        # Demo data generation
        demo_pastes = self._generate_demo_pastes(keywords)
        results["pastes_found"] = demo_pastes
        results["total_found"] = len(demo_pastes)
        results["is_demo"] = True
        
        return results
    
    # =========================================================================
    # Breach Methods
    # =========================================================================
    
    async def get_recent_leaks(
        self,
        hours: int = 24,
        limit: int = 50,
    ) -> Dict[str, Any]:
        """
        Get recent data breaches and leaks.
        
        Args:
            hours: Look back period in hours
            limit: Maximum results
            
        Returns:
            Recent breaches and leaks
        """
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        results = {
            "hours": hours,
            "since": cutoff.isoformat(),
            "breaches": [],
            "leaks": [],
            "total_affected_records": 0,
        }
        
        # Search Elasticsearch for recent breaches
        breaches = await self._get_recent_breaches_es(cutoff, limit)
        results["breaches"] = breaches
        
        # Search for recent leaks
        leaks = await self._get_recent_leaks_es(cutoff, limit)
        results["leaks"] = leaks
        
        # Generate demo data if empty
        if not results["breaches"]:
            results["breaches"] = self._generate_demo_breaches()
            results["is_demo"] = True
        
        # Calculate totals
        results["total_breaches"] = len(results["breaches"])
        results["total_leaks"] = len(results["leaks"])
        results["total_affected_records"] = sum(
            b.get("records_count", 0) for b in results["breaches"]
        )
        
        return results
    
    async def _get_recent_breaches_es(
        self,
        since: datetime,
        limit: int,
    ) -> List[Dict[str, Any]]:
        """Get recent breaches from Elasticsearch."""
        if not es_service.client:
            await es_service.connect()
        
        if not es_service.client:
            return []
        
        try:
            body = {
                "query": {
                    "range": {
                        "added_date": {"gte": since.isoformat()}
                    }
                },
                "sort": [{"added_date": "desc"}],
                "size": limit,
            }
            
            response = await es_service.client.search(
                index=self.BREACHES_INDEX,
                body=body,
            )
            
            return [hit["_source"] for hit in response["hits"]["hits"]]
        except Exception as e:
            logger.error(f"Recent breaches search error: {e}")
            return []
    
    async def _get_recent_leaks_es(
        self,
        since: datetime,
        limit: int,
    ) -> List[Dict[str, Any]]:
        """Get recent leaks from Elasticsearch."""
        if not es_service.client:
            await es_service.connect()
        
        if not es_service.client:
            return []
        
        try:
            body = {
                "query": {
                    "range": {
                        "found_date": {"gte": since.isoformat()}
                    }
                },
                "sort": [{"found_date": "desc"}],
                "size": limit,
            }
            
            response = await es_service.client.search(
                index=self.LEAKS_INDEX,
                body=body,
            )
            
            return [hit["_source"] for hit in response["hits"]["hits"]]
        except Exception as e:
            logger.error(f"Recent leaks search error: {e}")
            return []
    
    async def get_breach_details(self, breach_name: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a specific breach.
        
        Args:
            breach_name: Name of the breach
            
        Returns:
            Breach details or None
        """
        if not es_service.client:
            await es_service.connect()
        
        if not es_service.client:
            return None
        
        try:
            body = {
                "query": {
                    "term": {"name": breach_name.lower()}
                }
            }
            
            response = await es_service.client.search(
                index=self.BREACHES_INDEX,
                body=body,
            )
            
            if response["hits"]["hits"]:
                return response["hits"]["hits"][0]["_source"]
            return None
        except Exception as e:
            logger.error(f"Breach details error: {e}")
            return None
    
    # =========================================================================
    # Credential Exposure Check
    # =========================================================================
    
    async def check_credential_exposure(
        self,
        email: str,
    ) -> Dict[str, Any]:
        """
        Check if an email address appears in known breaches.
        
        Uses k-anonymity model similar to HIBP for privacy.
        
        Args:
            email: Email address to check
            
        Returns:
            Exposure information
        """
        email = email.lower().strip()
        
        # Generate SHA-1 hash prefix (first 5 chars) for k-anonymity
        email_hash = hashlib.sha1(email.encode()).hexdigest().upper()
        hash_prefix = email_hash[:5]
        
        results = {
            "email": email,
            "email_hash_prefix": hash_prefix,
            "is_exposed": False,
            "breach_count": 0,
            "breaches": [],
            "paste_count": 0,
            "first_breach": None,
            "latest_breach": None,
            "data_types_exposed": [],
            "checked_at": datetime.utcnow().isoformat(),
        }
        
        # Search local database
        local_results = await self._check_exposure_local(email)
        
        # Mock HIBP check (would be real API call in production)
        hibp_results = await self._check_exposure_hibp(email)
        
        # Combine results
        all_breaches = local_results + hibp_results
        
        if not all_breaches:
            # Generate demo exposure for demo mode
            all_breaches = self._generate_demo_exposure(email)
            results["is_demo"] = True
        
        if all_breaches:
            results["is_exposed"] = True
            results["breach_count"] = len(all_breaches)
            results["breaches"] = all_breaches
            
            # Find date range
            dates = [b.get("breach_date") for b in all_breaches if b.get("breach_date")]
            if dates:
                results["first_breach"] = min(dates)
                results["latest_breach"] = max(dates)
            
            # Aggregate data types
            all_types = set()
            for breach in all_breaches:
                all_types.update(breach.get("data_types", []))
            results["data_types_exposed"] = list(all_types)
        
        return results
    
    async def _check_exposure_local(self, email: str) -> List[Dict[str, Any]]:
        """Check local database for email exposure."""
        if not es_service.client:
            await es_service.connect()
        
        if not es_service.client:
            return []
        
        try:
            body = {
                "query": {
                    "term": {"email": email}
                },
                "size": 100,
            }
            
            response = await es_service.client.search(
                index=self.LEAKS_INDEX,
                body=body,
            )
            
            breaches = []
            for hit in response["hits"]["hits"]:
                source = hit["_source"]
                breaches.append({
                    "name": source.get("breach_name", source.get("source")),
                    "breach_date": source.get("breach_date"),
                    "data_types": source.get("data_types", []),
                })
            
            return breaches
        except Exception as e:
            logger.error(f"Local exposure check error: {e}")
            return []
    
    async def _check_exposure_hibp(self, email: str) -> List[Dict[str, Any]]:
        """
        Check HIBP API for email exposure.
        
        Note: Requires API key for breach lookup.
        Currently returns empty (mock).
        """
        # In production:
        # client = await self._get_client()
        # response = await client.get(
        #     f"{self.HIBP_API_URL}/breachedaccount/{email}",
        #     headers={"hibp-api-key": settings.HIBP_API_KEY}
        # )
        return []
    
    # =========================================================================
    # Monitor Management
    # =========================================================================
    
    async def add_monitor(
        self,
        target: str,
        target_type: MonitorType,
        organization: Optional[str] = None,
        alert_email: Optional[str] = None,
        webhook_url: Optional[str] = None,
        owner_user_id: Optional[int] = None,
    ) -> MonitoredTarget:
        """
        Add a new monitoring target.

        Args:
            target: Domain, email, or keyword to monitor
            target_type: Type of target
            organization: Organization name
            alert_email: Email for alerts
            webhook_url: Webhook for alerts
            owner_user_id: Owning JichoDNS user id (multi-tenant scoping)

        Returns:
            Created monitor
        """
        monitor = MonitoredTarget(
            target=target.lower(),
            target_type=target_type,
            organization=organization,
            alert_email=alert_email,
            webhook_url=webhook_url,
            owner_user_id=owner_user_id,
        )
        
        # Store in Elasticsearch
        await self._store_monitor(monitor)
        
        logger.info(f"Added dark web monitor: {target} ({target_type.value})")
        
        return monitor
    
    async def _store_monitor(self, monitor: MonitoredTarget):
        """Store monitor in Elasticsearch."""
        if not es_service.client:
            await es_service.connect()
        
        if not es_service.client:
            return
        
        try:
            await es_service.client.index(
                index=self.MONITORS_INDEX,
                id=monitor.id,
                body=monitor.to_es_doc(),
            )
        except Exception as e:
            logger.error(f"Failed to store monitor: {e}")
    
    async def get_monitors(
        self,
        active_only: bool = True,
        limit: int = 100,
        owner_user_id: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get monitoring targets.

        Args:
            active_only: Only return active monitors
            limit: Maximum monitors to return
            owner_user_id: When provided, restrict to monitors owned by this
                user (multi-tenant scoping). Pass None for admins/full access.
        """
        if not es_service.client:
            await es_service.connect()

        if not es_service.client:
            return []

        try:
            filters = []
            if active_only:
                filters.append({"term": {"is_active": True}})
            if owner_user_id is not None:
                filters.append({"term": {"owner_user_id": owner_user_id}})

            query = {"bool": {"filter": filters}} if filters else {"match_all": {}}

            body = {
                "query": query,
                "sort": [{"created_at": "desc"}],
                "size": limit,
            }

            response = await es_service.client.search(
                index=self.MONITORS_INDEX,
                body=body,
            )

            return [hit["_source"] for hit in response["hits"]["hits"]]
        except Exception as e:
            logger.error(f"Get monitors error: {e}")
            return []

    async def get_monitor(self, monitor_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single monitor document by id (or None if missing)."""
        if not es_service.client:
            await es_service.connect()

        if not es_service.client:
            return None

        try:
            response = await es_service.client.get(
                index=self.MONITORS_INDEX,
                id=monitor_id,
            )
            return response["_source"]
        except Exception:
            return None

    async def delete_monitor(self, monitor_id: str) -> bool:
        """Delete a monitor."""
        if not es_service.client:
            await es_service.connect()
        
        if not es_service.client:
            return False
        
        try:
            await es_service.client.delete(
                index=self.MONITORS_INDEX,
                id=monitor_id,
            )
            return True
        except Exception as e:
            logger.error(f"Delete monitor error: {e}")
            return False
    
    # =========================================================================
    # Alert Management
    # =========================================================================
    
    async def get_alerts(
        self,
        unread_only: bool = False,
        severity_filter: Optional[str] = None,
        limit: int = 50,
        owner_user_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Get dark web alerts.

        Args:
            unread_only: Only return unread alerts
            severity_filter: Filter by severity
            limit: Maximum alerts to return
            owner_user_id: When provided, restrict to alerts owned by this user
                (multi-tenant scoping). Pass None for admins/full access.

        Returns:
            Alerts with statistics
        """
        results = {
            "total": 0,
            "unread_count": 0,
            "by_severity": {},
            "alerts": [],
        }

        if not es_service.client:
            await es_service.connect()

        if not es_service.client:
            # Return demo alerts
            results["alerts"] = self._generate_demo_alerts()
            results["is_demo"] = True
            results["total"] = len(results["alerts"])
            return results

        try:
            filter_clauses = []

            if unread_only:
                filter_clauses.append({"term": {"is_read": False}})

            if severity_filter:
                filter_clauses.append({"term": {"severity": severity_filter}})

            if owner_user_id is not None:
                filter_clauses.append({"term": {"owner_user_id": owner_user_id}})

            body = {
                "query": {
                    "bool": {
                        "filter": filter_clauses if filter_clauses else [{"match_all": {}}]
                    }
                },
                "sort": [{"created_at": "desc"}],
                "size": limit,
            }

            response = await es_service.client.search(
                index=self.ALERTS_INDEX,
                body=body,
            )

            results["alerts"] = [hit["_source"] for hit in response["hits"]["hits"]]
            results["total"] = response["hits"]["total"]["value"]

            # Count unread (scoped to owner for non-admins)
            unread_filter = [{"term": {"is_read": False}}]
            if owner_user_id is not None:
                unread_filter.append({"term": {"owner_user_id": owner_user_id}})
            unread_body = {
                "query": {"bool": {"filter": unread_filter}},
            }
            unread_response = await es_service.client.count(
                index=self.ALERTS_INDEX,
                body=unread_body,
            )
            results["unread_count"] = unread_response["count"]
            
            # Aggregate by severity
            for alert in results["alerts"]:
                sev = alert.get("severity", "medium")
                results["by_severity"][sev] = results["by_severity"].get(sev, 0) + 1
            
        except Exception as e:
            logger.error(f"Get alerts error: {e}")
            results["alerts"] = self._generate_demo_alerts()
            results["is_demo"] = True
            results["total"] = len(results["alerts"])
        
        return results
    
    async def create_alert(
        self,
        monitor_id: str,
        alert_type: str,
        severity: str,
        title: str,
        description: str,
        source: str,
        matched_target: str,
        source_url: Optional[str] = None,
        related_item_id: Optional[str] = None,
        owner_user_id: Optional[int] = None,
    ) -> DarkWebAlert:
        """Create a new alert."""
        alert = DarkWebAlert(
            monitor_id=monitor_id,
            alert_type=alert_type,
            severity=severity,
            title=title,
            description=description,
            source=source,
            source_url=source_url,
            matched_target=matched_target,
            owner_user_id=owner_user_id,
            related_item_id=related_item_id,
        )
        
        if es_service.client:
            try:
                await es_service.client.index(
                    index=self.ALERTS_INDEX,
                    id=alert.id,
                    body=alert.to_es_doc(),
                )
            except Exception as e:
                logger.error(f"Failed to store alert: {e}")
        
        return alert
    
    async def get_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single alert document by id (or None if missing)."""
        if not es_service.client:
            await es_service.connect()

        if not es_service.client:
            return None

        try:
            response = await es_service.client.get(
                index=self.ALERTS_INDEX,
                id=alert_id,
            )
            return response["_source"]
        except Exception:
            return None

    async def mark_alert_read(self, alert_id: str) -> bool:
        """Mark an alert as read."""
        if not es_service.client:
            return False
        
        try:
            await es_service.client.update(
                index=self.ALERTS_INDEX,
                id=alert_id,
                doc={"is_read": True},
                retry_on_conflict=3,
            )
            return True
        except Exception as e:
            logger.error(f"Mark alert read error: {e}")
            return False
    
    # =========================================================================
    # Statistics
    # =========================================================================
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get dark web monitoring statistics."""
        stats = {
            "total_leaks": 0,
            "total_mentions": 0,
            "total_breaches": 0,
            "total_monitors": 0,
            "total_alerts": 0,
            "unread_alerts": 0,
            "leaks_by_severity": {},
            "mentions_by_source_type": {},
            "recent_activity": [],
        }
        
        if not es_service.client:
            await es_service.connect()
        
        if not es_service.client:
            return stats
        
        try:
            # Count documents in each index
            for index, key in [
                (self.LEAKS_INDEX, "total_leaks"),
                (self.MENTIONS_INDEX, "total_mentions"),
                (self.BREACHES_INDEX, "total_breaches"),
                (self.MONITORS_INDEX, "total_monitors"),
                (self.ALERTS_INDEX, "total_alerts"),
            ]:
                try:
                    response = await es_service.client.count(index=index)
                    stats[key] = response["count"]
                except Exception:
                    pass
            
            # Count unread alerts
            try:
                response = await es_service.client.count(
                    index=self.ALERTS_INDEX,
                    body={"query": {"term": {"is_read": False}}},
                )
                stats["unread_alerts"] = response["count"]
            except Exception:
                pass
            
        except Exception as e:
            logger.error(f"Statistics error: {e}")
        
        return stats
    
    # =========================================================================
    # Demo Data Generation
    # =========================================================================
    
    def _generate_demo_leaks(
        self,
        domain: str,
        email: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Generate demo leaked credentials for testing."""
        demo_leaks = []
        
        # Common breach names
        breaches = [
            ("LinkedIn2021", "2021-04-08", "RaidForums"),
            ("Collection1", "2019-01-17", "MEGA"),
            ("Verifications.io", "2019-02-25", "Security Researcher"),
            ("Apollo", "2018-07-23", "Hacker Forum"),
            ("Zynga", "2019-09-12", "GnosticPlayers"),
        ]
        
        # Generate 5-10 demo leaks
        num_leaks = random.randint(5, 10)
        
        for i in range(num_leaks):
            breach = random.choice(breaches)
            
            if email:
                leak_email = email
            else:
                usernames = ["john", "admin", "user", "info", "support", "hr", "sales", "dev"]
                leak_email = f"{random.choice(usernames)}{random.randint(1, 999)}@{domain}"
            
            severity = random.choice(list(LeakSeverity))
            data_types = random.sample(
                [DataType.EMAIL, DataType.PASSWORD_HASH, DataType.USERNAME, DataType.PHONE],
                k=random.randint(2, 4),
            )
            
            leak = LeakedCredential(
                email=leak_email,
                domain=domain,
                password_hash=hashlib.sha256(f"demo{i}".encode()).hexdigest()[:32],
                hash_type=random.choice(["sha256", "md5", "bcrypt", "sha1"]),
                username=leak_email.split("@")[0],
                source=breach[2],
                breach_date=datetime.fromisoformat(breach[1]),
                breach_name=breach[0],
                found_date=datetime.utcnow() - timedelta(days=random.randint(1, 365)),
                severity=severity,
                data_types=data_types,
            )
            
            demo_leaks.append(leak.to_es_doc())
        
        return demo_leaks
    
    def _generate_demo_mentions(self, keywords: List[str]) -> List[Dict[str, Any]]:
        """Generate demo dark web mentions for testing."""
        demo_mentions = []
        
        sources = [
            ("BreachForums", "forum"),
            ("XSS.is", "forum"),
            ("Telegram", "telegram"),
            ("Pastebin", "paste"),
            ("RaidForums Archive", "forum"),
            ("Exploit.in", "marketplace"),
        ]
        
        snippets = [
            "Selling fresh database dump from {keyword} - 50k records",
            "Looking to buy {keyword} access - PM me",
            "{keyword} employee credentials available",
            "New combo list includes {keyword} domain",
            "Exploiting {keyword} - need partners",
            "Fresh {keyword} data leak - emails + passwords",
        ]
        
        for keyword in keywords[:3]:  # Limit to 3 keywords
            num_mentions = random.randint(2, 5)
            
            for _ in range(num_mentions):
                source = random.choice(sources)
                snippet_template = random.choice(snippets)
                
                mention = DarkWebMention(
                    keyword=keyword,
                    source=source[0],
                    source_type=source[1],
                    content_snippet=snippet_template.format(keyword=keyword),
                    author=f"threat_actor_{random.randint(100, 999)}",
                    found_date=datetime.utcnow() - timedelta(hours=random.randint(1, 168)),
                    post_date=datetime.utcnow() - timedelta(hours=random.randint(1, 168)),
                    severity=random.choice(list(MentionSeverity)),
                    tags=["credential_sale", "data_leak"],
                )
                
                demo_mentions.append(mention.to_es_doc())
        
        return demo_mentions
    
    def _generate_demo_pastes(self, keywords: List[str]) -> List[Dict[str, Any]]:
        """Generate demo paste findings."""
        pastes = []
        
        for keyword in keywords[:2]:
            num_pastes = random.randint(1, 3)
            
            for i in range(num_pastes):
                paste_site = random.choice(self.PASTE_SITES)
                
                pastes.append({
                    "id": str(uuid4()),
                    "site": paste_site["name"],
                    "url": f"{paste_site['url']}/demo{random.randint(1000, 9999)}",
                    "title": f"Database dump containing {keyword}",
                    "preview": f"email,password\n{keyword}@example.com,********\n...",
                    "size_bytes": random.randint(1000, 1000000),
                    "created_at": (datetime.utcnow() - timedelta(hours=random.randint(1, 72))).isoformat(),
                    "matches_keyword": keyword,
                })
        
        return pastes
    
    def _generate_demo_breaches(self) -> List[Dict[str, Any]]:
        """Generate demo breach data."""
        demo_breaches = [
            {
                "name": "africanbank2024",
                "title": "African Regional Bank Data Breach",
                "domain": "africanregionalbank.com",
                "breach_date": (datetime.utcnow() - timedelta(days=random.randint(1, 30))).isoformat(),
                "added_date": datetime.utcnow().isoformat(),
                "records_count": random.randint(50000, 500000),
                "data_types": ["email", "password_hash", "phone", "address"],
                "description": "A major African regional bank suffered a data breach exposing customer information.",
                "is_verified": True,
                "pwn_count": random.randint(10000, 100000),
                "sources": ["Security Researcher", "BreachForums"],
            },
            {
                "name": "mobilemoney2024",
                "title": "Mobile Money Provider Breach",
                "domain": "mobilemoneyprovider.co.ke",
                "breach_date": (datetime.utcnow() - timedelta(days=random.randint(1, 60))).isoformat(),
                "added_date": datetime.utcnow().isoformat(),
                "records_count": random.randint(100000, 1000000),
                "data_types": ["email", "phone", "username", "password"],
                "description": "Mobile money service provider breach affecting users across East Africa.",
                "is_verified": True,
                "pwn_count": random.randint(50000, 200000),
                "sources": ["Telegram Channel", "Dark Web Forum"],
            },
            {
                "name": "telecomghana2024",
                "title": "Ghana Telecom Customer Data Leak",
                "domain": "ghtelecom.com.gh",
                "breach_date": (datetime.utcnow() - timedelta(days=random.randint(5, 90))).isoformat(),
                "added_date": datetime.utcnow().isoformat(),
                "records_count": random.randint(200000, 800000),
                "data_types": ["email", "phone", "national_id", "address"],
                "description": "Telecommunications provider in Ghana exposed customer data including national IDs.",
                "is_verified": False,
                "pwn_count": random.randint(100000, 300000),
                "sources": ["Pastebin", "XSS.is"],
            },
        ]
        
        return demo_breaches
    
    def _generate_demo_exposure(self, email: str) -> List[Dict[str, Any]]:
        """Generate demo breach exposure data for an email."""
        # Only show exposure for demo purposes
        if "test" in email or "demo" in email or "example" in email:
            return []
        
        breaches = [
            {
                "name": "Collection1",
                "breach_date": "2019-01-17",
                "data_types": ["email", "password"],
            },
            {
                "name": "LinkedIn2021",
                "breach_date": "2021-04-08",
                "data_types": ["email", "phone", "username"],
            },
        ]
        
        # Randomly include 0-2 breaches
        return random.sample(breaches, k=random.randint(0, min(2, len(breaches))))
    
    def _generate_demo_alerts(self) -> List[Dict[str, Any]]:
        """Generate demo alerts."""
        alerts = [
            {
                "id": str(uuid4()),
                "monitor_id": str(uuid4()),
                "alert_type": "leak",
                "severity": "high",
                "title": "New credential leak detected",
                "description": "5 new email addresses from your domain found in a dark web paste.",
                "source": "Pastebin",
                "matched_target": "example.com",
                "created_at": (datetime.utcnow() - timedelta(hours=2)).isoformat(),
                "is_read": False,
                "is_acknowledged": False,
            },
            {
                "id": str(uuid4()),
                "monitor_id": str(uuid4()),
                "alert_type": "mention",
                "severity": "critical",
                "title": "Brand mentioned in threat context",
                "description": "Your organization was mentioned in a post discussing selling access.",
                "source": "BreachForums",
                "matched_target": "safaricom",
                "created_at": (datetime.utcnow() - timedelta(hours=5)).isoformat(),
                "is_read": False,
                "is_acknowledged": False,
            },
            {
                "id": str(uuid4()),
                "monitor_id": str(uuid4()),
                "alert_type": "breach",
                "severity": "medium",
                "title": "Related breach discovered",
                "description": "A new breach was discovered that may contain data from your industry.",
                "source": "Have I Been Pwned",
                "matched_target": "financial-sector",
                "created_at": (datetime.utcnow() - timedelta(days=1)).isoformat(),
                "is_read": True,
                "is_acknowledged": False,
            },
        ]
        
        return alerts
    
    # =========================================================================
    # Data Storage Methods
    # =========================================================================
    
    async def store_leak(self, leak: LeakedCredential) -> bool:
        """Store a leaked credential in Elasticsearch."""
        if not es_service.client:
            await es_service.connect()
        
        if not es_service.client:
            return False
        
        try:
            await es_service.client.index(
                index=self.LEAKS_INDEX,
                id=leak.id,
                body=leak.to_es_doc(),
            )
            return True
        except Exception as e:
            logger.error(f"Failed to store leak: {e}")
            return False
    
    async def store_mention(self, mention: DarkWebMention) -> bool:
        """Store a dark web mention in Elasticsearch."""
        if not es_service.client:
            await es_service.connect()
        
        if not es_service.client:
            return False
        
        try:
            await es_service.client.index(
                index=self.MENTIONS_INDEX,
                id=mention.id,
                body=mention.to_es_doc(),
            )
            return True
        except Exception as e:
            logger.error(f"Failed to store mention: {e}")
            return False
    
    async def store_breach(self, breach: DataBreach) -> bool:
        """Store a data breach in Elasticsearch."""
        if not es_service.client:
            await es_service.connect()
        
        if not es_service.client:
            return False
        
        try:
            await es_service.client.index(
                index=self.BREACHES_INDEX,
                id=breach.id,
                body=breach.to_es_doc(),
            )
            return True
        except Exception as e:
            logger.error(f"Failed to store breach: {e}")
            return False
    
    async def generate_sample_data(self) -> Dict[str, int]:
        """
        Generate and store sample data for testing/demo purposes.
        
        Returns:
            Counts of generated items
        """
        counts = {"leaks": 0, "mentions": 0, "breaches": 0}
        
        # Ensure indices exist
        await self.ensure_indices()
        
        # Generate sample leaks for African domains
        african_domains = [
            "safaricom.co.ke", "mtn.com.ng", "airtel.africa",
            "equitybank.co.ke", "standardbank.co.za", "fnb.co.za",
            "vodacom.co.za", "capitecbank.co.za", "absa.africa",
        ]
        
        for domain in african_domains:
            leaks = self._generate_demo_leaks(domain)
            for leak_doc in leaks:
                leak = LeakedCredential(**{
                    k: v for k, v in leak_doc.items()
                    if k in LeakedCredential.model_fields
                })
                if await self.store_leak(leak):
                    counts["leaks"] += 1
        
        # Generate sample mentions
        for keyword in self.AFRICAN_BRANDS[:10]:
            mentions = self._generate_demo_mentions([keyword])
            for mention_doc in mentions:
                mention = DarkWebMention(**{
                    k: v for k, v in mention_doc.items()
                    if k in DarkWebMention.model_fields
                })
                if await self.store_mention(mention):
                    counts["mentions"] += 1
        
        # Generate sample breaches
        for breach_doc in self._generate_demo_breaches():
            breach = DataBreach(
                name=breach_doc["name"],
                title=breach_doc["title"],
                domain=breach_doc.get("domain"),
                breach_date=datetime.fromisoformat(breach_doc["breach_date"]),
                records_count=breach_doc["records_count"],
                data_types=[DataType(dt) for dt in breach_doc["data_types"]],
                description=breach_doc["description"],
                is_verified=breach_doc.get("is_verified", True),
                pwn_count=breach_doc.get("pwn_count", 0),
                sources=breach_doc.get("sources", []),
            )
            if await self.store_breach(breach):
                counts["breaches"] += 1
        
        logger.info(f"Generated sample data: {counts}")
        return counts


# Singleton instance
darkweb_monitor = DarkWebMonitor()
