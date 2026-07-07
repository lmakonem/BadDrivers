"""
Attack Surface Management (ASM) Service for JichoDNS.

Provides comprehensive attack surface discovery, monitoring, and vulnerability assessment
with integrations to Shodan, SecurityTrails, crt.sh, and DNS lookups.
"""

import asyncio
import hashlib
import logging
import re
import socket
import ssl
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from uuid import uuid4

import httpx
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from pydantic import BaseModel, Field, field_validator

from app.core.config import settings
from app.core.net_guard import resolve_public_ips, resolve_public_ips_sync, SSRFError

try:
    import dns.resolver
    import dns.asyncresolver
    import dns.rdatatype
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    logging.warning("dnspython not available - DNS lookups will be limited")

logger = logging.getLogger(__name__)


# =============================================================================
# Pydantic Models
# =============================================================================

class AssetType(str, Enum):
    """Types of assets that can be discovered."""
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    PORT = "port"
    SERVICE = "service"
    CERTIFICATE = "certificate"


class AssetStatus(str, Enum):
    """Status of a discovered asset."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    UNKNOWN = "unknown"
    VULNERABLE = "vulnerable"


class SeverityLevel(str, Enum):
    """Severity levels for vulnerabilities."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ChangeType(str, Enum):
    """Types of changes detected in assets."""
    NEW = "new"
    REMOVED = "removed"
    MODIFIED = "modified"
    PORT_OPENED = "port_opened"
    PORT_CLOSED = "port_closed"
    SERVICE_CHANGED = "service_changed"
    CERTIFICATE_CHANGED = "certificate_changed"
    IP_CHANGED = "ip_changed"


class Asset(BaseModel):
    """Represents a discovered asset in the attack surface."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    type: AssetType
    value: str
    parent_id: Optional[str] = None
    client_id: Optional[int] = None        # ASMClient.id — set by AttackSurfaceManager
    root_domain: Optional[str] = None      # seed domain that triggered discovery
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    status: AssetStatus = AssetStatus.ACTIVE
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    discovery_source: Optional[str] = None  # real source(s) that discovered this asset
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("risk_score")
    @classmethod
    def validate_risk_score(cls, v: float) -> float:
        return max(0.0, min(100.0, v))
    
    def to_es_doc(self) -> Dict[str, Any]:
        """Convert to Elasticsearch document."""
        return {
            "id": self.id,
            "type": self.type.value,
            "value": self.value,
            "parent_id": self.parent_id,
            "client_id": self.client_id,
            "root_domain": self.root_domain,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "status": self.status.value,
            "risk_score": self.risk_score,
            "discovery_source": self.discovery_source,
            "tags": self.tags,
            "metadata": self.metadata,
        }


class Vulnerability(BaseModel):
    """Represents a discovered vulnerability."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    cve_id: Optional[str] = None
    title: str
    severity: SeverityLevel
    description: str
    affected_asset_id: str
    affected_asset_value: str
    affected_asset_type: AssetType
    cvss_score: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    remediation: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    is_exploitable: bool = False
    exploit_available: bool = False
    
    def to_es_doc(self) -> Dict[str, Any]:
        """Convert to Elasticsearch document."""
        return {
            "id": self.id,
            "cve_id": self.cve_id,
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "affected_asset_id": self.affected_asset_id,
            "affected_asset_value": self.affected_asset_value,
            "affected_asset_type": self.affected_asset_type.value,
            "cvss_score": self.cvss_score,
            "remediation": self.remediation,
            "references": self.references,
            "detected_at": self.detected_at.isoformat(),
            "is_exploitable": self.is_exploitable,
            "exploit_available": self.exploit_available,
        }


class AssetChange(BaseModel):
    """Represents a change detected in an asset."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    asset_id: str
    asset_value: str
    change_type: ChangeType
    old_value: Optional[str] = None
    new_value: Optional[str] = None
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    details: Dict[str, Any] = Field(default_factory=dict)
    
    def to_es_doc(self) -> Dict[str, Any]:
        """Convert to Elasticsearch document."""
        return {
            "id": self.id,
            "asset_id": self.asset_id,
            "asset_value": self.asset_value,
            "change_type": self.change_type.value,
            "old_value": self.old_value,
            "new_value": self.new_value,
            "detected_at": self.detected_at.isoformat(),
            "details": self.details,
        }


class DNSRecord(BaseModel):
    """Represents a DNS record."""
    record_type: str
    value: str
    ttl: Optional[int] = None


class SSLCertInfo(BaseModel):
    """SSL/TLS certificate information."""
    subject: str
    issuer: str
    valid_from: datetime
    valid_until: datetime
    is_valid: bool
    is_expired: bool
    days_until_expiry: int
    serial_number: str
    fingerprint_sha256: str
    san_names: List[str] = Field(default_factory=list)
    key_size: Optional[int] = None
    signature_algorithm: Optional[str] = None
    issues: List[str] = Field(default_factory=list)


class ServiceInfo(BaseModel):
    """Information about an exposed service."""
    port: int
    protocol: str
    service_name: str
    version: Optional[str] = None
    banner: Optional[str] = None
    is_encrypted: bool = False
    vulnerabilities: List[str] = Field(default_factory=list)


class DiscoveryResult(BaseModel):
    """Result of asset discovery."""
    domain: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    assets: List[Asset] = Field(default_factory=list)
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    dns_records: List[DNSRecord] = Field(default_factory=list)
    ssl_info: Optional[SSLCertInfo] = None
    services: List[ServiceInfo] = Field(default_factory=list)
    subdomains: List[str] = Field(default_factory=list)
    ips: List[str] = Field(default_factory=list)
    total_risk_score: float = 0.0
    error: Optional[str] = None
    # Computed summary fields — populated after discovery completes
    total_ips: int = 0
    total_open_ports: int = 0
    ssl_issues: int = 0


# =============================================================================
# External API Clients (with Mock Support)
# =============================================================================

class ShodanClient:
    """Client for Shodan API with mock fallback."""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or settings.SHODAN_API_KEY
        self.base_url = "https://api.shodan.io"
        # Three states:
        #   real     — API key present
        #   mock     — no key but ALLOW_MOCK_DATA=true (explicit demo mode)
        #   disabled — no key and ALLOW_MOCK_DATA=false (prod default): SKIP source
        self.mock_mode = settings.ALLOW_MOCK_DATA and not bool(self.api_key)
        self.enabled = bool(self.api_key) or self.mock_mode

        if not self.enabled:
            logger.info(
                "Shodan client disabled (no SHODAN_API_KEY, ALLOW_MOCK_DATA=false) "
                "— Shodan source will be skipped and return empty results"
            )
        elif self.mock_mode:
            logger.warning(
                "Shodan client in MOCK mode (ALLOW_MOCK_DATA=true) — results are "
                "SYNTHETIC and must not be used in client-facing reports"
            )

    @staticmethod
    def _empty_host_info(ip: str) -> Dict[str, Any]:
        """Fail-closed empty host record (no ports/services/vulns)."""
        return {
            "ip": ip,
            "ip_str": ip,
            "ports": [],
            "hostnames": [],
            "data": [],
            "vulns": [],
        }

    async def get_host_info(self, ip: str) -> Dict[str, Any]:
        """Get information about a host from Shodan."""
        if not self.api_key:
            # Fail-closed: only fabricate when demo mode is explicitly enabled
            return self._mock_host_info(ip) if self.mock_mode else self._empty_host_info(ip)

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    f"{self.base_url}/shodan/host/{ip}",
                    params={"key": self.api_key}
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return self._empty_host_info(ip)
            logger.error(f"Shodan API error for {ip}: {e}")
            return self._empty_host_info(ip)
        except Exception as e:
            logger.error(f"Shodan request failed for {ip}: {e}")
            return self._empty_host_info(ip)

    async def search_domain(self, domain: str) -> Dict[str, Any]:
        """Search Shodan for domain information."""
        if not self.api_key:
            return (
                self._mock_domain_search(domain)
                if self.mock_mode
                else {"domain": domain, "subdomains": [], "data": []}
            )

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    f"{self.base_url}/dns/domain/{domain}",
                    params={"key": self.api_key}
                )
                response.raise_for_status()
                return response.json()
        except Exception as e:
            logger.error(f"Shodan domain search failed for {domain}: {e}")
            return {"domain": domain, "subdomains": [], "data": []}
    
    def _mock_host_info(self, ip: str) -> Dict[str, Any]:
        """Generate mock host information."""
        # Generate deterministic mock data based on IP
        ip_hash = int(hashlib.md5(ip.encode()).hexdigest()[:8], 16)
        ports = []
        
        # Common ports based on hash
        port_sets = [
            [22, 80, 443],
            [80, 443, 8080],
            [22, 80, 443, 3306],
            [80, 443, 22, 25, 587],
            [80, 443, 21, 22, 3389],
        ]
        ports = port_sets[ip_hash % len(port_sets)]
        
        return {
            "ip": ip,
            "ip_str": ip,
            "ports": ports,
            "hostnames": [],
            "country_code": "KE",  # Default to Kenya for Africa focus
            "org": "Mock Organization",
            "isp": "Mock ISP",
            "data": [
                {
                    "port": port,
                    "transport": "tcp",
                    "product": self._mock_service_name(port),
                    "version": "1.0.0",
                }
                for port in ports
            ],
            "vulns": [],
        }
    
    def _mock_domain_search(self, domain: str) -> Dict[str, Any]:
        """Generate mock domain search results."""
        domain_hash = int(hashlib.md5(domain.encode()).hexdigest()[:8], 16)
        
        # Generate mock subdomains
        prefixes = ["www", "mail", "api", "cdn", "dev", "staging", "admin"]
        subdomains = [f"{prefix}.{domain}" for prefix in prefixes[:3 + domain_hash % 4]]
        
        return {
            "domain": domain,
            "subdomains": subdomains,
            "data": [
                {"subdomain": sub, "type": "A", "value": f"192.168.{i}.{i+1}"}
                for i, sub in enumerate(subdomains)
            ],
        }
    
    def _mock_service_name(self, port: int) -> str:
        """Get service name for common ports."""
        services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            587: "SMTP",
            993: "IMAPS",
            995: "POP3S",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            6379: "Redis",
            8080: "HTTP-Proxy",
            8443: "HTTPS-Alt",
            27017: "MongoDB",
        }
        return services.get(port, f"Unknown-{port}")


class SecurityTrailsClient:
    """Client for SecurityTrails API with mock fallback."""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or settings.SECURITYTRAILS_API_KEY
        self.base_url = "https://api.securitytrails.com/v1"
        # Same three-state model as ShodanClient (real / mock / disabled)
        self.mock_mode = settings.ALLOW_MOCK_DATA and not bool(self.api_key)
        self.enabled = bool(self.api_key) or self.mock_mode

        if not self.enabled:
            logger.info(
                "SecurityTrails client disabled (no SECURITYTRAILS_API_KEY, "
                "ALLOW_MOCK_DATA=false) — source will be skipped and return empty"
            )
        elif self.mock_mode:
            logger.warning(
                "SecurityTrails client in MOCK mode (ALLOW_MOCK_DATA=true) — results "
                "are SYNTHETIC and must not be used in client-facing reports"
            )

    async def get_subdomains(self, domain: str) -> List[str]:
        """Get subdomains for a domain."""
        if not self.api_key:
            return self._mock_subdomains(domain) if self.mock_mode else []

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    f"{self.base_url}/domain/{domain}/subdomains",
                    headers={"APIKEY": self.api_key}
                )
                response.raise_for_status()
                data = response.json()
                return [f"{sub}.{domain}" for sub in data.get("subdomains", [])]
        except Exception as e:
            logger.error(f"SecurityTrails request failed for {domain}: {e}")
            return []

    async def get_domain_history(self, domain: str) -> Dict[str, Any]:
        """Get historical DNS data for a domain."""
        if not self.api_key:
            return (
                self._mock_domain_history(domain)
                if self.mock_mode
                else {"domain": domain, "records": []}
            )

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    f"{self.base_url}/history/{domain}/dns/a",
                    headers={"APIKEY": self.api_key}
                )
                response.raise_for_status()
                return response.json()
        except Exception as e:
            logger.error(f"SecurityTrails history request failed: {e}")
            return {"domain": domain, "records": []}
    
    def _mock_subdomains(self, domain: str) -> List[str]:
        """Generate mock subdomains."""
        domain_hash = int(hashlib.md5(domain.encode()).hexdigest()[:8], 16)
        prefixes = [
            "www", "mail", "api", "cdn", "dev", "staging", "admin",
            "app", "portal", "secure", "vpn", "remote", "ftp", "ssh"
        ]
        count = 3 + domain_hash % 8
        selected = prefixes[:count]
        return [f"{prefix}.{domain}" for prefix in selected]
    
    def _mock_domain_history(self, domain: str) -> Dict[str, Any]:
        """Generate mock domain history."""
        return {
            "domain": domain,
            "records": [
                {
                    "type": "A",
                    "first_seen": "2020-01-01",
                    "last_seen": datetime.utcnow().strftime("%Y-%m-%d"),
                    "values": [{"ip": "192.168.1.1"}],
                }
            ],
        }


class CrtShClient:
    """Client for crt.sh certificate transparency logs."""
    
    def __init__(self):
        self.base_url = "https://crt.sh"
    
    async def get_certificates(self, domain: str) -> List[Dict[str, Any]]:
        """Get certificates from CT logs for a domain."""
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.get(
                    f"{self.base_url}/?q=%.{domain}&output=json"
                )
                response.raise_for_status()
                
                # crt.sh returns an array of certificate entries
                certs = response.json()
                return certs if isinstance(certs, list) else []
        except httpx.HTTPStatusError as e:
            logger.error(f"crt.sh HTTP error for {domain}: {e}")
            return []
        except Exception as e:
            logger.error(f"crt.sh request failed for {domain}: {e}")
            return []
    
    async def get_subdomains_from_ct(self, domain: str) -> Set[str]:
        """Extract unique subdomains from certificate transparency logs."""
        certs = await self.get_certificates(domain)
        subdomains = set()
        
        for cert in certs:
            name_value = cert.get("name_value", "")
            # Handle multiple names separated by newlines
            names = name_value.split("\n")
            for name in names:
                name = name.strip().lower()
                # Filter valid subdomains
                if name and name.endswith(f".{domain}") and not name.startswith("*"):
                    subdomains.add(name)
                elif name == domain:
                    subdomains.add(name)
        
        return subdomains


# =============================================================================
# Attack Surface Manager
# =============================================================================

class AttackSurfaceManager:
    """
    Manages attack surface discovery, monitoring, and vulnerability assessment.
    
    Integrates with multiple data sources to provide comprehensive visibility
    into an organization's external attack surface.
    """
    
    # Common ports to scan
    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
        465, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900,
        6379, 8000, 8080, 8443, 9200, 27017
    ]
    
    # High-risk ports
    HIGH_RISK_PORTS = {
        21: "FTP - unencrypted file transfer",
        23: "Telnet - unencrypted remote access",
        135: "MSRPC - Windows RPC",
        139: "NetBIOS - Windows networking",
        445: "SMB - Windows file sharing",
        1433: "MSSQL - database server",
        1521: "Oracle - database server",
        3306: "MySQL - database server",
        3389: "RDP - remote desktop",
        5432: "PostgreSQL - database server",
        5900: "VNC - remote desktop",
        6379: "Redis - in-memory database",
        27017: "MongoDB - database server",
    }
    
    def __init__(
        self,
        es_client: Optional[Any] = None,
        shodan_api_key: Optional[str] = None,
        security_trails_api_key: Optional[str] = None,
        client_id: Optional[int] = None,
    ):
        """
        Initialize Attack Surface Manager.

        Args:
            es_client: Elasticsearch client for storage
            shodan_api_key: Shodan API key (uses mock if not provided)
            security_trails_api_key: SecurityTrails API key (uses mock if not provided)
            client_id: ASMClient.id — scopes all ES indices to this client.
                       If None, falls back to the shared "assets"/"vulnerabilities" indices
                       (legacy behaviour, kept for backwards compat).
        """
        self.es_client = es_client
        self.shodan = ShodanClient(shodan_api_key)
        self.security_trails = SecurityTrailsClient(security_trails_api_key)
        self.crt_sh = CrtShClient()
        self.client_id = client_id

        # Elasticsearch index names — scoped per client when client_id is set
        _prefix = f"asm_client_{client_id}" if client_id else "asm_global"
        self.assets_index = f"{_prefix}_assets"
        # findings_index: enterprise findings (CVE+EPSS+TI enriched). Also aliased as
        # vulnerabilities_index so old code that uses that attribute still works.
        self.findings_index = f"{_prefix}_findings"
        self.vulnerabilities_index = self.findings_index  # backwards-compat alias
        self.changes_index = f"{_prefix}_changes"
    
    # =========================================================================
    # Core Discovery Methods
    # =========================================================================
    
    async def discover_assets(
        self,
        domain: str,
        include_subdomains: bool = True,
        include_ports: bool = True,
        include_ssl: bool = True,
        include_services: bool = True,
    ) -> DiscoveryResult:
        """
        Perform comprehensive asset discovery for a domain.
        
        Args:
            domain: Root domain to discover assets for
            include_subdomains: Whether to discover subdomains
            include_ports: Whether to scan for open ports
            include_ssl: Whether to check SSL certificates
            include_services: Whether to discover exposed services
            
        Returns:
            DiscoveryResult with all discovered assets
        """
        logger.info(f"Starting asset discovery for {domain} (client_id={self.client_id})")

        result = DiscoveryResult(
            domain=domain,
            started_at=datetime.utcnow(),
        )

        def _make_asset(**kwargs) -> Asset:
            """Helper: create an Asset pre-stamped with client_id and root_domain."""
            return Asset(client_id=self.client_id, root_domain=domain, **kwargs)

        try:
            # Create root domain asset
            root_asset = _make_asset(
                type=AssetType.DOMAIN,
                value=domain,
                status=AssetStatus.ACTIVE,
                discovery_source="seed",
            )
            result.assets.append(root_asset)
            
            # Gather DNS records
            dns_records = await self.get_dns_records(domain)
            result.dns_records = dns_records
            
            # Extract IPs from DNS records
            for record in dns_records:
                if record.record_type in ("A", "AAAA"):
                    if record.value not in result.ips:
                        result.ips.append(record.value)
                        ip_asset = _make_asset(
                            type=AssetType.IP,
                            value=record.value,
                            parent_id=root_asset.id,
                            discovery_source="dns",
                        )
                        result.assets.append(ip_asset)

            # Discover subdomains
            if include_subdomains:
                # Map of subdomain -> set of sources that reported it
                subdomain_sources = await self._discover_subdomains(domain)
                resolved_subdomains: List[str] = []

                for subdomain in sorted(subdomain_sources):
                    # Fail-closed: resolve BEFORE creating the asset. An
                    # enumerated name that does not resolve is not a confirmed
                    # asset and must not appear in client-facing reports.
                    sub_ips = await self._resolve_domain(subdomain)
                    if not sub_ips:
                        logger.debug(
                            f"Skipping unresolved subdomain {subdomain} "
                            f"(sources={sorted(subdomain_sources[subdomain])})"
                        )
                        continue

                    resolved_subdomains.append(subdomain)
                    sub_asset = _make_asset(
                        type=AssetType.SUBDOMAIN,
                        value=subdomain,
                        parent_id=root_asset.id,
                        discovery_source=",".join(sorted(subdomain_sources[subdomain])),
                    )
                    result.assets.append(sub_asset)

                    for ip in sub_ips:
                        if ip not in result.ips:
                            result.ips.append(ip)
                            ip_asset = _make_asset(
                                type=AssetType.IP,
                                value=ip,
                                parent_id=sub_asset.id,
                                discovery_source="dns",
                            )
                            result.assets.append(ip_asset)

                result.subdomains = resolved_subdomains
            
            # Port scanning
            if include_ports and result.ips:
                for ip in result.ips[:10]:  # Limit to first 10 IPs
                    ports = await self.scan_ports(ip)
                    for port_info in ports:
                        port_asset = _make_asset(
                            type=AssetType.PORT,
                            value=f"{ip}:{port_info['port']}",
                            parent_id=next(
                                (a.id for a in result.assets if a.value == ip),
                                None
                            ),
                            discovery_source="port_scan",
                            metadata={
                                "port": port_info["port"],
                                "protocol": port_info.get("protocol", "tcp"),
                                "service": port_info.get("service"),
                            },
                        )
                        
                        # Check if high-risk port
                        if port_info["port"] in self.HIGH_RISK_PORTS:
                            port_asset.tags.append("high_risk")
                            port_asset.risk_score = 60.0
                        
                        result.assets.append(port_asset)
            
            # SSL/TLS analysis
            if include_ssl:
                ssl_info = await self.check_ssl_certificates(domain)
                result.ssl_info = ssl_info
                
                if ssl_info:
                    cert_asset = _make_asset(
                        type=AssetType.CERTIFICATE,
                        value=ssl_info.fingerprint_sha256,
                        parent_id=root_asset.id,
                        discovery_source="tls",
                        metadata={
                            "subject": ssl_info.subject,
                            "issuer": ssl_info.issuer,
                            "valid_until": ssl_info.valid_until.isoformat(),
                            "san_names": ssl_info.san_names,
                        },
                    )
                    result.assets.append(cert_asset)
                    
                    # Create vulnerabilities for SSL issues
                    for issue in ssl_info.issues:
                        vuln = Vulnerability(
                            title=f"SSL/TLS Issue: {issue}",
                            severity=SeverityLevel.MEDIUM,
                            description=issue,
                            affected_asset_id=cert_asset.id,
                            affected_asset_value=domain,
                            affected_asset_type=AssetType.CERTIFICATE,
                        )
                        result.vulnerabilities.append(vuln)
            
            # Find exposed services
            if include_services:
                services = await self.find_exposed_services(domain)
                result.services = services
                
                for service in services:
                    service_asset = _make_asset(
                        type=AssetType.SERVICE,
                        value=f"{service.service_name}:{service.port}",
                        discovery_source="shodan",
                        metadata={
                            "port": service.port,
                            "protocol": service.protocol,
                            "version": service.version,
                            "banner": service.banner,
                        },
                    )
                    result.assets.append(service_asset)
                    
                    # Check for vulnerabilities in service — only create one finding
                    # per port using only that port's own risk description
                    if service.port in self.HIGH_RISK_PORTS:
                        port_desc = self.HIGH_RISK_PORTS[service.port]
                        port_name = self._guess_service(service.port).upper()
                        sev = (
                            SeverityLevel.CRITICAL if service.port in (23, 3389, 5900)
                            else SeverityLevel.HIGH if service.port in (21, 1433, 1521, 3306, 5432, 6379, 27017)
                            else SeverityLevel.MEDIUM
                        )
                        vuln = Vulnerability(
                            title=f"High-Risk Port Exposed: {port_name} (port {service.port})",
                            severity=sev,
                            description=(
                                f"Port {service.port} ({port_name}) is exposed to the internet. "
                                f"{port_desc}. "
                                f"This service should not be publicly accessible."
                            ),
                            affected_asset_id=service_asset.id,
                            affected_asset_value=f"{domain}:{service.port}",
                            affected_asset_type=AssetType.SERVICE,
                            remediation=(
                                f"Restrict access to port {service.port} using firewall rules. "
                                f"Only allow connections from trusted IP ranges. "
                                f"If this service is not required, disable it entirely."
                            ),
                        )
                        result.vulnerabilities.append(vuln)
                    elif service.vulnerabilities:
                        # CVE-based vulnerabilities from Shodan
                        for vuln_desc in service.vulnerabilities:
                            if not vuln_desc.startswith("High-risk service:"):
                                vuln = Vulnerability(
                                    title=f"Vulnerability on {self._guess_service(service.port).upper()} (port {service.port}): {vuln_desc[:60]}",
                                    severity=SeverityLevel.HIGH,
                                    description=vuln_desc,
                                    affected_asset_id=service_asset.id,
                                    affected_asset_value=f"{domain}:{service.port}",
                                    affected_asset_type=AssetType.SERVICE,
                                )
                                result.vulnerabilities.append(vuln)
            
            # Calculate overall risk score
            result.total_risk_score = self._calculate_risk_score(result)

            # Populate computed summary fields
            result.total_ips = len(result.ips)
            # Count PORT-type assets (each represents one open port)
            result.total_open_ports = sum(
                1 for a in result.assets if a.type == AssetType.PORT
            )
            if result.ssl_info:
                ssl_issues = 0
                if getattr(result.ssl_info, "is_expired", False):
                    ssl_issues += 1
                if getattr(result.ssl_info, "days_until_expiry", 999) < 30:
                    ssl_issues += 1
                result.ssl_issues = ssl_issues

            # Update risk scores for all assets
            for asset in result.assets:
                asset.risk_score = self._calculate_asset_risk(asset, result)

            # Store results in Elasticsearch
            await self._store_discovery_results(result)
            
            result.completed_at = datetime.utcnow()
            logger.info(
                f"Discovery completed for {domain}: "
                f"{len(result.assets)} assets, "
                f"{len(result.vulnerabilities)} vulnerabilities"
            )
            
        except Exception as e:
            logger.error(f"Discovery failed for {domain}: {e}")
            result.error = str(e)
            result.completed_at = datetime.utcnow()
        
        return result
    
    async def _discover_subdomains(self, domain: str) -> Dict[str, Set[str]]:
        """Discover subdomains from multiple sources, tracking which source(s)
        reported each name.

        Returns a mapping of subdomain -> set of source names. Sources that are
        disabled (no API key and ALLOW_MOCK_DATA=false) contribute nothing, so
        with no keys configured only crt.sh (real CT-log data) is used. The
        caller is responsible for resolution-verifying each name before treating
        it as a confirmed asset.
        """
        source_coros = [
            ("crtsh", self.crt_sh.get_subdomains_from_ct(domain)),
            ("securitytrails", self.security_trails.get_subdomains(domain)),
            ("shodan", self._get_shodan_subdomains(domain)),
        ]

        results = await asyncio.gather(
            *(coro for _, coro in source_coros), return_exceptions=True
        )

        discovered: Dict[str, Set[str]] = {}
        for (source_name, _), result in zip(source_coros, results):
            if isinstance(result, Exception):
                logger.warning(f"Subdomain discovery error from {source_name}: {result}")
                continue
            if isinstance(result, (set, list)):
                for sub in result:
                    if not sub or sub == domain:
                        continue
                    discovered.setdefault(sub, set()).add(source_name)

        return discovered
    
    async def _get_shodan_subdomains(self, domain: str) -> List[str]:
        """Get subdomains from Shodan."""
        result = await self.shodan.search_domain(domain)
        return result.get("subdomains", [])
    
    async def _resolve_domain(self, domain: str) -> List[str]:
        """Resolve domain to IP addresses (non-blocking)."""
        ips = []

        if DNS_AVAILABLE:
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = 5.0
            resolver.lifetime = 10.0

            for rtype in ("A", "AAAA"):
                try:
                    answers = await resolver.resolve(domain, rtype)
                    for rdata in answers:
                        ips.append(str(rdata))
                except dns.exception.DNSException:
                    pass
                except Exception as e:
                    logger.warning(f"DNS resolution failed for {domain} {rtype}: {e}")
        else:
            # Fallback to socket — run blocking getaddrinfo off the event loop
            try:
                result = await asyncio.to_thread(
                    socket.getaddrinfo, domain, None, socket.AF_UNSPEC
                )
                for item in result:
                    ip = item[4][0]
                    if ip not in ips:
                        ips.append(ip)
            except socket.error as e:
                logger.warning(f"Socket resolution failed for {domain}: {e}")

        return ips
    
    # =========================================================================
    # Port Scanning
    # =========================================================================
    
    async def scan_ports(
        self,
        ip: str,
        ports: Optional[List[int]] = None,
        timeout: float = 2.0,
    ) -> List[Dict[str, Any]]:
        """
        Scan for open ports on an IP address.
        
        Args:
            ip: IP address to scan
            ports: List of ports to scan (defaults to common ports)
            timeout: Connection timeout in seconds
            
        Returns:
            List of open ports with service information
        """
        if ports is None:
            ports = self.COMMON_PORTS

        # SSRF guard: resolve + reject non-public addresses, then pin the scan
        # to the validated IP so a hostname can't be rebound to an internal host.
        try:
            validated = await resolve_public_ips(ip)
        except SSRFError as e:
            logger.warning(f"scan_ports blocked target {ip!r}: {e}")
            return []
        ip = validated[0]

        # First try Shodan for service info
        shodan_info = await self.shodan.get_host_info(ip)
        shodan_ports = {
            item["port"]: item
            for item in shodan_info.get("data", [])
        }
        
        open_ports = []
        
        # Scan ports concurrently
        async def check_port(port: int) -> Optional[Dict[str, Any]]:
            try:
                # Use asyncio for non-blocking socket connection
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=timeout
                )
                writer.close()
                await writer.wait_closed()
                
                # Get service info from Shodan or guess
                shodan_data = shodan_ports.get(port, {})
                service = shodan_data.get("product", self._guess_service(port))
                
                return {
                    "port": port,
                    "protocol": "tcp",
                    "state": "open",
                    "service": service,
                    "version": shodan_data.get("version"),
                    "banner": shodan_data.get("data"),
                }
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None
        
        # Run port checks concurrently with limited concurrency
        semaphore = asyncio.Semaphore(50)  # Limit concurrent connections
        
        async def limited_check(port: int) -> Optional[Dict[str, Any]]:
            async with semaphore:
                return await check_port(port)
        
        tasks = [limited_check(port) for port in ports]
        results = await asyncio.gather(*tasks)
        
        for result in results:
            if result is not None:
                open_ports.append(result)
        
        return open_ports
    
    def _guess_service(self, port: int) -> str:
        """Guess service name from port number."""
        services = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            111: "rpcbind",
            135: "msrpc",
            139: "netbios-ssn",
            143: "imap",
            443: "https",
            445: "microsoft-ds",
            465: "smtps",
            587: "submission",
            993: "imaps",
            995: "pop3s",
            1433: "mssql",
            1521: "oracle",
            3306: "mysql",
            3389: "ms-wbt-server",
            5432: "postgresql",
            5900: "vnc",
            6379: "redis",
            8000: "http-alt",
            8080: "http-proxy",
            8443: "https-alt",
            9200: "elasticsearch",
            27017: "mongodb",
        }
        return services.get(port, f"unknown-{port}")
    
    # =========================================================================
    # SSL/TLS Analysis
    # =========================================================================
    
    async def check_ssl_certificates(
        self,
        domain: str,
        port: int = 443,
    ) -> Optional[SSLCertInfo]:
        """
        Analyze SSL/TLS certificate for a domain.
        
        Args:
            domain: Domain to check
            port: Port to connect to (default 443)
            
        Returns:
            SSLCertInfo with certificate details and issues
        """
        try:
            # SSRF guard: resolve + reject non-public addresses before connecting.
            try:
                validated = await resolve_public_ips(domain)
            except SSRFError as e:
                logger.warning(f"check_ssl_certificates blocked target {domain!r}: {e}")
                return None

            # Create SSL context
            context = ssl.create_default_context()

            # Connect and get certificate (pinned to the validated IP, SNI = domain)
            loop = asyncio.get_event_loop()
            cert_der = await loop.run_in_executor(
                None,
                self._get_certificate,
                domain,
                port,
                validated[0],
            )
            
            if cert_der is None:
                return None
            
            # Parse certificate
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            
            # Extract information
            now = datetime.utcnow()
            valid_from = cert.not_valid_before_utc.replace(tzinfo=None)
            valid_until = cert.not_valid_after_utc.replace(tzinfo=None)
            is_expired = valid_until < now
            days_until_expiry = (valid_until - now).days
            
            # Get subject alternative names
            san_names = []
            try:
                san_ext = cert.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                )
                san_names = [
                    name.value for name in san_ext.value
                    if isinstance(name, x509.DNSName)
                ]
            except x509.ExtensionNotFound:
                pass
            
            # Calculate fingerprint
            fingerprint = cert.fingerprint(cert.signature_hash_algorithm)
            fingerprint_hex = fingerprint.hex()
            
            # Detect issues
            issues = []
            
            if is_expired:
                issues.append("Certificate has expired")
            elif days_until_expiry < 30:
                issues.append(f"Certificate expires in {days_until_expiry} days")
            
            # Check key size (for RSA)
            try:
                public_key = cert.public_key()
                key_size = public_key.key_size
                if key_size < 2048:
                    issues.append(f"Weak key size: {key_size} bits (should be >= 2048)")
            except AttributeError:
                key_size = None
            
            # Check for wildcard
            if any(name.startswith("*") for name in san_names):
                issues.append("Uses wildcard certificate")
            
            # Check signature algorithm
            sig_algo = cert.signature_algorithm_oid._name
            weak_algos = ["md5", "sha1"]
            if any(algo in sig_algo.lower() for algo in weak_algos):
                issues.append(f"Weak signature algorithm: {sig_algo}")
            
            return SSLCertInfo(
                subject=cert.subject.rfc4514_string(),
                issuer=cert.issuer.rfc4514_string(),
                valid_from=valid_from,
                valid_until=valid_until,
                is_valid=not is_expired,
                is_expired=is_expired,
                days_until_expiry=days_until_expiry,
                serial_number=str(cert.serial_number),
                fingerprint_sha256=fingerprint_hex,
                san_names=san_names,
                key_size=key_size,
                signature_algorithm=sig_algo,
                issues=issues,
            )
            
        except Exception as e:
            logger.error(f"SSL check failed for {domain}: {e}")
            return None
    
    def _get_certificate(
        self, domain: str, port: int, connect_ip: Optional[str] = None
    ) -> Optional[bytes]:
        """Get SSL certificate in DER format (blocking, run in executor)."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # Pin the TCP connection to a validated public IP (SNI stays = domain).
            # If no pinned IP was supplied (e.g. internal callers), validate here.
            if connect_ip is None:
                connect_ip = resolve_public_ips_sync(domain)[0]

            with socket.create_connection((connect_ip, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    return cert_der
        except Exception as e:
            logger.warning(f"Failed to get certificate for {domain}:{port}: {e}")
            return None
    
    # =========================================================================
    # Service Discovery
    # =========================================================================
    
    async def find_exposed_services(self, domain: str) -> List[ServiceInfo]:
        """
        Find exposed services for a domain.
        
        Args:
            domain: Domain to analyze
            
        Returns:
            List of ServiceInfo objects describing exposed services
        """
        services = []
        
        # Resolve domain to IP
        ips = await self._resolve_domain(domain)
        
        for ip in ips[:5]:  # Limit to first 5 IPs
            # Get Shodan data
            shodan_info = await self.shodan.get_host_info(ip)
            
            for service_data in shodan_info.get("data", []):
                port = service_data.get("port", 0)
                
                service = ServiceInfo(
                    port=port,
                    protocol=service_data.get("transport", "tcp"),
                    service_name=service_data.get("product", self._guess_service(port)),
                    version=service_data.get("version"),
                    banner=service_data.get("data"),
                    is_encrypted=port in (443, 465, 587, 993, 995, 8443),
                )
                
                # Check for known vulnerabilities — copy list so each service is independent
                service.vulnerabilities = list(shodan_info.get("vulns", []))

                # Add high-risk warning only for THIS port's own risk description
                if port in self.HIGH_RISK_PORTS:
                    service.vulnerabilities.append(
                        f"High-risk service: {self.HIGH_RISK_PORTS[port]}"
                    )
                
                services.append(service)
        
        return services
    
    # =========================================================================
    # DNS Records
    # =========================================================================
    
    async def get_dns_records(self, domain: str) -> List[DNSRecord]:
        """
        Get all DNS records for a domain.
        
        Args:
            domain: Domain to query
            
        Returns:
            List of DNSRecord objects
        """
        records = []
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]
        
        if not DNS_AVAILABLE:
            # Fallback to basic resolution
            try:
                result = await asyncio.to_thread(
                    socket.getaddrinfo, domain, None, socket.AF_INET
                )
                for item in result:
                    records.append(DNSRecord(
                        record_type="A",
                        value=item[4][0],
                        ttl=3600,
                    ))
            except socket.error:
                pass
            return records

        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 5.0
        resolver.lifetime = 10.0

        for rtype in record_types:
            try:
                answers = await resolver.resolve(domain, rtype)
                for rdata in answers:
                    value = str(rdata)
                    
                    # Clean up MX records
                    if rtype == "MX":
                        value = f"{rdata.preference} {rdata.exchange}"
                    
                    records.append(DNSRecord(
                        record_type=rtype,
                        value=value,
                        ttl=answers.ttl,
                    ))
            except dns.exception.DNSException:
                continue
            except Exception as e:
                logger.warning(f"DNS query failed for {domain} {rtype}: {e}")
        
        return records
    
    # =========================================================================
    # Vulnerability Assessment
    # =========================================================================
    
    async def check_vulnerabilities(
        self,
        asset: Dict[str, Any],
    ) -> List[Vulnerability]:
        """
        Check for known vulnerabilities in an asset.
        
        Args:
            asset: Asset dictionary with type, value, and metadata
            
        Returns:
            List of Vulnerability objects
        """
        vulnerabilities = []
        asset_type = asset.get("type", "")
        asset_value = asset.get("value", "")
        asset_id = asset.get("id", str(uuid4()))
        
        try:
            asset_type_enum = AssetType(asset_type)
        except ValueError:
            asset_type_enum = AssetType.DOMAIN
        
        # Check based on asset type
        if asset_type == "ip" or asset_type == AssetType.IP:
            # Get Shodan vulnerabilities
            shodan_info = await self.shodan.get_host_info(asset_value)
            vulns = shodan_info.get("vulns", [])
            
            for cve_id in vulns:
                vuln = Vulnerability(
                    cve_id=cve_id,
                    title=f"Known vulnerability: {cve_id}",
                    severity=SeverityLevel.HIGH,
                    description=f"CVE {cve_id} detected by Shodan scan",
                    affected_asset_id=asset_id,
                    affected_asset_value=asset_value,
                    affected_asset_type=asset_type_enum,
                    references=[f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
                )
                vulnerabilities.append(vuln)
        
        elif asset_type == "port" or asset_type == AssetType.PORT:
            # Check for high-risk ports
            metadata = asset.get("metadata", {})
            port = metadata.get("port", 0)
            
            if port in self.HIGH_RISK_PORTS:
                vuln = Vulnerability(
                    title=f"High-Risk Port Exposed: {port}",
                    severity=SeverityLevel.MEDIUM,
                    description=self.HIGH_RISK_PORTS[port],
                    affected_asset_id=asset_id,
                    affected_asset_value=asset_value,
                    affected_asset_type=asset_type_enum,
                    remediation="Consider restricting access to this port using firewall rules",
                )
                vulnerabilities.append(vuln)
        
        elif asset_type == "certificate" or asset_type == AssetType.CERTIFICATE:
            # Check certificate issues
            metadata = asset.get("metadata", {})
            valid_until = metadata.get("valid_until")
            
            if valid_until:
                try:
                    expiry = datetime.fromisoformat(valid_until)
                    days_left = (expiry - datetime.utcnow()).days
                    
                    if days_left < 0:
                        vuln = Vulnerability(
                            title="Expired SSL Certificate",
                            severity=SeverityLevel.HIGH,
                            description="SSL certificate has expired",
                            affected_asset_id=asset_id,
                            affected_asset_value=asset_value,
                            affected_asset_type=asset_type_enum,
                            remediation="Renew SSL certificate immediately",
                        )
                        vulnerabilities.append(vuln)
                    elif days_left < 30:
                        vuln = Vulnerability(
                            title="SSL Certificate Expiring Soon",
                            severity=SeverityLevel.MEDIUM,
                            description=f"SSL certificate expires in {days_left} days",
                            affected_asset_id=asset_id,
                            affected_asset_value=asset_value,
                            affected_asset_type=asset_type_enum,
                            remediation="Plan certificate renewal before expiration",
                        )
                        vulnerabilities.append(vuln)
                except (ValueError, TypeError):
                    pass
        
        return vulnerabilities
    
    # =========================================================================
    # Change Monitoring
    # =========================================================================
    
    async def monitor_changes(self, asset_id: str) -> List[AssetChange]:
        """
        Detect changes to an asset by comparing current state with stored state.
        
        Args:
            asset_id: ID of asset to monitor
            
        Returns:
            List of AssetChange objects describing detected changes
        """
        changes = []
        
        if not self.es_client:
            logger.warning("Elasticsearch not configured - cannot monitor changes")
            return changes
        
        try:
            # Get current asset from Elasticsearch
            current_asset = await self._get_asset_from_es(asset_id)
            
            if not current_asset:
                logger.warning(f"Asset not found: {asset_id}")
                return changes
            
            asset_type = current_asset.get("type")
            asset_value = current_asset.get("value", "")
            
            # Perform fresh scan based on asset type
            if asset_type == "domain":
                # Check for IP changes
                current_ips = await self._resolve_domain(asset_value)
                stored_ips = current_asset.get("metadata", {}).get("ips", [])
                
                new_ips = set(current_ips) - set(stored_ips)
                removed_ips = set(stored_ips) - set(current_ips)
                
                for ip in new_ips:
                    change = AssetChange(
                        asset_id=asset_id,
                        asset_value=asset_value,
                        change_type=ChangeType.IP_CHANGED,
                        new_value=ip,
                        details={"action": "added"},
                    )
                    changes.append(change)
                
                for ip in removed_ips:
                    change = AssetChange(
                        asset_id=asset_id,
                        asset_value=asset_value,
                        change_type=ChangeType.IP_CHANGED,
                        old_value=ip,
                        details={"action": "removed"},
                    )
                    changes.append(change)
            
            elif asset_type == "ip":
                # Check for port changes
                current_ports = await self.scan_ports(asset_value)
                current_port_nums = {p["port"] for p in current_ports}
                stored_ports = set(
                    current_asset.get("metadata", {}).get("open_ports", [])
                )
                
                new_ports = current_port_nums - stored_ports
                closed_ports = stored_ports - current_port_nums
                
                for port in new_ports:
                    change = AssetChange(
                        asset_id=asset_id,
                        asset_value=asset_value,
                        change_type=ChangeType.PORT_OPENED,
                        new_value=str(port),
                        details={"port": port},
                    )
                    changes.append(change)
                
                for port in closed_ports:
                    change = AssetChange(
                        asset_id=asset_id,
                        asset_value=asset_value,
                        change_type=ChangeType.PORT_CLOSED,
                        old_value=str(port),
                        details={"port": port},
                    )
                    changes.append(change)
            
            elif asset_type == "certificate":
                # Check for certificate changes
                domain = current_asset.get("metadata", {}).get("domain", "")
                if domain:
                    new_ssl = await self.check_ssl_certificates(domain)
                    if new_ssl:
                        stored_fingerprint = current_asset.get("value", "")
                        if new_ssl.fingerprint_sha256 != stored_fingerprint:
                            change = AssetChange(
                                asset_id=asset_id,
                                asset_value=domain,
                                change_type=ChangeType.CERTIFICATE_CHANGED,
                                old_value=stored_fingerprint,
                                new_value=new_ssl.fingerprint_sha256,
                                details={
                                    "new_valid_until": new_ssl.valid_until.isoformat(),
                                    "new_issuer": new_ssl.issuer,
                                },
                            )
                            changes.append(change)
            
            # Store detected changes
            for change in changes:
                await self._store_change(change)
            
        except Exception as e:
            logger.error(f"Change monitoring failed for {asset_id}: {e}")
        
        return changes
    
    # =========================================================================
    # Risk Scoring
    # =========================================================================
    
    def _calculate_risk_score(self, result: DiscoveryResult) -> float:
        """Calculate overall risk score for a discovery result."""
        score = 0.0
        
        # Base score for number of exposed assets
        asset_count = len(result.assets)
        score += min(asset_count * 2, 20)  # Max 20 points for assets
        
        # Score for vulnerabilities
        vuln_weights = {
            SeverityLevel.CRITICAL: 25,
            SeverityLevel.HIGH: 15,
            SeverityLevel.MEDIUM: 8,
            SeverityLevel.LOW: 3,
            SeverityLevel.INFO: 1,
        }
        
        for vuln in result.vulnerabilities:
            score += vuln_weights.get(vuln.severity, 5)
        
        # Score for SSL issues
        if result.ssl_info:
            score += len(result.ssl_info.issues) * 10
            if result.ssl_info.is_expired:
                score += 20
        
        # Score for exposed services
        for service in result.services:
            if service.port in self.HIGH_RISK_PORTS:
                score += 15
            if not service.is_encrypted:
                score += 5
        
        # Normalize to 0-100
        return min(score, 100.0)
    
    def _calculate_asset_risk(
        self,
        asset: Asset,
        result: DiscoveryResult,
    ) -> float:
        """Calculate risk score for a specific asset."""
        score = 0.0
        
        # Type-based base risk
        type_risks = {
            AssetType.DOMAIN: 10,
            AssetType.SUBDOMAIN: 15,
            AssetType.IP: 20,
            AssetType.PORT: 30,
            AssetType.SERVICE: 25,
            AssetType.CERTIFICATE: 15,
        }
        score += type_risks.get(asset.type, 10)
        
        # Check for high-risk tags
        if "high_risk" in asset.tags:
            score += 20
        
        # Check for related vulnerabilities
        related_vulns = [
            v for v in result.vulnerabilities
            if v.affected_asset_id == asset.id
        ]
        for vuln in related_vulns:
            if vuln.severity == SeverityLevel.CRITICAL:
                score += 25
            elif vuln.severity == SeverityLevel.HIGH:
                score += 15
            elif vuln.severity == SeverityLevel.MEDIUM:
                score += 8
        
        return min(score, 100.0)
    
    # =========================================================================
    # Elasticsearch Storage
    # =========================================================================
    
    async def _store_discovery_results(self, result: DiscoveryResult) -> None:
        """Store discovery results in Elasticsearch."""
        if not self.es_client:
            logger.warning("Elasticsearch not configured - skipping storage")
            return
        
        try:
            # Store assets
            for asset in result.assets:
                await self.es_client.index(
                    index=self.assets_index,
                    id=asset.id,
                    document=asset.to_es_doc(),
                )
            
            # Store vulnerabilities
            for vuln in result.vulnerabilities:
                await self.es_client.index(
                    index=self.vulnerabilities_index,
                    id=vuln.id,
                    document=vuln.to_es_doc(),
                )
            
            logger.info(f"Stored {len(result.assets)} assets and {len(result.vulnerabilities)} vulnerabilities")
            
        except Exception as e:
            logger.error(f"Failed to store discovery results: {e}")
    
    async def _store_change(self, change: AssetChange) -> None:
        """Store an asset change in Elasticsearch."""
        if not self.es_client:
            return
        
        try:
            await self.es_client.index(
                index=self.changes_index,
                id=change.id,
                document=change.to_es_doc(),
            )
        except Exception as e:
            logger.error(f"Failed to store change: {e}")
    
    async def _get_asset_from_es(self, asset_id: str) -> Optional[Dict[str, Any]]:
        """Get asset from Elasticsearch by ID."""
        if not self.es_client:
            return None
        
        try:
            response = await self.es_client.get(
                index=self.assets_index,
                id=asset_id,
            )
            return response["_source"]
        except Exception as e:
            logger.warning(f"Failed to get asset {asset_id}: {e}")
            return None
    
    async def get_assets(
        self,
        asset_type: Optional[AssetType] = None,
        parent_id: Optional[str] = None,
        status: Optional[AssetStatus] = None,
        min_risk_score: float = 0.0,
        limit: int = 100,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """
        Get assets from Elasticsearch with filtering.
        
        Returns:
            Tuple of (assets list, total count)
        """
        if not self.es_client:
            return [], 0
        
        query_filters = []
        
        if asset_type:
            query_filters.append({"term": {"type": asset_type.value}})
        
        if parent_id:
            query_filters.append({"term": {"parent_id": parent_id}})
        
        if status:
            query_filters.append({"term": {"status": status.value}})
        
        if min_risk_score > 0:
            query_filters.append({"range": {"risk_score": {"gte": min_risk_score}}})
        
        query: Dict[str, Any]
        if query_filters:
            query = {"bool": {"filter": query_filters}}
        else:
            query = {"match_all": {}}

        try:
            response = await self.es_client.search(
                index=self.assets_index,
                query=query,
                from_=offset,
                size=limit,
                sort=[{"risk_score": "desc"}, {"last_seen": "desc"}],
                track_total_hits=True,
            )

            hits = [hit["_source"] for hit in response["hits"]["hits"]]
            total_raw = response["hits"]["total"]
            total = total_raw["value"] if isinstance(total_raw, dict) else int(total_raw)

            return hits, total

        except Exception as e:
            logger.error(f"Failed to search assets: {e}")
            return [], 0
    
    async def get_vulnerabilities(
        self,
        severity: Optional[SeverityLevel] = None,
        asset_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Get vulnerabilities from Elasticsearch."""
        if not self.es_client:
            return [], 0
        
        query_filters = []
        
        if severity:
            query_filters.append({"term": {"severity": severity.value}})
        
        if asset_id:
            query_filters.append({"term": {"affected_asset_id": asset_id}})
        
        vuln_query: Dict[str, Any]
        if query_filters:
            vuln_query = {"bool": {"filter": query_filters}}
        else:
            vuln_query = {"match_all": {}}

        try:
            response = await self.es_client.search(
                index=self.vulnerabilities_index,
                query=vuln_query,
                from_=offset,
                size=limit,
                sort=[{"detected_at": "desc"}],
                track_total_hits=True,
            )

            hits = [hit["_source"] for hit in response["hits"]["hits"]]
            total_raw = response["hits"]["total"]
            total = total_raw["value"] if isinstance(total_raw, dict) else int(total_raw)

            return hits, total

        except Exception as e:
            logger.error(f"Failed to search vulnerabilities: {e}")
            return [], 0
    
    async def get_changes(
        self,
        asset_id: Optional[str] = None,
        change_type: Optional[ChangeType] = None,
        since: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get recent asset changes from Elasticsearch."""
        if not self.es_client:
            return []
        
        query_filters = []
        
        if asset_id:
            query_filters.append({"term": {"asset_id": asset_id}})
        
        if change_type:
            query_filters.append({"term": {"change_type": change_type.value}})
        
        if since:
            query_filters.append({
                "range": {"detected_at": {"gte": since.isoformat()}}
            })
        
        changes_query: Dict[str, Any]
        if query_filters:
            changes_query = {"bool": {"filter": query_filters}}
        else:
            changes_query = {"match_all": {}}

        try:
            response = await self.es_client.search(
                index=self.changes_index,
                query=changes_query,
                size=limit,
                sort=[{"detected_at": "desc"}],
            )

            return [hit["_source"] for hit in response["hits"]["hits"]]

        except Exception as e:
            logger.error(f"Failed to search changes: {e}")
            return []
    
    async def get_summary(self, domain: Optional[str] = None) -> Dict[str, Any]:
        """
        Get attack surface summary statistics.

        Returns a dict with keys aligned to what asm.py endpoints expose:
            total_assets, by_type, average_risk_score, high_risk_assets,
            total_vulnerabilities, vulnerabilities_by_severity,
            critical_vulnerabilities, high_vulnerabilities,
            total_open_ports, ssl_issues,
            total_changes_24h, changes_last_7_days
        """
        summary: Dict[str, Any] = {
            "total_assets": 0,
            "by_type": {},
            "average_risk_score": 0.0,
            "high_risk_assets": 0,
            "total_vulnerabilities": 0,
            "vulnerabilities_by_severity": {},
            "critical_vulnerabilities": 0,
            "high_vulnerabilities": 0,
            "total_open_ports": 0,
            "ssl_issues": 0,
            "total_changes_24h": 0,
            "changes_last_7_days": 0,
        }

        if not self.es_client:
            return summary

        try:
            # ── Asset aggregations ────────────────────────────────────────────
            try:
                assets_agg = await self.es_client.search(
                    index=self.assets_index,
                    size=0,
                    track_total_hits=True,
                    aggs={
                        "by_type": {"terms": {"field": "type", "size": 20}},
                        "high_risk": {
                            "filter": {"range": {"risk_score": {"gte": 70}}}
                        },
                        "avg_risk": {"avg": {"field": "risk_score"}},
                        "open_ports": {
                            "filter": {"term": {"type": "port"}}
                        },
                    },
                )
                total_raw = assets_agg["hits"]["total"]
                summary["total_assets"] = total_raw["value"] if isinstance(total_raw, dict) else int(total_raw)
                summary["by_type"] = {
                    b["key"]: b["doc_count"]
                    for b in assets_agg["aggregations"]["by_type"]["buckets"]
                }
                summary["high_risk_assets"] = assets_agg["aggregations"]["high_risk"]["doc_count"]
                summary["average_risk_score"] = round(
                    assets_agg["aggregations"]["avg_risk"]["value"] or 0.0, 2
                )
                summary["total_open_ports"] = assets_agg["aggregations"]["open_ports"]["doc_count"]
            except Exception:
                pass  # assets index may not exist yet for new clients

            # ── Vulnerability aggregations ────────────────────────────────────
            try:
                vulns_agg = await self.es_client.search(
                    index=self.vulnerabilities_index,
                    size=0,
                    track_total_hits=True,
                    aggs={
                        "by_severity": {"terms": {"field": "severity", "size": 10}},
                        "ssl_issues": {
                            "filter": {"term": {"category": "ssl"}}
                        },
                    },
                )
                total_v_raw = vulns_agg["hits"]["total"]
                summary["total_vulnerabilities"] = total_v_raw["value"] if isinstance(total_v_raw, dict) else int(total_v_raw)
                by_sev = {
                    b["key"]: b["doc_count"]
                    for b in vulns_agg["aggregations"]["by_severity"]["buckets"]
                }
                summary["vulnerabilities_by_severity"] = by_sev
                summary["critical_vulnerabilities"] = by_sev.get("critical", 0)
                summary["high_vulnerabilities"] = by_sev.get("high", 0)
                summary["ssl_issues"] = vulns_agg["aggregations"]["ssl_issues"]["doc_count"]
            except Exception:
                pass  # vulnerabilities index may not exist yet for new clients

            # ── Change counts — guarded separately (changes index created lazily) ──
            since_24h = (datetime.utcnow() - timedelta(hours=24)).isoformat()
            since_7d = (datetime.utcnow() - timedelta(days=7)).isoformat()
            try:
                c24h = await self.es_client.count(
                    index=self.changes_index,
                    query={"range": {"detected_at": {"gte": since_24h}}},
                )
                summary["total_changes_24h"] = c24h.get("count", 0)
            except Exception:
                summary["total_changes_24h"] = 0
            try:
                c7d = await self.es_client.count(
                    index=self.changes_index,
                    query={"range": {"detected_at": {"gte": since_7d}}},
                )
                summary["changes_last_7_days"] = c7d.get("count", 0)
            except Exception:
                summary["changes_last_7_days"] = 0

        except Exception as e:
            logger.error(f"Failed to get summary: {e}")

        return summary
