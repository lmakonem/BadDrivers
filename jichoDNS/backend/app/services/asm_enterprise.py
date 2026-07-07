"""
ASM Enterprise Service — JichoDNS

Provides the high-value SOC capabilities that sit on top of the base
AttackSurfaceManager discovery engine:

  1. Findings index  — normalised, deduplicated, enriched finding records
                       (replaces raw `vulnerabilities`; one doc per issue per asset)
  2. TI correlation  — join discovered assets against live IOC index;
                       tag assets seen in C2/phishing/malware feeds
  3. CVE enrichment  — EPSS probability + CISA KEV flag per CVE finding
  4. HTTP checks     — tech fingerprinting, security-header audit, redirect chain
  5. Risk engine     — composite 0–100 score with factors breakdown (A–F grade)
  6. Webhook alerts  — HMAC-signed outbound POST on new critical events
  7. Export          — CSV/JSON asset inventory + findings for SIEM/audit

All data is per-client isolated via ES index prefixes (asm_client_{id}_*).

Finding document schema (ES index: asm_client_{id}_findings):
{
    "id":                str (uuid),
    "client_id":         int,
    "asset_id":          str,
    "asset_value":       str,          # FQDN / IP / fingerprint
    "asset_type":        str,
    "category":          str,          # "cve"|"ssl"|"http_header"|"port"|"ti_hit"|
                                       # "email_security"|"dns_takeover"|"misconfiguration"
    "title":             str,
    "severity":          str,          # critical|high|medium|low|info
    "cve_id":            str|null,
    "cvss_score":        float|null,
    "epss_score":        float|null,   # 0.0–1.0 probability of exploitation
    "is_cisa_kev":       bool,         # in CISA Known Exploited Vulnerabilities
    "is_exploitable":    bool,
    "description":       str,
    "remediation":       str,
    "evidence":          dict,         # raw scan output that triggered this
    "status":            str,          # "open"|"accepted"|"remediated"
    "first_seen":        ISO datetime,
    "last_seen":         ISO datetime,
    "source":            str,          # "dns_scan"|"ssl_check"|"http_check"|"ti_feed"|...
}
"""

import asyncio
import hashlib
import hmac
import json
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

import httpx

from app.core.config import settings
from app.core.net_guard import resolve_public_ips, SSRFError

logger = logging.getLogger(__name__)

# CISA KEV domain (updated daily) — we cache in memory
_CISA_KEV_CACHE: set = set()
_CISA_KEV_FETCHED_AT: Optional[datetime] = None
_CISA_KEV_TTL = timedelta(hours=12)

# EPSS score cache: {cve_id -> score}
_EPSS_CACHE: Dict[str, float] = {}


# =============================================================================
# CISA KEV helpers
# =============================================================================

async def _ensure_cisa_kev() -> set:
    """Fetch CISA KEV catalog if stale. Returns set of CVE IDs."""
    global _CISA_KEV_CACHE, _CISA_KEV_FETCHED_AT
    now = datetime.utcnow()
    if _CISA_KEV_FETCHED_AT and (now - _CISA_KEV_FETCHED_AT) < _CISA_KEV_TTL:
        return _CISA_KEV_CACHE
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            )
            r.raise_for_status()
            data = r.json()
            _CISA_KEV_CACHE = {v["cveID"] for v in data.get("vulnerabilities", [])}
            _CISA_KEV_FETCHED_AT = now
            logger.info(f"CISA KEV updated: {len(_CISA_KEV_CACHE)} CVEs")
    except Exception as e:
        logger.warning(f"Could not fetch CISA KEV: {e}")
    return _CISA_KEV_CACHE


async def get_epss_score(cve_id: str) -> float:
    """Return EPSS exploitation-probability for a CVE (0.0–1.0)."""
    if cve_id in _EPSS_CACHE:
        return _EPSS_CACHE[cve_id]
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                f"https://api.first.org/data/v1/epss?cve={cve_id}"
            )
            r.raise_for_status()
            data = r.json()
            score = float(data["data"][0]["epss"]) if data.get("data") else 0.0
            _EPSS_CACHE[cve_id] = score
            return score
    except Exception:
        return 0.0


# =============================================================================
# HTTP / Tech fingerprinting
# =============================================================================

HEADERS_TO_CHECK = [
    ("strict-transport-security", "high",   "Missing HSTS",
     "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"),
    ("x-frame-options",            "medium", "Missing X-Frame-Options",
     "Add: X-Frame-Options: SAMEORIGIN"),
    ("x-content-type-options",    "low",    "Missing X-Content-Type-Options",
     "Add: X-Content-Type-Options: nosniff"),
    ("content-security-policy",   "medium", "Missing Content-Security-Policy",
     "Define a Content-Security-Policy header."),
    ("referrer-policy",           "low",    "Missing Referrer-Policy",
     "Add: Referrer-Policy: strict-origin-when-cross-origin"),
    ("permissions-policy",        "low",    "Missing Permissions-Policy",
     "Add a Permissions-Policy header."),
]

TECH_SIGNATURES: Dict[str, List[Tuple[str, str]]] = {
    # (header_or_field, pattern) → tech_name
    "Server": [
        ("Apache", "Apache"),
        ("nginx", "nginx"),
        ("Microsoft-IIS", "IIS"),
        ("cloudflare", "Cloudflare"),
        ("AmazonS3", "AWS S3"),
        ("LiteSpeed", "LiteSpeed"),
    ],
    "X-Powered-By": [
        ("PHP", "PHP"),
        ("ASP.NET", "ASP.NET"),
        ("Express", "Node.js/Express"),
        ("Django", "Django"),
    ],
    "X-Generator": [
        ("WordPress", "WordPress"),
        ("Drupal", "Drupal"),
        ("Joomla", "Joomla"),
    ],
}


async def http_fingerprint(domain: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Perform HTTP checks on a domain:
      - Follow redirects, capture chain
      - Check security headers
      - Fingerprint technology stack
      - Detect admin/login pages
    Returns dict with findings list, tech_stack list, redirect_chain.
    """
    result: Dict[str, Any] = {
        "url": f"https://{domain}",
        "reachable": False,
        "status_code": None,
        "redirect_chain": [],
        "tech_stack": [],
        "header_findings": [],
        "response_time_ms": None,
        "error": None,
    }

    # SSRF guard: discovery-group seeds are user-controlled and reach this
    # function via the Celery worker (bypassing the API-layer guard), so we
    # must validate here too. follow_redirects is disabled so a 3xx to an
    # internal address cannot bypass the pre-request validation.
    try:
        await resolve_public_ips(domain)
    except SSRFError as e:
        result["error"] = f"blocked: {e}"
        return result

    try:
        import time
        start = time.monotonic()
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            verify=False,
            headers={"User-Agent": "JichoSec-ASM/1.0 (+https://jichosec.defendanddetect.com)"},
        ) as client:
            r = await client.get(f"https://{domain}")

        elapsed = int((time.monotonic() - start) * 1000)
        result["reachable"] = True
        result["status_code"] = r.status_code
        result["response_time_ms"] = elapsed

        # Redirect chain
        result["redirect_chain"] = [str(h.url) for h in r.history] + [str(r.url)]

        headers = {k.lower(): v for k, v in r.headers.items()}

        # Security header audit
        for hdr, sev, title, rem in HEADERS_TO_CHECK:
            if hdr not in headers:
                result["header_findings"].append({
                    "header": hdr,
                    "severity": sev,
                    "title": title,
                    "remediation": rem,
                })

        # Tech fingerprinting
        tech: List[str] = []
        for header_name, signatures in TECH_SIGNATURES.items():
            val = headers.get(header_name.lower(), "")
            for pattern, label in signatures:
                if pattern.lower() in val.lower():
                    tech.append(label)

        # Body-based fingerprinting (minimal — just meta generator)
        try:
            body_sample = r.text[:4000]
            if "wp-content" in body_sample or "wordpress" in body_sample.lower():
                tech.append("WordPress")
            if "drupal" in body_sample.lower():
                tech.append("Drupal")
            if "react" in body_sample.lower() and "root" in body_sample:
                tech.append("React")
            if "next.js" in body_sample.lower() or "__NEXT_DATA__" in body_sample:
                tech.append("Next.js")
            if "angular" in body_sample.lower():
                tech.append("Angular")
        except Exception:
            pass

        result["tech_stack"] = list(set(tech))

    except httpx.ConnectError:
        result["error"] = "Connection refused"
    except httpx.TimeoutException:
        result["error"] = "Timeout"
    except Exception as e:
        result["error"] = str(e)[:200]

    return result


# =============================================================================
# TI Correlation
# =============================================================================

async def correlate_assets_with_ti(
    es_client: Any,
    assets: List[Dict[str, Any]],
    ioc_index: str = "iocs",
) -> Dict[str, List[Dict[str, Any]]]:
    """
    For each IP/domain asset, query the live IOC index and return any matches.
    Returns: dict mapping asset_value → list of matching IOC docs
    """
    if not es_client or not assets:
        return {}

    # Collect unique IPs and domains
    indicators = set()
    for a in assets:
        if a.get("type") in ("ip", "domain", "subdomain"):
            indicators.add(a.get("value", "").lower().strip())

    if not indicators:
        return {}

    hits: Dict[str, List[Dict[str, Any]]] = {}

    try:
        # Batch query — ES terms query (up to 1024 values)
        indicator_list = list(indicators)[:512]
        response = await es_client.search(
            index=ioc_index,
            query={
                "bool": {
                    "filter": [
                        {"terms": {"indicator": indicator_list}},
                        {"term": {"active": True}},
                    ]
                }
            },
            size=200,
            _source=["indicator", "indicator_type", "threat_type", "source",
                     "confidence", "risk_score", "country_code", "first_seen",
                     "last_seen", "tags"],
            track_total_hits=False,
        )
        for hit in response["hits"]["hits"]:
            src = hit["_source"]
            val = src.get("indicator", "").lower()
            if val not in hits:
                hits[val] = []
            hits[val].append(src)
    except Exception as e:
        logger.error(f"TI correlation error: {e}")

    return hits


# =============================================================================
# Risk engine
# =============================================================================

SEV_WEIGHTS = {"critical": 30, "high": 15, "medium": 8, "low": 3, "info": 0}


def compute_risk_score(
    findings: List[Dict[str, Any]],
    ti_hits: int = 0,
    open_ports: int = 0,
    ssl_issues: int = 0,
    total_assets: int = 0,
) -> Tuple[float, str, List[str]]:
    """
    Compute a 0–100 composite risk score and A–F grade.

    Returns: (score, grade, factors_list)
    """
    score = 0.0
    factors: List[str] = []

    # ── Findings contribution ─────────────────────────────────────────────────
    sev_counts: Dict[str, int] = {s: 0 for s in SEV_WEIGHTS}
    for f in findings:
        sev = f.get("severity", "info")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    critical = sev_counts["critical"]
    high = sev_counts["high"]
    medium = sev_counts["medium"]
    low = sev_counts["low"]

    if critical:
        score += min(critical * 30, 40)
        factors.append(f"{critical} critical finding(s)")
    if high:
        score += min(high * 10, 20)
        factors.append(f"{high} high-severity finding(s)")
    if medium:
        score += min(medium * 4, 10)
    if low:
        score += min(low * 1, 5)

    # ── TI hits ───────────────────────────────────────────────────────────────
    if ti_hits > 0:
        score += min(ti_hits * 15, 25)
        factors.append(f"{ti_hits} asset(s) seen in threat-intel feeds")

    # ── EPSS / KEV boost ─────────────────────────────────────────────────────
    kev_count = sum(1 for f in findings if f.get("is_cisa_kev"))
    if kev_count:
        score += min(kev_count * 10, 20)
        factors.append(f"{kev_count} CVE(s) in CISA Known Exploited Vulnerabilities")

    exploitable = sum(1 for f in findings if f.get("is_exploitable"))
    if exploitable:
        score += min(exploitable * 5, 10)

    # ── Exposure ──────────────────────────────────────────────────────────────
    HIGH_RISK_PORTS = {21, 23, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 27017}
    if open_ports:
        score += min(open_ports * 1, 10)
        if open_ports > 5:
            factors.append(f"{open_ports} open port(s) exposed")

    if ssl_issues:
        score += min(ssl_issues * 8, 16)
        factors.append(f"{ssl_issues} SSL/TLS issue(s)")

    # ── Asset scale ───────────────────────────────────────────────────────────
    if total_assets > 50:
        score += 5
    if total_assets > 200:
        score += 5

    score = min(round(score, 1), 100.0)

    # Grade
    if score <= 10:
        grade = "A"
    elif score <= 25:
        grade = "B"
    elif score <= 45:
        grade = "C"
    elif score <= 65:
        grade = "D"
    else:
        grade = "F"

    return score, grade, factors


# =============================================================================
# Findings builder
# =============================================================================

def _normalize_finding(doc: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalise a finding document to the enterprise schema regardless of which
    scanner wrote it.  Old base-scanner docs use:
        affected_asset_value / affected_asset_type / detected_at
    Enterprise docs use:
        asset_value / asset_type / category / status / first_seen / last_seen / source

    Returns a new dict — does NOT mutate the original.
    """
    doc = dict(doc)  # shallow copy — never mutate the caller's dict
    # Field aliasing: prefer new names, fall back to old names
    doc.setdefault("asset_value",  doc.get("affected_asset_value", ""))
    doc.setdefault("asset_type",   doc.get("affected_asset_type", "unknown"))
    doc.setdefault("category",     _infer_category(doc))
    doc.setdefault("status",       "open")
    doc.setdefault("source",       "asm_scan")
    doc.setdefault("first_seen",   doc.get("detected_at", ""))
    doc.setdefault("last_seen",    doc.get("detected_at", ""))
    doc.setdefault("epss_score",   None)
    doc.setdefault("is_cisa_kev",  False)
    doc.setdefault("is_exploitable", doc.get("exploit_available", False))
    doc.setdefault("remediation",  None)
    doc.setdefault("references",   [])
    doc.setdefault("description",  "")
    doc.setdefault("cve_id",       None)
    doc.setdefault("cvss_score",   None)
    return doc


def _infer_category(doc: Dict[str, Any]) -> str:
    """Infer the finding category from its title/description for old-schema docs."""
    title = (doc.get("title") or "").lower()
    if "ssl" in title or "tls" in title or "certificate" in title:
        return "ssl"
    if "http" in title and ("header" in title or "csp" in title or "hsts" in title):
        return "http_header"
    if "cve-" in title:
        return "cve"
    if "service" in title or "port" in title:
        return "port"
    if "dns" in title and "takeover" in title:
        return "dns_takeover"
    if "spf" in title or "dkim" in title or "dmarc" in title or "email" in title:
        return "email_security"
    if "ti" in title or "threat" in title or "ioc" in title:
        return "ti_hit"
    if "credential" in title or "leak" in title or "breach" in title:
        return "credential_leak"
    if "dark web" in title or "darkweb" in title:
        return "darkweb_mention"
    if "brand" in title or "typosquat" in title or "impersonation" in title:
        return "brand_impersonation"
    return "misconfiguration"


def make_finding(
    client_id: int,
    asset_id: str,
    asset_value: str,
    asset_type: str,
    category: str,
    title: str,
    severity: str,
    description: str,
    remediation: str = "",
    cve_id: Optional[str] = None,
    cvss_score: Optional[float] = None,
    epss_score: Optional[float] = None,
    is_cisa_kev: bool = False,
    is_exploitable: bool = False,
    evidence: Optional[Dict] = None,
    source: str = "asm_scan",
) -> Dict[str, Any]:
    """Build a normalised finding document for the ES findings index."""
    now = datetime.utcnow().isoformat()
    # Deterministic ID: category + asset + title so re-scans upsert
    dedup_key = f"{client_id}:{asset_value}:{category}:{title}"
    finding_id = hashlib.md5(dedup_key.encode()).hexdigest()
    return {
        "id": finding_id,
        "client_id": client_id,
        "asset_id": asset_id,
        "asset_value": asset_value,
        "asset_type": asset_type,
        "category": category,
        "title": title,
        "severity": severity,
        "cve_id": cve_id,
        "cvss_score": cvss_score,
        "epss_score": epss_score,
        "is_cisa_kev": is_cisa_kev,
        "is_exploitable": is_exploitable,
        "description": description,
        "remediation": remediation,
        "evidence": evidence or {},
        "status": "open",
        "source": source,
        "first_seen": now,
        "last_seen": now,
    }


# =============================================================================
# Webhook sender
# =============================================================================

async def send_webhook(
    url: str,
    payload: Dict[str, Any],
    signing_secret: str = "",
) -> bool:
    """
    POST a JSON payload to the webhook URL.
    Signs with HMAC-SHA256 if signing_secret is provided.
    """
    body = json.dumps(payload, default=str)
    headers = {"Content-Type": "application/json", "User-Agent": "JichoSec-ASM/1.0"}
    if signing_secret:
        sig = hmac.new(signing_secret.encode(), body.encode(), hashlib.sha256).hexdigest()
        headers["X-JichoSec-Signature"] = f"sha256={sig}"

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(url, content=body, headers=headers)
            return r.status_code < 300
    except Exception as e:
        logger.warning(f"Webhook delivery failed to {url}: {e}")
        return False


# =============================================================================
# Enterprise ASM Service
# =============================================================================

class ASMEnterpriseService:
    """
    Wraps AttackSurfaceManager with enterprise SOC capabilities.
    Instantiated per-client (takes client_id + es_client).
    """

    def __init__(self, es_client: Any, client_id: int):
        self.es = es_client
        self.client_id = client_id
        self._prefix = f"asm_client_{client_id}"
        self.assets_index = f"{self._prefix}_assets"
        self.findings_index = f"{self._prefix}_findings"
        self.changes_index = f"{self._prefix}_changes"
        self.ti_hits_index = f"{self._prefix}_ti_hits"
        self.ioc_index = "iocs"

    # ── Index creation ────────────────────────────────────────────────────────

    async def ensure_indices(self) -> None:
        """Create ES indices with correct mappings if they don't exist."""
        if not self.es:
            return

        findings_mapping = {
            "id": {"type": "keyword"},
            "client_id": {"type": "integer"},
            "asset_id": {"type": "keyword"},
            "asset_value": {"type": "keyword"},
            "asset_type": {"type": "keyword"},
            "category": {"type": "keyword"},
            "title": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
            "severity": {"type": "keyword"},
            "cve_id": {"type": "keyword"},
            "cvss_score": {"type": "float"},
            "epss_score": {"type": "float"},
            "is_cisa_kev": {"type": "boolean"},
            "is_exploitable": {"type": "boolean"},
            "status": {"type": "keyword"},
            "source": {"type": "keyword"},
            "first_seen": {"type": "date"},
            "last_seen": {"type": "date"},
        }

        assets_mapping = {
            "id": {"type": "keyword"},
            "client_id": {"type": "integer"},
            "type": {"type": "keyword"},
            "value": {
                "type": "text",
                "fields": {"keyword": {"type": "keyword"}},
            },
            "status": {"type": "keyword"},
            "risk_score": {"type": "float"},
            "tags": {"type": "keyword"},
            "tech_stack": {"type": "keyword"},
            "owner": {"type": "keyword"},
            "environment": {"type": "keyword"},
            "business_unit": {"type": "keyword"},
            "ti_tagged": {"type": "boolean"},
            "ti_threat_types": {"type": "keyword"},
            "first_seen": {"type": "date"},
            "last_seen": {"type": "date"},
            "root_domain": {"type": "keyword"},
        }

        for index, properties in [
            (self.findings_index, findings_mapping),
            (self.assets_index, assets_mapping),
        ]:
            try:
                exists = await self.es.indices.exists(index=index)
                if not exists:
                    await self.es.indices.create(
                        index=index,
                        mappings={"properties": properties},
                    )
                    logger.info(f"Created index {index}")
            except Exception as e:
                logger.warning(f"Index {index} setup: {e}")

    # ── Findings CRUD ─────────────────────────────────────────────────────────

    async def upsert_finding(self, finding: Dict[str, Any]) -> None:
        """Upsert a finding into ES (deduplicated by finding ID = MD5 of key fields)."""
        if not self.es:
            return
        finding["last_seen"] = datetime.utcnow().isoformat()
        try:
            await self.es.update(
                index=self.findings_index,
                id=finding["id"],
                doc=finding,
                doc_as_upsert=True,
                retry_on_conflict=3,
            )
        except Exception as e:
            logger.error(f"Upsert finding {finding.get('id')}: {e}")

    async def get_findings(
        self,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        status: str = "open",
        asset_value: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 200,
        offset: int = 0,
        sort_by: str = "severity",
    ) -> Tuple[List[Dict], int]:
        """Query findings for this client."""
        if not self.es:
            return [], 0

        filters: List[Dict] = []
        musts: List[Dict] = []
        if severity:
            filters.append({"term": {"severity": severity}})
        if category:
            filters.append({"term": {"category": category}})
        if status:
            filters.append({"term": {"status": status}})
        if asset_value:
            filters.append({"term": {"asset_value": asset_value}})
        if search:
            musts.append({"multi_match": {
                "query": search,
                "fields": ["title^3", "description^2", "asset_value"],
                "type": "best_fields",
            }})

        if musts:
            query: Dict = {"bool": {"must": musts, "filter": filters}}
        elif filters:
            query = {"bool": {"filter": filters}}
        else:
            query = {"match_all": {}}

        # Severity sort: custom order
        sev_order_script = {
            "_script": {
                "type": "number",
                "script": {
                    "source": """
                        def m = ['critical':0,'high':1,'medium':2,'low':3,'info':4];
                        return m.getOrDefault(doc['severity'].value, 5);
                    """
                },
                "order": "asc",
            }
        }

        try:
            resp = await self.es.search(
                index=self.findings_index,
                query=query,
                sort=[sev_order_script, {"last_seen": "desc"}],
                size=limit,
                from_=offset,
                track_total_hits=True,
            )
            raw_hits = [h["_source"] for h in resp["hits"]["hits"]]
            total_raw = resp["hits"]["total"]
            total = total_raw["value"] if isinstance(total_raw, dict) else int(total_raw)
            # Normalise old-schema docs (written by base AttackSurfaceManager)
            # to the enterprise schema so the frontend always gets consistent fields.
            hits = [_normalize_finding(f) for f in raw_hits]
            return hits, total
        except Exception as e:
            logger.error(f"get_findings: {e}")
            return [], 0

    async def get_findings_summary(self) -> Dict[str, Any]:
        """Aggregate finding counts by severity + category."""
        if not self.es:
            return {}
        try:
            resp = await self.es.search(
                index=self.findings_index,
                query={"term": {"status": "open"}},
                size=0,
                track_total_hits=True,
                aggs={
                    "by_severity": {"terms": {"field": "severity", "size": 10}},
                    "by_category": {"terms": {"field": "category", "size": 20}},
                    "kev_count": {"filter": {"term": {"is_cisa_kev": True}}},
                    "exploitable": {"filter": {"term": {"is_exploitable": True}}},
                    "avg_epss": {"avg": {"field": "epss_score"}},
                },
            )
            aggs = resp["aggregations"]
            total_raw = resp["hits"]["total"]
            total = total_raw["value"] if isinstance(total_raw, dict) else int(total_raw)
            return {
                "total_open": total,
                "by_severity": {b["key"]: b["doc_count"] for b in aggs["by_severity"]["buckets"]},
                "by_category": {b["key"]: b["doc_count"] for b in aggs["by_category"]["buckets"]},
                "kev_count": aggs["kev_count"]["doc_count"],
                "exploitable_count": aggs["exploitable"]["doc_count"],
                "avg_epss": round(aggs["avg_epss"]["value"] or 0.0, 4),
            }
        except Exception as e:
            logger.error(f"get_findings_summary: {e}")
            return {}

    # ── TI correlation ────────────────────────────────────────────────────────

    async def run_ti_correlation(self) -> Dict[str, Any]:
        """
        Join all assets for this client against the live IOC index.
        Tags matching assets and creates TI-hit findings.
        Returns summary counts.
        """
        if not self.es:
            return {"ti_hits": 0}

        # Fetch all IP + domain assets
        try:
            assets_resp = await self.es.search(
                index=self.assets_index,
                query={"terms": {"type": ["ip", "domain", "subdomain"]}},
                size=5000,
                _source=["id", "type", "value", "client_id"],
                track_total_hits=False,
            )
            assets = [h["_source"] for h in assets_resp["hits"]["hits"]]
        except Exception:
            return {"ti_hits": 0}

        if not assets:
            return {"ti_hits": 0}

        ti_map = await correlate_assets_with_ti(self.es, assets, self.ioc_index)

        ti_hits_total = 0
        for asset in assets:
            val = asset.get("value", "").lower()
            matches = ti_map.get(val, [])
            if not matches:
                continue

            ti_hits_total += 1

            # Tag the asset
            threat_types = list({m.get("threat_type", "unknown") for m in matches})
            try:
                await self.es.update(
                    index=self.assets_index,
                    id=asset["id"],
                    doc={
                        "ti_tagged": True,
                        "ti_threat_types": threat_types,
                        "ti_hit_count": len(matches),
                        "ti_last_seen": datetime.utcnow().isoformat(),
                    },
                    doc_as_upsert=True,
                    retry_on_conflict=3,
                )
            except Exception:
                pass

            # Create a finding for each unique threat type hit
            for match in matches[:5]:  # Cap at 5 findings per asset
                severity = "critical" if match.get("threat_type") in ("c2", "malware") else "high"
                finding = make_finding(
                    client_id=self.client_id,
                    asset_id=asset["id"],
                    asset_value=asset["value"],
                    asset_type=asset["type"],
                    category="ti_hit",
                    title=f"Asset in {match.get('threat_type','unknown').upper()} threat-intel feed",
                    severity=severity,
                    description=(
                        f"{asset['value']} was seen in {match.get('source','unknown')} "
                        f"as {match.get('threat_type','unknown')} indicator. "
                        f"Confidence: {match.get('confidence',0):.0%}."
                    ),
                    remediation=(
                        "Investigate this asset immediately. If legitimate, add to allow-list. "
                        "Check for signs of compromise (unusual outbound traffic, new processes)."
                    ),
                    evidence=match,
                    source="ti_correlation",
                )
                await self.upsert_finding(finding)

        return {"ti_hits": ti_hits_total, "assets_checked": len(assets)}

    # ── Platform dataset correlation ──────────────────────────────────────────

    async def run_platform_correlation(
        self,
        client: Any,          # ASMClient model instance
        domains: List[str],   # seed domains for this client
    ) -> Dict[str, Any]:
        """
        Cross-correlate ALL platform datasets against this client's identity:

        1. IOC index (iocs)         — match client domains/IPs against C2/phishing/malware IOCs
        2. Credential exposures     — match client domains against leaked credential records
        3. Dark web posts           — match client name/domains against dark web crawl results
        4. Brand monitors/alerts    — match client name against brand impersonation detections

        Each hit creates a finding in the client's findings index with full context.
        Returns counts per dataset for risk scoring.
        """
        if not self.es:
            return {}

        counts: Dict[str, int] = {
            "ioc_hits": 0,
            "credential_hits": 0,
            "darkweb_hits": 0,
            "brand_hits": 0,
        }

        # Build correlation identifiers
        client_name = getattr(client, "name", "") or ""
        country_code = getattr(client, "country_code", "") or ""
        # Extract root domains (strip www. prefix)
        root_domains = list({
            d.lstrip("www.").lower() for d in domains if d
        })
        # Name keywords: first two words, lowercased
        name_keywords = [w.lower() for w in client_name.split()[:2] if len(w) > 3]

        now = datetime.utcnow().isoformat()

        # ── 1. IOC correlation ────────────────────────────────────────────────
        # Match client domains/subdomains against the live IOC feed
        try:
            ioc_query = {
                "bool": {
                    "should": [
                        {"terms": {"indicator": root_domains}},
                        *[{"wildcard": {"indicator": f"*{d}*"}} for d in root_domains[:3]],
                    ],
                    "minimum_should_match": 1,
                    "filter": [{"term": {"active": True}}],
                }
            }
            resp = await self.es.search(
                index="iocs",
                query=ioc_query,
                size=50,
                _source=["indicator", "indicator_type", "threat_type", "source",
                         "risk_score", "confidence", "tags", "first_seen"],
            )
            hits = resp["hits"]["hits"]
            counts["ioc_hits"] = len(hits)

            for h in hits:
                src = h["_source"]
                threat = src.get("threat_type", "unknown")
                sev = (
                    "critical" if src.get("risk_score", 0) >= 80 else
                    "high"     if src.get("risk_score", 0) >= 60 else
                    "medium"
                )
                asset_val = src.get("indicator", "")
                asset_id = hashlib.md5(asset_val.encode()).hexdigest()
                finding = make_finding(
                    client_id=self.client_id,
                    asset_id=asset_id,
                    asset_value=asset_val,
                    asset_type=src.get("indicator_type", "domain"),
                    category="ti_hit",
                    title=f"IOC Feed Hit: {threat.upper()} — {asset_val[:60]}",
                    severity=sev,
                    description=(
                        f"A client asset ({asset_val}) was found in the platform's live threat "
                        f"intelligence feed as a known {threat} indicator. "
                        f"Source: {src.get('source', 'unknown')}. "
                        f"Confidence: {float(src.get('confidence', 0)) * 100:.0f}%."
                    ),
                    remediation=(
                        "Block this indicator at the perimeter firewall and DNS resolver. "
                        "Investigate any outbound connections to this indicator for signs of "
                        "compromise. If this is a false positive, submit for review."
                    ),
                    evidence=src,
                    source="platform_ioc_correlation",
                )
                await self.upsert_finding(finding)

        except Exception as e:
            logger.warning(f"[platform_corr] IOC correlation failed for client {self.client_id}: {e}")

        # ── 2. Credential exposure correlation ────────────────────────────────
        # Match client's root domains in the credential_exposures index
        try:
            cred_query = {
                "bool": {
                    "should": [{"term": {"domain": d}} for d in root_domains],
                    "minimum_should_match": 1,
                }
            }
            resp = await self.es.search(
                index="credential_exposures",
                query=cred_query,
                size=100,
                _source=["email", "username", "domain", "password_type", "source_name",
                         "breach_date", "severity", "discovered_at", "country"],
            )
            hits = resp["hits"]["hits"]
            counts["credential_hits"] = resp["hits"]["total"]["value"] if isinstance(resp["hits"]["total"], dict) else len(hits)

            # Create one finding per unique (domain, source_name) pair rather than per row
            seen_breach: set = set()
            for h in hits:
                src = h["_source"]
                breach_key = f"{src.get('domain', '')}::{src.get('source_name', '')}"
                if breach_key in seen_breach:
                    continue
                seen_breach.add(breach_key)

                sev = src.get("severity", "high")
                domain_hit = src.get("domain", "")
                asset_id = hashlib.md5(domain_hit.encode()).hexdigest()
                plaintext = src.get("password_type") == "plaintext"
                finding = make_finding(
                    client_id=self.client_id,
                    asset_id=asset_id,
                    asset_value=domain_hit,
                    asset_type="domain",
                    category="credential_leak",
                    title=f"Credential Leak: {domain_hit} in «{src.get('source_name', 'Unknown Breach')}»",
                    severity="critical" if plaintext else sev,
                    description=(
                        f"Employee or customer credentials for {domain_hit} were found in a "
                        f"data breach ({src.get('source_name', 'unknown source')}). "
                        f"{'Passwords are exposed in PLAINTEXT — immediate password reset required. ' if plaintext else ''}"
                        f"Total exposed records matching this domain: {counts['credential_hits']}. "
                        f"Breach date: {src.get('breach_date', 'unknown')}."
                    ),
                    remediation=(
                        "Force an immediate password reset for all affected accounts. "
                        "Enable MFA on all corporate systems. "
                        "Notify affected users and review access logs for suspicious activity. "
                        "Consider engaging a breach notification service."
                    ),
                    evidence={
                        "domain": domain_hit,
                        "source_name": src.get("source_name"),
                        "total_exposed": counts["credential_hits"],
                        "password_type": src.get("password_type"),
                        "breach_date": src.get("breach_date"),
                    },
                    source="platform_credential_correlation",
                )
                await self.upsert_finding(finding)

        except Exception as e:
            logger.warning(f"[platform_corr] Credential correlation failed for client {self.client_id}: {e}")

        # ── 3. Dark web post correlation ──────────────────────────────────────
        # Match client name/domains in dark web crawl results
        try:
            dw_should = []
            for d in root_domains[:5]:
                dw_should.append({"match_phrase": {"body_text": d}})
                dw_should.append({"match_phrase": {"domains_found": d}})
            for kw in name_keywords:
                dw_should.append({"match": {"body_text": kw}})

            if dw_should:
                dw_query = {"bool": {"should": dw_should, "minimum_should_match": 1}}
                resp = await self.es.search(
                    index="darkweb_posts",
                    query=dw_query,
                    size=20,
                    _source=["url", "title", "body_text", "source", "severity",
                             "discovered_at", "emails_found", "domains_found", "tags"],
                )
                hits = resp["hits"]["hits"]
                counts["darkweb_hits"] = len(hits)

                for h in hits:
                    src = h["_source"]
                    sev = src.get("severity", "medium")
                    title_str = src.get("title", "Unknown")[:80]
                    asset_id = hashlib.md5(src.get("url", "dw").encode()).hexdigest()
                    finding = make_finding(
                        client_id=self.client_id,
                        asset_id=asset_id,
                        asset_value=src.get("url", "darkweb"),
                        asset_type="url",
                        category="darkweb_mention",
                        title=f"Dark Web Mention: {title_str}",
                        severity=sev,
                        description=(
                            f"A reference to this client was found in a dark web crawl result. "
                            f"Source: {src.get('source', 'unknown')}. "
                            f"Title: {title_str}. "
                            f"Emails found: {src.get('emails_found', [])}. "
                            f"Domains found: {src.get('domains_found', [])}."
                        ),
                        remediation=(
                            "Review the dark web post for any leaked data. "
                            "If sensitive information is present, engage incident response. "
                            "Monitor for further mentions and consider a takedown request."
                        ),
                        evidence=src,
                        source="platform_darkweb_correlation",
                    )
                    await self.upsert_finding(finding)

        except Exception as e:
            logger.warning(f"[platform_corr] Dark web correlation failed for client {self.client_id}: {e}")

        # ── 4. Brand impersonation correlation ────────────────────────────────
        # Match client name/domains in brand_monitors and brand_alerts
        try:
            brand_should = []
            for kw in name_keywords + root_domains[:3]:
                brand_should.append({"match": {"brand_name": kw}})
                brand_should.append({"match_phrase": {"domains": kw}})

            if brand_should:
                # brand_monitors
                try:
                    resp = await self.es.search(
                        index="brand_monitors",
                        query={"bool": {"should": brand_should, "minimum_should_match": 1}},
                        size=20,
                        _source=["brand_name", "domains", "typosquat_count", "last_scan_at"],
                    )
                    monitor_hits = resp["hits"]["hits"]
                except Exception:
                    monitor_hits = []

                # brand_alerts
                try:
                    resp = await self.es.search(
                        index="brand_alerts",
                        query={"bool": {"should": brand_should, "minimum_should_match": 1}},
                        size=20,
                        _source=["brand_name", "alert_type", "domain", "similarity",
                                 "severity", "discovered_at", "url"],
                    )
                    alert_hits = resp["hits"]["hits"]
                except Exception:
                    alert_hits = []

                counts["brand_hits"] = len(monitor_hits) + len(alert_hits)

                for h in alert_hits:
                    src = h["_source"]
                    domain_hit = src.get("domain", src.get("url", client_name))
                    asset_id = hashlib.md5(domain_hit.encode()).hexdigest()
                    finding = make_finding(
                        client_id=self.client_id,
                        asset_id=asset_id,
                        asset_value=domain_hit,
                        asset_type="domain",
                        category="brand_impersonation",
                        title=f"Brand Impersonation: {src.get('alert_type', 'typosquat')} — {domain_hit}",
                        severity=src.get("severity", "high"),
                        description=(
                            f"A brand impersonation asset targeting «{src.get('brand_name', client_name)}» "
                            f"was detected. Type: {src.get('alert_type', 'unknown')}. "
                            f"Similarity: {src.get('similarity', '?')}%. "
                            f"URL: {src.get('url', 'unknown')}."
                        ),
                        remediation=(
                            "Submit a takedown request to the registrar and hosting provider. "
                            "Report to the relevant CERT. "
                            "Alert customers to avoid this domain via official channels."
                        ),
                        evidence=src,
                        source="platform_brand_correlation",
                    )
                    await self.upsert_finding(finding)

        except Exception as e:
            logger.warning(f"[platform_corr] Brand correlation failed for client {self.client_id}: {e}")

        total_platform_hits = sum(counts.values())
        logger.info(
            f"[platform_corr] client={self.client_id} "
            f"ioc={counts['ioc_hits']} cred={counts['credential_hits']} "
            f"dw={counts['darkweb_hits']} brand={counts['brand_hits']}"
        )
        return {**counts, "total_platform_hits": total_platform_hits}

    # ── HTTP checks + tech fingerprinting ────────────────────────────────────

    async def run_http_checks(self, domains: List[str]) -> List[Dict[str, Any]]:
        """
        Run HTTP checks on a list of domains concurrently.
        Creates header and tech-stack findings.
        Returns list of http_fingerprint results.
        """
        if not domains:
            return []

        results = await asyncio.gather(
            *[http_fingerprint(d) for d in domains[:50]],  # cap at 50 concurrent
            return_exceptions=True,
        )

        output = []
        for domain, result in zip(domains[:50], results):
            if isinstance(result, Exception):
                continue
            output.append(result)

            if not result.get("reachable"):
                continue

            # Create findings for missing security headers
            for hf in result.get("header_findings", []):
                asset_id = hashlib.md5(domain.encode()).hexdigest()
                finding = make_finding(
                    client_id=self.client_id,
                    asset_id=asset_id,
                    asset_value=domain,
                    asset_type="domain",
                    category="http_header",
                    title=hf["title"],
                    severity=hf["severity"],
                    description=f"The {hf['header']} HTTP security header is missing on {domain}.",
                    remediation=hf["remediation"],
                    source="http_check",
                )
                await self.upsert_finding(finding)

            # Update asset with tech stack
            try:
                asset_id = hashlib.md5(domain.encode()).hexdigest()
                await self.es.update(
                    index=self.assets_index,
                    id=asset_id,
                    doc={
                        "tech_stack": result.get("tech_stack", []),
                        "last_http_check": datetime.utcnow().isoformat(),
                        "http_status": result.get("status_code"),
                    },
                    doc_as_upsert=True,
                    retry_on_conflict=3,
                )
            except Exception:
                pass

        return output

    # ── CVE enrichment ────────────────────────────────────────────────────────

    async def enrich_cve_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        For findings that have a cve_id, fetch EPSS score + CISA KEV flag.
        Returns enriched findings list.
        """
        kev = await _ensure_cisa_kev()

        enriched = []
        for f in findings:
            cve = f.get("cve_id")
            if cve:
                epss = await get_epss_score(cve)
                f["epss_score"] = epss
                f["is_cisa_kev"] = cve in kev
                f["is_exploitable"] = epss > 0.1 or f["is_cisa_kev"]
                # Promote severity if high EPSS or KEV
                if f["is_cisa_kev"] and f.get("severity") not in ("critical",):
                    f["severity"] = "critical"
                elif epss > 0.5 and f.get("severity") not in ("critical", "high"):
                    f["severity"] = "high"
            enriched.append(f)
        return enriched

    # ── Full client scan pipeline ─────────────────────────────────────────────

    async def run_full_scan(
        self,
        client: Any,  # ASMClient model instance
        domains: List[str],
    ) -> Dict[str, Any]:
        """
        Orchestrates the full enterprise scan pipeline:
          1. Run base discovery (AttackSurfaceManager) for each domain
          2. Run HTTP checks + tech fingerprinting on web assets
          3. Run TI correlation
          4. Enrich CVE findings with EPSS + KEV
          5. Compute composite risk score
          6. Send webhook alerts for critical findings (if configured)
        """
        from app.services.attack_surface import AttackSurfaceManager

        await self.ensure_indices()

        asm = AttackSurfaceManager(
            es_client=self.es,
            client_id=self.client_id,
        )

        scan_results = []
        all_findings: List[Dict[str, Any]] = []

        # Step 1: Discovery per domain
        for domain in domains:
            try:
                result = await asm.discover_assets(
                    domain=domain,
                    include_subdomains=True,
                    include_ports=True,
                    include_ssl=True,
                )
                scan_results.append({
                    "domain": domain,
                    "assets": len(result.assets),
                    "error": result.error,
                })

                # Convert raw vulnerabilities → findings
                for vuln in result.vulnerabilities:
                    f = make_finding(
                        client_id=self.client_id,
                        asset_id=vuln.affected_asset_id,
                        asset_value=vuln.affected_asset_value,
                        asset_type=vuln.affected_asset_type.value,
                        category="cve" if vuln.cve_id else "misconfiguration",
                        title=vuln.title,
                        severity=vuln.severity.value,
                        description=vuln.description,
                        remediation=vuln.remediation or "",
                        cve_id=vuln.cve_id,
                        cvss_score=vuln.cvss_score,
                        is_exploitable=vuln.is_exploitable,
                        source="asm_scan",
                    )
                    all_findings.append(f)

                # SSL findings
                if result.ssl_info and result.ssl_info.issues:
                    asset_id = next(
                        (a.id for a in result.assets if a.type.value == "certificate"),
                        hashlib.md5(domain.encode()).hexdigest()
                    )
                    for issue in result.ssl_info.issues:
                        sev = "critical" if result.ssl_info.is_expired else "high" if result.ssl_info.days_until_expiry < 14 else "medium"
                        f = make_finding(
                            client_id=self.client_id,
                            asset_id=asset_id,
                            asset_value=domain,
                            asset_type="certificate",
                            category="ssl",
                            title=f"SSL/TLS Issue: {issue}",
                            severity=sev,
                            description=issue,
                            remediation="Renew or reconfigure the SSL/TLS certificate.",
                            source="ssl_check",
                        )
                        all_findings.append(f)

            except Exception as e:
                logger.error(f"Discovery failed for {domain}: {e}")
                scan_results.append({"domain": domain, "assets": 0, "error": str(e)})

        # Step 2: HTTP checks on web domains
        web_domains = [d for d in domains if not d.replace(".", "").isdigit()][:20]
        if web_domains:
            http_results = await self.run_http_checks(web_domains)
            for hr in http_results:
                for hf in hr.get("header_findings", []):
                    http_domain = hr["url"].replace("https://", "").replace("http://", "").split("/")[0]
                    asset_id = hashlib.md5(http_domain.encode()).hexdigest()
                    f = make_finding(
                        client_id=self.client_id,
                        asset_id=asset_id,
                        asset_value=http_domain,
                        asset_type="domain",
                        category="http_header",
                        title=hf["title"],
                        severity=hf["severity"],
                        description=f"Missing {hf['header']} security header on {http_domain}.",
                        remediation=hf["remediation"],
                        source="http_check",
                    )
                    all_findings.append(f)

        # Step 3: Enrich CVE findings
        all_findings = await self.enrich_cve_findings(all_findings)

        # Step 4: Upsert all findings
        for f in all_findings:
            await self.upsert_finding(f)

        # Step 5: TI correlation (asset IPs/domains vs IOC index)
        ti_result = await self.run_ti_correlation()

        # Step 5b: Platform-wide dataset correlation
        # (credential leaks, dark web mentions, brand impersonation, IOC feed)
        platform_result = await self.run_platform_correlation(
            client=client,
            domains=domains,
        )

        # Step 6: Compute risk score using all findings including platform hits
        findings_summary = await self.get_findings_summary()
        open_findings = findings_summary.get("total_open", 0)
        critical = findings_summary.get("by_severity", {}).get("critical", 0)
        high = findings_summary.get("by_severity", {}).get("high", 0)
        score, grade, factors = compute_risk_score(
            findings=all_findings,
            ti_hits=ti_result.get("ti_hits", 0) + platform_result.get("ioc_hits", 0),
            open_ports=sum(1 for _ in all_findings if _.get("category") == "port"),
            ssl_issues=sum(1 for _ in all_findings if _.get("category") == "ssl"),
            total_assets=sum(r["assets"] for r in scan_results),
        )
        # Boost risk score for credential leaks and dark web mentions
        cred_hits = platform_result.get("credential_hits", 0)
        dw_hits = platform_result.get("darkweb_hits", 0)
        brand_hits_p = platform_result.get("brand_hits", 0)
        if cred_hits > 0:
            score = min(score + min(cred_hits * 0.5, 15), 100.0)
            factors.append(f"{cred_hits} credential record(s) found in breach databases")
        if dw_hits > 0:
            score = min(score + min(dw_hits * 5, 15), 100.0)
            factors.append(f"{dw_hits} dark web mention(s) detected")
        if brand_hits_p > 0:
            score = min(score + min(brand_hits_p * 5, 10), 100.0)
            factors.append(f"{brand_hits_p} brand impersonation indicator(s) found")
        score = round(score, 1)

        # Step 7: Webhook alert for critical findings
        new_critical = [f for f in all_findings if f.get("severity") == "critical"]
        if new_critical and client.webhook_url and "critical_finding" in (client.notify_on or []):
            payload = {
                "event": "critical_finding",
                "client": client.name,
                "client_id": client.id,
                "count": len(new_critical),
                "findings": new_critical[:5],
                "risk_score": score,
                "grade": grade,
                "timestamp": datetime.utcnow().isoformat(),
            }
            await send_webhook(
                client.webhook_url,
                payload,
                settings.WEBHOOK_SIGNING_SECRET,
            )

        return {
            "scan_results": scan_results,
            "total_findings": open_findings,
            "critical": critical,
            "high": high,
            "ti_hits": ti_result.get("ti_hits", 0),
            "platform_hits": platform_result,
            "risk_score": score,
            "grade": grade,
            "risk_factors": factors,
        }

    # ── Asset queries ─────────────────────────────────────────────────────────

    async def get_assets(
        self,
        asset_type: Optional[str] = None,
        search: Optional[str] = None,
        ti_tagged: Optional[bool] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Tuple[List[Dict], int]:
        """Query assets with full-text search support."""
        if not self.es:
            return [], 0

        filters: List[Dict] = []
        musts: List[Dict] = []

        if asset_type:
            filters.append({"term": {"type": asset_type}})
        if ti_tagged is not None:
            filters.append({"term": {"ti_tagged": ti_tagged}})
        if search:
            musts.append({"multi_match": {
                "query": search,
                "fields": ["value^3", "value.keyword^5", "tags", "tech_stack", "root_domain"],
                "type": "best_fields",
            }})

        if musts:
            query: Dict = {"bool": {"must": musts, "filter": filters}}
        elif filters:
            query = {"bool": {"filter": filters}}
        else:
            query = {"match_all": {}}

        try:
            resp = await self.es.search(
                index=self.assets_index,
                query=query,
                sort=[{"risk_score": "desc"}, {"last_seen": "desc"}],
                size=limit,
                from_=offset,
                track_total_hits=True,
            )
            hits = [h["_source"] for h in resp["hits"]["hits"]]
            total_raw = resp["hits"]["total"]
            total = total_raw["value"] if isinstance(total_raw, dict) else int(total_raw)
            return hits, total
        except Exception as e:
            logger.error(f"get_assets: {e}")
            return [], 0

    # ── CSV Export ────────────────────────────────────────────────────────────

    async def export_csv(self, export_type: str = "assets") -> str:
        """
        Generate a CSV string for assets or findings.
        Used by the export endpoint for SIEM/audit ingestion.
        """
        import csv, io

        output = io.StringIO()

        if export_type == "assets":
            assets, _ = await self.get_assets(limit=5000)
            fieldnames = ["value", "type", "status", "risk_score", "ti_tagged",
                          "tech_stack", "tags", "first_seen", "last_seen", "root_domain"]
            writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for a in assets:
                row = {**a}
                row["tech_stack"] = "|".join(a.get("tech_stack") or [])
                row["tags"] = "|".join(a.get("tags") or [])
                writer.writerow(row)
        else:
            findings, _ = await self.get_findings(limit=5000)
            fieldnames = ["title", "severity", "category", "asset_value", "asset_type",
                          "cve_id", "cvss_score", "epss_score", "is_cisa_kev",
                          "is_exploitable", "status", "first_seen", "last_seen"]
            writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for f in findings:
                writer.writerow(f)

        return output.getvalue()
