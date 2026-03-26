"""
OSINT Collector — drives SpiderFoot scans, ingests results into ES + MISP.

Communicates with SpiderFoot HTTP API at http://intel-spiderfoot:5001
to create scans, poll results, and normalize findings into osint_results
Elasticsearch index.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

OSINT_INDEX = "osint_results"
SPIDERFOOT_URL = "http://intel-spiderfoot:5001"


class SpiderFootClient:
    """Async HTTP client for SpiderFoot REST API."""

    def __init__(self, base_url: str = SPIDERFOOT_URL):
        self.base_url = base_url.rstrip("/")
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=httpx.Timeout(60.0, connect=10.0),
            )
        return self._client

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def is_available(self) -> bool:
        """Check if SpiderFoot is reachable."""
        try:
            client = await self._get_client()
            r = await client.get("/")
            return r.status_code == 200
        except Exception:
            return False

    async def start_scan(
        self,
        target: str,
        scan_name: str = "",
        modules: Optional[List[str]] = None,
    ) -> Optional[str]:
        """
        Start a SpiderFoot scan.

        Returns scan_id or None on failure.
        """
        try:
            client = await self._get_client()
            if not scan_name:
                scan_name = f"jichodns-{target}-{datetime.now().strftime('%Y%m%d%H%M')}"

            data = {
                "scanname": scan_name,
                "scantarget": target,
                "usecase": "all",  # or "passive", "investigate"
            }
            if modules:
                data["modules"] = ",".join(modules)

            r = await client.post("/startscan", data=data)
            if r.status_code == 200:
                # SpiderFoot returns redirect to scan page
                # Extract scan ID from response
                scan_id = r.headers.get("location", "").split("/")[-1]
                if not scan_id:
                    # Try parsing from response body
                    text = r.text
                    if "scaninfo?id=" in text:
                        scan_id = text.split("scaninfo?id=")[1].split('"')[0]
                logger.info(f"SpiderFoot scan started: {scan_id} for {target}")
                return scan_id
            logger.error(f"SpiderFoot start_scan failed: {r.status_code}")
            return None
        except Exception as e:
            logger.error(f"SpiderFoot start_scan error: {e}")
            return None

    async def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Get scan status."""
        try:
            client = await self._get_client()
            r = await client.get(f"/scanstatus?id={scan_id}")
            if r.status_code == 200:
                return r.json()
            return {"status": "unknown", "error": r.status_code}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    async def get_scan_results(
        self,
        scan_id: str,
        event_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get scan results as list of events.

        event_types of interest:
        - EMAILADDR, EMAILADDR_COMPROMISED
        - DARKNET_MENTION_URL, DARKNET_MENTION_CONTENT
        - CREDENTIAL_BREACHED
        - DOMAIN_NAME, IP_ADDRESS
        - VULNERABILITY
        - SOCIAL_MEDIA
        """
        try:
            client = await self._get_client()
            url = f"/scaneventresults?id={scan_id}"
            if event_type:
                url += f"&eventType={event_type}"
            r = await client.get(url)
            if r.status_code == 200:
                return r.json()
            return []
        except Exception as e:
            logger.error(f"SpiderFoot results error: {e}")
            return []

    async def list_scans(self) -> List[Dict[str, Any]]:
        """List all scans."""
        try:
            client = await self._get_client()
            r = await client.get("/scanlist")
            if r.status_code == 200:
                return r.json()
            return []
        except Exception as e:
            logger.error(f"SpiderFoot list_scans error: {e}")
            return []


async def ensure_osint_index(es_client):
    """Create the osint_results index if it doesn't exist."""
    if not es_client:
        return
    exists = await es_client.indices.exists(index=OSINT_INDEX)
    if not exists:
        await es_client.indices.create(
            index=OSINT_INDEX,
            body={
                "mappings": {
                    "properties": {
                        "scan_id": {"type": "keyword"},
                        "scan_target": {"type": "keyword"},
                        "event_type": {"type": "keyword"},
                        "module": {"type": "keyword"},
                        "data": {"type": "text"},
                        "source_event": {"type": "keyword"},
                        "discovered_at": {"type": "date"},
                        "severity": {"type": "keyword"},
                        "watchlist_id": {"type": "integer"},
                        "tags": {"type": "keyword"},
                        "misp_event_id": {"type": "keyword"},
                    }
                },
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 0,
                },
            },
        )
        logger.info(f"Created index: {OSINT_INDEX}")


def classify_severity(event_type: str) -> str:
    """Map SpiderFoot event types to severity levels."""
    critical_types = {
        "CREDENTIAL_BREACHED", "EMAILADDR_COMPROMISED",
        "DARKNET_MENTION_URL", "DARKNET_MENTION_CONTENT",
        "VULNERABILITY_CVE_CRITICAL",
    }
    high_types = {
        "VULNERABILITY", "VULNERABILITY_CVE_HIGH",
        "MALICIOUS_IPADDR", "MALICIOUS_DOMAIN",
        "BLACKLISTED_IPADDR",
    }
    medium_types = {
        "EMAILADDR", "SOCIAL_MEDIA", "DOMAIN_NAME",
        "IP_ADDRESS", "WEBSERVER_TECHNOLOGY",
    }

    if event_type in critical_types:
        return "critical"
    if event_type in high_types:
        return "high"
    if event_type in medium_types:
        return "medium"
    return "low"


async def ingest_scan_results(
    es_client,
    sf_client: SpiderFootClient,
    scan_id: str,
    scan_target: str,
    watchlist_id: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Fetch SpiderFoot scan results and store in Elasticsearch.
    """
    await ensure_osint_index(es_client)

    results = await sf_client.get_scan_results(scan_id)
    now = datetime.now(timezone.utc).isoformat()

    stored = 0
    critical_count = 0
    high_count = 0

    for event in results:
        event_type = event.get("type", "UNKNOWN")
        severity = classify_severity(event_type)

        doc = {
            "scan_id": scan_id,
            "scan_target": scan_target,
            "event_type": event_type,
            "module": event.get("module", ""),
            "data": event.get("data", ""),
            "source_event": event.get("source", ""),
            "discovered_at": now,
            "severity": severity,
            "watchlist_id": watchlist_id,
            "tags": [event_type.lower().replace("_", "-")],
        }

        import hashlib
        _data_hash = hashlib.md5(event.get("data", "").encode()).hexdigest()
        doc_id = f"sf:{scan_id}:{_data_hash}"
        try:
            await es_client.index(index=OSINT_INDEX, id=doc_id, document=doc)
            stored += 1
            if severity == "critical":
                critical_count += 1
            elif severity == "high":
                high_count += 1
        except Exception as e:
            logger.error(f"ES index error for SF result: {e}")

    return {
        "scan_id": scan_id,
        "target": scan_target,
        "total_results": len(results),
        "stored": stored,
        "critical": critical_count,
        "high": high_count,
    }


# Singleton
sf_client = SpiderFootClient()
