"""
MISP integration service.

Async HTTP client for querying an external MISP instance.
Handles the slow response times typical of large MISP deployments
by using generous timeouts and background-only heavy queries.
"""

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)


class MISPClient:
    """Async MISP REST API client."""

    def __init__(self):
        self.base_url = settings.MISP_URL.rstrip("/")
        self.api_key = settings.MISP_API_KEY
        self.verify_ssl = settings.MISP_VERIFY_SSL
        self.timeout = settings.MISP_TIMEOUT
        self._client: Optional[httpx.AsyncClient] = None

    @property
    def enabled(self) -> bool:
        return bool(settings.MISP_ENABLED and self.api_key and self.base_url)

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers={
                    "Authorization": self.api_key,
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                verify=self.verify_ssl,
                timeout=httpx.Timeout(self.timeout, connect=30.0),
            )
        return self._client

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    # ── Read operations ───────────────────────────────────────────────────

    async def get_version(self) -> Dict[str, Any]:
        """Get MISP server version — fast health check."""
        try:
            client = await self._get_client()
            r = await client.get("/servers/getVersion.json")
            r.raise_for_status()
            return r.json()
        except Exception as e:
            logger.error(f"MISP get_version error: {e}")
            return {"error": str(e)}

    async def search_attributes(
        self,
        value: Optional[str] = None,
        type_attribute: Optional[str] = None,
        category: Optional[str] = None,
        last: str = "30d",
        limit: int = 100,
        page: int = 1,
    ) -> List[Dict[str, Any]]:
        """Search MISP attributes (IOCs)."""
        try:
            client = await self._get_client()
            body: Dict[str, Any] = {
                "returnFormat": "json",
                "limit": limit,
                "page": page,
                "last": last,
            }
            if value:
                body["value"] = value
            if type_attribute:
                body["type"] = type_attribute
            if category:
                body["category"] = category

            r = await client.post("/attributes/restSearch", json=body)
            r.raise_for_status()
            data = r.json()
            resp = data.get("response", data)
            return resp.get("Attribute", []) if isinstance(resp, dict) else []
        except Exception as e:
            logger.error(f"MISP search_attributes error: {e}")
            return []

    async def search_events(
        self,
        last: str = "30d",
        limit: int = 50,
        page: int = 1,
        tags: Optional[List[str]] = None,
        published: bool = True,
    ) -> List[Dict[str, Any]]:
        """Search MISP events."""
        try:
            client = await self._get_client()
            body: Dict[str, Any] = {
                "returnFormat": "json",
                "limit": limit,
                "page": page,
                "last": last,
                "published": published,
            }
            if tags:
                body["tags"] = tags

            r = await client.post("/events/restSearch", json=body)
            r.raise_for_status()
            data = r.json()
            resp = data.get("response", data)
            if isinstance(resp, list):
                return [e.get("Event", e) for e in resp]
            return []
        except Exception as e:
            logger.error(f"MISP search_events error: {e}")
            return []

    async def get_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        """Get a single MISP event with all attributes."""
        try:
            client = await self._get_client()
            r = await client.get(f"/events/view/{event_id}.json")
            r.raise_for_status()
            data = r.json()
            return data.get("Event", data)
        except Exception as e:
            logger.error(f"MISP get_event({event_id}) error: {e}")
            return None

    async def pull_recent_attributes(
        self,
        since_days: int = 7,
        limit: int = 500,
        ioc_types: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Pull recent IOC attributes for ingestion into Elasticsearch.

        Focuses on network indicators that can be mapped to the threat map.
        """
        if ioc_types is None:
            ioc_types = [
                "ip-dst", "ip-src", "domain", "hostname",
                "url", "md5", "sha256", "sha1",
                "email-src", "email-dst",
            ]

        all_attrs = []
        for ioc_type in ioc_types:
            try:
                attrs = await self.search_attributes(
                    type_attribute=ioc_type,
                    last=f"{since_days}d",
                    limit=limit,
                )
                all_attrs.extend(attrs)
                if len(all_attrs) >= limit:
                    break
            except Exception as e:
                logger.warning(f"MISP pull type={ioc_type} error: {e}")
                continue

        return all_attrs[:limit]

    # ── Helpers ────────────────────────────────────────────────────────────

    @staticmethod
    def attribute_to_indicator(attr: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert a MISP attribute to our indicator schema for ES storage.
        """
        misp_type = attr.get("type", "")
        value = attr.get("value", "")
        category = attr.get("category", "")

        # Map MISP types to our indicator_type
        type_map = {
            "ip-dst": "ip",
            "ip-src": "ip",
            "domain": "domain",
            "hostname": "domain",
            "url": "url",
            "md5": "hash",
            "sha256": "hash",
            "sha1": "hash",
            "email-src": "email",
            "email-dst": "email",
        }

        # Map MISP categories to threat types
        threat_map = {
            "Network activity": "c2",
            "Payload delivery": "malware",
            "Payload installation": "malware",
            "Persistence mechanism": "malware",
            "External analysis": "suspicious",
            "Antivirus detection": "malware",
        }

        # Extract tags
        tags = []
        if attr.get("Tag"):
            tags = [t.get("name", "") for t in attr["Tag"] if t.get("name")]

        # Determine threat_type from category and tags
        threat_type = threat_map.get(category, "suspicious")
        for tag in tags:
            tag_lower = tag.lower()
            if "phishing" in tag_lower:
                threat_type = "phishing"
                break
            elif "c2" in tag_lower or "c&c" in tag_lower:
                threat_type = "c2"
                break
            elif "ransomware" in tag_lower or "malware" in tag_lower:
                threat_type = "malware"
                break
            elif "botnet" in tag_lower:
                threat_type = "botnet"
                break

        indicator = {
            "indicator": value,
            "indicator_type": type_map.get(misp_type, "other"),
            "threat_type": threat_type,
            "source": "misp",
            "confidence": int(attr.get("confidence", 70)),
            "risk_score": 70,  # Default, can be refined
            "first_seen": attr.get("first_seen") or attr.get("timestamp"),
            "last_seen": attr.get("last_seen") or attr.get("timestamp"),
            "tags": tags[:10],
            "active": not attr.get("deleted", False),
            "misp_event_id": str(attr.get("event_id", "")),
            "misp_attribute_id": str(attr.get("id", "")),
            "misp_category": category,
            "misp_type": misp_type,
            "misp_comment": attr.get("comment", ""),
        }

        # Set IP address for GeoIP enrichment
        if misp_type in ("ip-dst", "ip-src"):
            indicator["ip_address"] = value

        return indicator


# Singleton
misp_client = MISPClient()
