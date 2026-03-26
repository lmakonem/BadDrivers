"""
NVD (National Vulnerability Database) CVE API client.

Fetches real CVE data from NIST NVD API v2.
Free, no auth required (API key optional for higher rate limits).

Docs: https://nvd.nist.gov/developers/vulnerabilities
"""

import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional

import aiohttp

from app.core.config import settings

logger = logging.getLogger(__name__)

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# CVSS severity mapping
def cvss_to_severity(score: float) -> str:
    if score >= 9.0:  return "critical"
    if score >= 7.0:  return "high"
    if score >= 4.0:  return "medium"
    return "low"


class NVDClient:
    """Client for the NVD CVE API v2."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or getattr(settings, "NVD_API_KEY", None)
        # Rate limit: 5 req/30s without key, 50 req/30s with key
        self._delay = 0.7 if self.api_key else 6.5

    def _headers(self) -> Dict[str, str]:
        h = {"User-Agent": "JichoSec-ThreatIntel/1.0"}
        if self.api_key:
            h["apiKey"] = self.api_key
        return h

    async def get_cves_by_cpe(self, cpe: str, limit: int = 20) -> List[Dict[str, Any]]:
        """Fetch CVEs matching a CPE string (e.g. 'cpe:2.3:a:apache:tomcat:*')."""
        params = {"cpeName": cpe, "resultsPerPage": min(limit, 2000)}
        return await self._fetch(params)

    async def get_recent_cves(self, days: int = 7, limit: int = 100) -> List[Dict[str, Any]]:
        """Fetch CVEs published or modified in the last N days."""
        now = datetime.now(timezone.utc)
        start = now - timedelta(days=days)
        params = {
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": min(limit, 2000),
        }
        return await self._fetch(params)

    async def get_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single CVE by ID."""
        params = {"cveId": cve_id}
        results = await self._fetch(params)
        return results[0] if results else None

    async def search_cves(
        self,
        keyword: str,
        severity: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Search CVEs by keyword (e.g. 'apache', 'ssl', 'rce')."""
        params = {"keywordSearch": keyword, "resultsPerPage": min(limit, 2000)}
        if severity:
            params["cvssV3Severity"] = severity.upper()
        return await self._fetch(params)

    async def _fetch(self, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Execute NVD API request and parse response."""
        await asyncio.sleep(self._delay)  # respect rate limit

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    NVD_BASE,
                    params=params,
                    headers=self._headers(),
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status == 429:
                        logger.warning("NVD rate limited — backing off 30s")
                        await asyncio.sleep(30)
                        return []
                    resp.raise_for_status()
                    data = await resp.json()

            return [self._parse_cve(v) for v in data.get("vulnerabilities", [])]

        except aiohttp.ClientError as e:
            logger.error(f"NVD API request failed: {e}")
            return []
        except Exception as e:
            logger.error(f"NVD parse error: {e}")
            return []

    def _parse_cve(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """Normalise a NVD vulnerability entry."""
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")

        # Description (English preferred)
        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            descriptions[0]["value"] if descriptions else "",
        )

        # CVSS scores — try v3.1 then v3.0 then v2
        metrics = cve.get("metrics", {})
        cvss_score = 0.0
        cvss_vector = ""
        cvss_version = "unknown"

        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                data_item = entries[0].get("cvssData", {})
                cvss_score = data_item.get("baseScore", 0.0)
                cvss_vector = data_item.get("vectorString", "")
                cvss_version = data_item.get("version", key[-3:])
                break

        # References
        refs = [r.get("url") for r in cve.get("references", []) if r.get("url")][:5]

        # CPE affected
        cpes = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if match.get("vulnerable"):
                        cpes.append(match.get("criteria", ""))
        cpes = cpes[:10]

        # Dates
        published = cve.get("published", "")
        modified = cve.get("lastModified", "")

        return {
            "cve_id": cve_id,
            "description": description[:2000],
            "severity": cvss_to_severity(cvss_score),
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "cvss_version": cvss_version,
            "references": refs,
            "cpe_affected": cpes,
            "published": published,
            "last_modified": modified,
            "source": "nvd",
            "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        }


# Singleton
nvd_client = NVDClient()
