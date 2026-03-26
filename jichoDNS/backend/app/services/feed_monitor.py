"""
Feed health monitor.

Tracks the freshness, IOC count, and error status of every threat feed.
Results are stored in the `feed_health` Elasticsearch index and exposed
via /api/v1/indicators/feed-health.
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

# SLA thresholds per feed (minutes before considered stale)
FEED_SLAS: Dict[str, int] = {
    # High-frequency feeds
    "urlhaus":          30,
    "sslbl":            30,
    "sslbl_ja3":        60,
    "threatfox":        30,
    "feodotracker":     60,
    # Medium-frequency feeds
    "malwarebazaar":    30,
    "openphish":        60,
    "crtsh":            60,
    # Lower-frequency feeds
    "phishtank":        240,
    "alienvault":       120,
    "alienvault_otx":   120,
    "abuseipdb":        120,
    # Slow feeds
    "dnstwist":         720,   # 12h
    # MISP
    "misp":             60,
    # Dark web & intel
    "darkweb_crawl":    300,   # 5h (runs every 2h)
    "torbot":           600,   # 10h (runs every 4h)
    "credentials":      600,   # 10h (runs every 4h)
    "osint":            720,   # 12h (runs every 6h)
}

FEED_HEALTH_INDEX = "feed_health"


class FeedHealthMonitor:
    """Track and report on feed freshness and quality."""

    def __init__(self, es_client=None):
        self.client = es_client

    async def record_run(
        self,
        feed_name: str,
        success: bool,
        ioc_count: int,
        duration_seconds: float,
        error_message: Optional[str] = None,
    ) -> None:
        """Record the result of a feed import run."""
        if not self.client:
            return

        now = datetime.now(timezone.utc)
        doc = {
            "feed_name": feed_name,
            "timestamp": now.isoformat(),
            "success": success,
            "ioc_count": ioc_count,
            "duration_seconds": round(duration_seconds, 2),
            "error_message": error_message,
            "status": "healthy" if success else "error",
        }

        try:
            await self.client.update(
                index=FEED_HEALTH_INDEX,
                id=feed_name,
                body={
                    "doc": {
                        **doc,
                        "last_success": now.isoformat() if success else None,
                        "last_error": None if success else now.isoformat(),
                        "consecutive_failures": 0 if success else None,
                    },
                    "doc_as_upsert": True,
                },
                retry_on_conflict=3,
            )
        except Exception as e:
            logger.warning(f"Could not record feed health for {feed_name}: {e}")

    async def get_all_health(self) -> List[Dict[str, Any]]:
        """Return health status for all feeds."""
        if not self.client:
            return []

        try:
            resp = await self.client.search(
                index=FEED_HEALTH_INDEX,
                body={"query": {"match_all": {}}, "size": 50},
            )
            results = []
            now = datetime.now(timezone.utc)

            for hit in resp["hits"]["hits"]:
                src = hit["_source"]
                feed = src.get("feed_name", hit["_id"])
                sla_minutes = FEED_SLAS.get(feed, 120)

                last_success_str = src.get("last_success") or src.get("timestamp")
                last_success = None
                if last_success_str:
                    try:
                        last_success = datetime.fromisoformat(
                            last_success_str.replace("Z", "+00:00")
                        )
                    except ValueError:
                        pass

                age_minutes = None
                stale = False
                if last_success:
                    age_minutes = int((now - last_success).total_seconds() / 60)
                    stale = age_minutes > sla_minutes

                results.append({
                    "feed": feed,
                    "status": "stale" if stale else src.get("status", "unknown"),
                    "last_success": last_success_str,
                    "age_minutes": age_minutes,
                    "sla_minutes": sla_minutes,
                    "ioc_count": src.get("ioc_count", 0),
                    "duration_seconds": src.get("duration_seconds"),
                    "error_message": src.get("error_message"),
                })

            return sorted(results, key=lambda x: x["feed"])

        except Exception as e:
            logger.error(f"Could not fetch feed health: {e}")
            return []

    async def get_stale_feeds(self) -> List[str]:
        """Return list of feed names that are past their SLA."""
        health = await self.get_all_health()
        return [h["feed"] for h in health if h["status"] == "stale"]

    async def ensure_index(self) -> None:
        """Create feed_health index if it doesn't exist."""
        if not self.client:
            return
        try:
            exists = await self.client.indices.exists(index=FEED_HEALTH_INDEX)
            if not exists:
                await self.client.indices.create(
                    index=FEED_HEALTH_INDEX,
                    body={
                        "mappings": {
                            "properties": {
                                "feed_name":         {"type": "keyword"},
                                "timestamp":         {"type": "date"},
                                "last_success":      {"type": "date"},
                                "last_error":        {"type": "date"},
                                "success":           {"type": "boolean"},
                                "ioc_count":         {"type": "long"},
                                "duration_seconds":  {"type": "float"},
                                "status":            {"type": "keyword"},
                                "error_message":     {"type": "text"},
                            }
                        }
                    },
                )
                logger.info("Created feed_health index")
        except Exception as e:
            logger.warning(f"Could not ensure feed_health index: {e}")


# Singleton
feed_monitor = FeedHealthMonitor()
