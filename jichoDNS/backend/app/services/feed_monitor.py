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
        now_iso = now.isoformat()
        duration = round(duration_seconds, 2)

        try:
            if success:
                # Partial merge: set last_success=now, reset the failure counter,
                # clear the error. `last_error` is intentionally NOT set, so the
                # previous failure timestamp is preserved for history.
                await self.client.update(
                    index=FEED_HEALTH_INDEX,
                    id=feed_name,
                    doc={
                        "feed_name": feed_name,
                        "timestamp": now_iso,
                        "success": True,
                        "ioc_count": ioc_count,
                        "duration_seconds": duration,
                        "error_message": None,
                        "status": "healthy",
                        "last_success": now_iso,
                        "consecutive_failures": 0,
                    },
                    doc_as_upsert=True,
                    retry_on_conflict=3,
                )
            else:
                # Scripted update: increment consecutive_failures and set
                # last_error, but DO NOT touch last_success (preserve the real
                # last-good timestamp so staleness is computed correctly).
                await self.client.update(
                    index=FEED_HEALTH_INDEX,
                    id=feed_name,
                    script={
                        "lang": "painless",
                        "source": (
                            "ctx._source.feed_name = params.feed_name;"
                            "ctx._source.timestamp = params.timestamp;"
                            "ctx._source.success = false;"
                            "ctx._source.ioc_count = params.ioc_count;"
                            "ctx._source.duration_seconds = params.duration_seconds;"
                            "ctx._source.error_message = params.error_message;"
                            "ctx._source.status = 'error';"
                            "ctx._source.last_error = params.timestamp;"
                            "if (ctx._source.consecutive_failures == null) {"
                            " ctx._source.consecutive_failures = 1; } else {"
                            " ctx._source.consecutive_failures ="
                            " ctx._source.consecutive_failures + 1; }"
                        ),
                        "params": {
                            "feed_name": feed_name,
                            "timestamp": now_iso,
                            "ioc_count": ioc_count,
                            "duration_seconds": duration,
                            "error_message": error_message,
                        },
                    },
                    upsert={
                        "feed_name": feed_name,
                        "timestamp": now_iso,
                        "success": False,
                        "ioc_count": ioc_count,
                        "duration_seconds": duration,
                        "error_message": error_message,
                        "status": "error",
                        "last_success": None,
                        "last_error": now_iso,
                        "consecutive_failures": 1,
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
                query={"match_all": {}},
                size=50,
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
                    "consecutive_failures": src.get("consecutive_failures", 0),
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
                    mappings={
                        "properties": {
                            "feed_name":             {"type": "keyword"},
                            "timestamp":             {"type": "date"},
                            "last_success":          {"type": "date"},
                            "last_error":            {"type": "date"},
                            "success":               {"type": "boolean"},
                            "ioc_count":             {"type": "long"},
                            "duration_seconds":      {"type": "float"},
                            "status":                {"type": "keyword"},
                            "error_message":         {"type": "text"},
                            "consecutive_failures":  {"type": "integer"},
                        }
                    },
                )
                logger.info("Created feed_health index")
        except Exception as e:
            logger.warning(f"Could not ensure feed_health index: {e}")


# Singleton
feed_monitor = FeedHealthMonitor()
