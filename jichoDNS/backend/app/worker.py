"""
Celery worker configuration and tasks.

Run with: celery -A app.worker worker --loglevel=info
Beat with: celery -A app.worker beat --loglevel=info
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from celery import Celery
from celery.schedules import crontab
import redis

from app.core.config import settings

logger = logging.getLogger(__name__)

# Create Celery app
celery_app = Celery(
    "jichodns",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
)

# Celery configuration
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 hour max
    worker_prefetch_multiplier=1,
    worker_concurrency=4,
)

# Redis channel for WebSocket broadcasts
IOC_CHANNEL = "jichodns:iocs:new"


def publish_new_iocs(indicators: list, source: str):
    """
    Publish new IOCs to Redis for WebSocket broadcast.
    
    Args:
        indicators: List of indicator dicts (already geo-enriched)
        source: Source feed name (urlhaus, threatfox, etc.)
    """
    if not indicators:
        return
    
    try:
        # Use sync Redis client for Celery tasks
        r = redis.from_url(settings.REDIS_URL)
        
        # Only send indicators with geo data for the map
        geo_indicators = [
            ind for ind in indicators 
            if ind.get("country_code")
        ]
        
        if geo_indicators:
            message = json.dumps({
                "source": source,
                "count": len(geo_indicators),
                "indicators": geo_indicators[:100],  # Limit to 100 per batch for WS
            })
            r.publish(IOC_CHANNEL, message)
            print(f"Published {len(geo_indicators)} IOCs from {source} to WebSocket channel")
        
        r.close()
    except Exception as e:
        print(f"Failed to publish IOCs to Redis: {e}")


# Beat schedule for periodic tasks
celery_app.conf.beat_schedule = {
    # === HIGH FREQUENCY (every 5 minutes) ===
    "import-urlhaus": {
        "task": "app.worker.import_urlhaus",
        "schedule": timedelta(minutes=5),
    },
    "import-threatfox": {
        "task": "app.worker.import_threatfox",
        "schedule": timedelta(minutes=5),
    },
    "import-feodotracker": {
        "task": "app.worker.import_feodotracker",
        "schedule": timedelta(minutes=5),
    },
    
    # === MEDIUM FREQUENCY (every 15-30 minutes) ===
    "import-sslbl": {
        "task": "app.worker.import_sslbl",
        "schedule": timedelta(minutes=15),
    },
    "import-sslbl-ja3": {
        "task": "app.worker.import_sslbl_ja3",
        "schedule": timedelta(minutes=30),
    },
    "import-openphish": {
        "task": "app.worker.import_openphish",
        "schedule": timedelta(minutes=30),
    },
    "import-crtsh": {
        "task": "app.worker.import_crtsh",
        "schedule": timedelta(minutes=30),
    },
    
    # === LOWER FREQUENCY (hourly) ===
    "import-phishtank": {
        "task": "app.worker.import_phishtank",
        "schedule": timedelta(hours=1),
    },
    "import-abuseipdb": {
        "task": "app.worker.import_abuseipdb",
        "schedule": timedelta(hours=1),
    },
    "import-alienvault-otx": {
        "task": "app.worker.import_alienvault_otx",
        "schedule": timedelta(hours=1),
    },
    
    # === SLOW (every 6 hours) ===
    "import-dnstwist": {
        "task": "app.worker.import_dnstwist",
        "schedule": timedelta(hours=6),
    },
    
    "import-malwarebazaar": {
        "task": "app.worker.import_malwarebazaar",
        "schedule": timedelta(minutes=15),
    },
    # === MISP (every 30 minutes — slow instance, needs long timeout) ===
    "import-misp": {
        "task": "app.worker.import_misp",
        "schedule": timedelta(minutes=30),
    },

    # === DARK WEB CRAWL (every 2 hours) ===
    "crawl-darkweb": {
        "task": "app.worker.crawl_darkweb",
        "schedule": timedelta(hours=2),
    },

    # === CREDENTIAL INGESTION (every 4 hours) ===
    "ingest-credentials": {
        "task": "app.worker.ingest_credentials",
        "schedule": timedelta(hours=4),
    },

    # === MAINTENANCE ===
    "aggregate-regions": {
        "task": "app.worker.aggregate_region_scores",
        "schedule": timedelta(minutes=15),
    },
    "cleanup-old-data": {
        "task": "app.worker.cleanup_old_data",
        "schedule": crontab(hour=2, minute=0),  # 2 AM daily
    },
    "expire-stale-iocs": {
        "task": "app.worker.expire_stale_iocs",
        "schedule": crontab(hour=3, minute=0),  # 3 AM daily
    },
    "check-feed-health": {
        "task": "app.worker.check_feed_health",
        "schedule": timedelta(minutes=30),
    },
}

# Alias for Celery to find the app
app = celery_app


def run_async(coro):
    """Helper to run async functions in sync context."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


async def _generic_import(importer_class, source_name: str):
    """Generic import function for all feed importers."""
    import time
    from app.services.elasticsearch import es_service
    from app.services.feed_monitor import feed_monitor

    start = time.monotonic()
    importer = importer_class()
    result, indicators = await importer.import_feed()
    duration = time.monotonic() - start

    await es_service.connect()

    # Record feed health
    feed_monitor.client = es_service.client
    await feed_monitor.ensure_index()
    await feed_monitor.record_run(
        feed_name=source_name,
        success=result.success,
        ioc_count=len(indicators),
        duration_seconds=duration,
        error_message=result.error_message if not result.success else None,
    )

    if result.success and len(indicators) > 0:
        store_result, stored_docs = await es_service.store_indicators(indicators, return_docs=True)
        await es_service.close()

        # Publish new IOCs to WebSocket channel
        publish_new_iocs(stored_docs, source_name)

        return {
            **result.to_dict(),
            "stored": store_result,
        }

    await es_service.close()
    return result.to_dict()


# === ABUSE.CH FEEDS ===

@celery_app.task(name="app.worker.import_urlhaus")
def import_urlhaus():
    """Import indicators from URLhaus."""
    from app.importers import URLhausImporter
    return run_async(_generic_import(URLhausImporter, "urlhaus"))


@celery_app.task(name="app.worker.import_threatfox")
def import_threatfox():
    """Import indicators from ThreatFox."""
    from app.importers import ThreatFoxImporter
    return run_async(_generic_import(ThreatFoxImporter, "threatfox"))


@celery_app.task(name="app.worker.import_feodotracker")
def import_feodotracker():
    """Import indicators from Feodo Tracker."""
    from app.importers import FeodoTrackerImporter
    return run_async(_generic_import(FeodoTrackerImporter, "feodotracker"))


@celery_app.task(name="app.worker.import_sslbl")
def import_sslbl():
    """Import indicators from SSL Blacklist."""
    from app.importers import SSLBlacklistImporter
    return run_async(_generic_import(SSLBlacklistImporter, "sslbl"))


@celery_app.task(name="app.worker.import_malwarebazaar")
def import_malwarebazaar():
    """Import malware hashes from MalwareBazaar."""
    from app.importers.malwarebazaar import MalwareBazaarImporter
    return run_async(_generic_import(MalwareBazaarImporter, "malwarebazaar"))


@celery_app.task(name="app.worker.import_sslbl_ja3")
def import_sslbl_ja3():
    """Import JA3 fingerprints from SSL Blacklist."""
    from app.importers import JA3FingerprintImporter
    return run_async(_generic_import(JA3FingerprintImporter, "sslbl_ja3"))


# === PHISHING FEEDS ===

@celery_app.task(name="app.worker.import_phishtank")
def import_phishtank():
    """Import indicators from PhishTank."""
    from app.importers import PhishTankImporter
    return run_async(_generic_import(PhishTankImporter, "phishtank"))


@celery_app.task(name="app.worker.import_openphish")
def import_openphish():
    """Import indicators from OpenPhish."""
    from app.importers.openphish import OpenPhishImporter
    return run_async(_generic_import(OpenPhishImporter, "openphish"))


# === COMMUNITY INTELLIGENCE ===

@celery_app.task(name="app.worker.import_alienvault_otx")
def import_alienvault_otx():
    """Import indicators from AlienVault OTX."""
    from app.importers import AlienVaultOTXImporter
    return run_async(_generic_import(AlienVaultOTXImporter, "alienvault_otx"))


@celery_app.task(name="app.worker.import_abuseipdb")
def import_abuseipdb():
    """Import indicators from AbuseIPDB."""
    from app.importers import AbuseIPDBImporter
    return run_async(_generic_import(AbuseIPDBImporter, "abuseipdb"))


# === CERTIFICATE & TYPOSQUATTING ===

@celery_app.task(name="app.worker.import_crtsh")
def import_crtsh():
    """Import suspicious certificates from crt.sh."""
    from app.importers import CertificateTransparencyImporter
    return run_async(_generic_import(CertificateTransparencyImporter, "crtsh"))


@celery_app.task(name="app.worker.import_dnstwist")
def import_dnstwist():
    """Detect typosquatting domains with DNSTwist."""
    from app.importers import DNSTwistImporter
    return run_async(_generic_import(DNSTwistImporter, "dnstwist"))


# === MISP ===

@celery_app.task(name="app.worker.import_misp", soft_time_limit=300, time_limit=360)
def import_misp():
    """Pull recent IOCs from external MISP instance into Elasticsearch."""
    return run_async(_import_misp())


async def _import_misp():
    """Async MISP import — handles slow responses gracefully."""
    import time
    from app.services.misp import misp_client
    from app.services.elasticsearch import es_service
    from app.services.geoip import geoip_service

    if not misp_client.enabled:
        return {"source": "misp", "success": False, "error": "MISP not configured"}

    start = time.monotonic()
    logger.info("Starting MISP import...")

    try:
        # Pull recent attributes (IOCs) from MISP
        # Use ip-dst, ip-src, domain, url types for map integration
        attrs = await misp_client.pull_recent_attributes(
            since_days=90,
            limit=settings.MISP_PULL_LIMIT,
            ioc_types=["ip-dst", "ip-src", "domain", "hostname", "url"],
        )

        if not attrs:
            logger.info("MISP: No new attributes found")
            return {
                "source": "misp",
                "success": True,
                "total_fetched": 0,
                "total_imported": 0,
                "duration_seconds": time.monotonic() - start,
            }

        # Convert MISP attributes to our indicator schema
        indicators = []
        for attr in attrs:
            ind = misp_client.attribute_to_indicator(attr)

            # GeoIP enrich IP addresses
            ip = ind.get("ip_address")
            if ip and geoip_service.is_available:
                geo = geoip_service.lookup(ip)
                if geo:
                    ind["country_code"] = geo.get("country_code")
                    ind["latitude"] = geo.get("latitude")
                    ind["longitude"] = geo.get("longitude")
                    ind["asn"] = geo.get("asn")
                    ind["asn_org"] = geo.get("asn_org")

            indicators.append(ind)

        # Store directly in Elasticsearch (indicators are already dicts, not model objects)
        await es_service.connect()
        from datetime import timezone
        from elasticsearch.helpers import async_bulk

        now_iso = datetime.now(timezone.utc).isoformat()
        actions = []
        stored_docs = []
        for ind in indicators:
            ind.setdefault("created_at", now_iso)
            ind.setdefault("updated_at", now_iso)
            ind.setdefault("active", True)
            ind.setdefault("risk_score", 70)

            doc_id = f"{ind.get('indicator_type', 'other')}:{ind['indicator']}"
            actions.append({
                "_op_type": "update",
                "_index": es_service.ioc_index,
                "_id": doc_id,
                "doc": ind,
                "doc_as_upsert": True,
                "retry_on_conflict": 3,
            })
            stored_docs.append(ind)

        success_count = 0
        error_count = 0
        if actions and es_service.client:
            try:
                success_count, errors = await async_bulk(
                    es_service.client, actions, raise_on_error=False
                )
                error_count = len(errors) if isinstance(errors, list) else 0
            except Exception as bulk_err:
                logger.error(f"MISP ES bulk error: {bulk_err}")
                error_count = len(actions)

        store_result = {"success": success_count, "errors": error_count}
        await es_service.close()

        # Publish to WebSocket for live map
        if stored_docs:
            publish_new_iocs(stored_docs, "misp")

        duration = time.monotonic() - start
        logger.info(
            f"MISP import complete: {len(indicators)} fetched, "
            f"{store_result.get('success', 0)} stored in {duration:.1f}s"
        )

        return {
            "source": "misp",
            "success": True,
            "total_fetched": len(attrs),
            "total_imported": len(indicators),
            "total_stored": store_result.get("success", 0),
            "duration_seconds": duration,
        }

    except Exception as e:
        logger.error(f"MISP import error: {e}", exc_info=True)
        return {
            "source": "misp",
            "success": False,
            "error": str(e),
            "duration_seconds": time.monotonic() - start,
        }
    finally:
        await misp_client.close()


# === CREDENTIAL INGESTION ===

@celery_app.task(name="app.worker.ingest_credentials", soft_time_limit=120, time_limit=180)
def ingest_credentials():
    """Ingest credential exposure data from breaches and dark web crawls."""
    return run_async(_ingest_credentials())


async def _ingest_credentials():
    import time
    from app.services.elasticsearch import es_service
    from app.intel.cred_ingestor import run_credential_ingestion

    start = time.monotonic()
    logger.info("Starting credential ingestion...")
    try:
        await es_service.connect()
        result = await run_credential_ingestion(es_service.client)
        await es_service.close()
        duration = time.monotonic() - start
        logger.info(f"Credential ingestion complete: {result} in {duration:.1f}s")
        return {**result, "duration_seconds": duration}
    except Exception as e:
        logger.error(f"Credential ingestion error: {e}", exc_info=True)
        return {"error": str(e)}


# === DARK WEB CRAWL ===

@celery_app.task(name="app.worker.crawl_darkweb", soft_time_limit=300, time_limit=360)
def crawl_darkweb(queries=None):
    """Crawl dark web sources and store in ES."""
    return run_async(_crawl_darkweb(queries))


async def _crawl_darkweb(queries=None):
    """Async dark web crawl."""
    import time
    from app.services.elasticsearch import es_service
    from app.intel.tor_crawler import run_dark_web_crawl

    start = time.monotonic()
    logger.info("Starting dark web crawl...")

    try:
        await es_service.connect()
        result = await run_dark_web_crawl(
            es_client=es_service.client,
            queries=queries,
        )
        await es_service.close()

        duration = time.monotonic() - start
        logger.info(f"Dark web crawl complete: {result} in {duration:.1f}s")
        return {**result, "duration_seconds": duration}

    except Exception as e:
        logger.error(f"Dark web crawl error: {e}", exc_info=True)
        return {"error": str(e), "duration_seconds": time.monotonic() - start}


# === BATCH IMPORTS ===

@celery_app.task(name="app.worker.import_all_feeds")
def import_all_feeds():
    """Import from all configured feeds."""
    results = {}
    
    # High priority feeds
    results["urlhaus"] = import_urlhaus()
    results["threatfox"] = import_threatfox()
    results["feodotracker"] = import_feodotracker()
    results["sslbl"] = import_sslbl()
    
    # Medium priority
    results["openphish"] = import_openphish()
    results["phishtank"] = import_phishtank()
    
    # API-based (may require keys)
    try:
        results["abuseipdb"] = import_abuseipdb()
    except Exception as e:
        results["abuseipdb"] = {"error": str(e)}
    
    try:
        results["alienvault_otx"] = import_alienvault_otx()
    except Exception as e:
        results["alienvault_otx"] = {"error": str(e)}
    
    # Certificate monitoring
    results["crtsh"] = import_crtsh()
    
    return results


# === MAINTENANCE TASKS ===

@celery_app.task(name="app.worker.aggregate_region_scores")
def aggregate_region_scores():
    """Aggregate threat scores by region (country/ASN)."""
    from app.services.elasticsearch import es_service
    
    async def _aggregate():
        await es_service.connect()
        stats = await es_service.get_stats()
        await es_service.close()
        
        return {
            "status": "completed",
            "stats": stats,
        }
    
    return run_async(_aggregate())


@celery_app.task(name="app.worker.cleanup_old_data")
def cleanup_old_data():
    """Clean up old/stale indicators."""
    # TODO: Implement cleanup logic
    # - Mark indicators not seen in 30+ days as inactive
    # - Delete indicators not seen in 90+ days
    return {"status": "completed", "cleaned": 0}


@celery_app.task(name="app.worker.analyze_domain_task")
def analyze_domain_task(domain: str):
    """Analyze a single domain for threats."""
    from app.services.dns_analysis import analyze_domain
    
    result = analyze_domain(domain)
    return result


@celery_app.task(name="app.worker.enrich_indicator")
def enrich_indicator(indicator: str, indicator_type: str):
    """Enrich an indicator with additional data."""
    # TODO: Implement enrichment from Shodan, VT, WHOIS, etc.
    return {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "enrichment": {},
    }


@celery_app.task(name="app.worker.enrich_geoip_batch")
def enrich_geoip_batch(batch_size: int = 1000, max_batches: int = 100):
    """
    Enrich IOCs without country_code with GeoIP data.
    
    Uses local MaxMind GeoLite2 database - no rate limits!
    Can process thousands of IPs per second.
    """
    from app.services.elasticsearch import es_service
    from app.services.geoip import geoip_service
    
    if not geoip_service.is_available:
        return {
            "status": "error",
            "error": "GeoIP database not available",
        }
    
    async def _enrich():
        await es_service.connect()
        
        total_enriched = 0
        total_processed = 0
        total_no_ip = 0
        
        for batch_num in range(max_batches):
            # Get indicators without country_code
            body = {
                "query": {
                    "bool": {
                        "must_not": [
                            {"exists": {"field": "country_code"}}
                        ],
                        "filter": [
                            {"term": {"active": True}}
                        ]
                    }
                },
                "size": batch_size,
                "_source": ["indicator", "indicator_type", "source"]
            }
            
            try:
                response = await es_service.client.search(
                    index=es_service.ioc_index,
                    body=body
                )
                
                hits = response["hits"]["hits"]
                if not hits:
                    break
                
                print(f"Batch {batch_num + 1}: Processing {len(hits)} indicators...")
                
                # Enrich each indicator using sync method (fast local DB)
                updates = []
                for hit in hits:
                    doc = hit["_source"]
                    doc_id = hit["_id"]
                    
                    # Use sync method - local DB is fast
                    geo_data = geoip_service.enrich_indicator_sync(
                        doc["indicator"],
                        doc["indicator_type"]
                    )
                    
                    if geo_data and geo_data.get("country_code"):
                        updates.append({
                            "_op_type": "update",
                            "_index": es_service.ioc_index,
                            "_id": doc_id,
                            "doc": geo_data,
                        })
                        total_enriched += 1
                    elif geo_data.get("ip_address"):
                        # Has IP but no geo data (not in DB)
                        total_processed += 1
                    else:
                        # No IP found in indicator
                        total_no_ip += 1
                    
                    total_processed += 1
                
                # Bulk update
                if updates:
                    from elasticsearch.helpers import async_bulk
                    success, failed = await async_bulk(
                        es_service.client, 
                        updates, 
                        raise_on_error=False,
                        stats_only=True
                    )
                    print(f"Batch {batch_num + 1}: Updated {success} indicators")
                
            except Exception as e:
                print(f"Batch {batch_num + 1} error: {e}")
                import traceback
                traceback.print_exc()
                break
        
        await es_service.close()
        
        return {
            "status": "completed",
            "total_processed": total_processed,
            "total_enriched": total_enriched,
            "total_no_ip": total_no_ip,
        }
    
    return run_async(_enrich())


@celery_app.task(name="app.worker.get_source_stats")
def get_source_stats():
    """Get IOC counts by source for monitoring."""
    from app.services.elasticsearch import es_service
    
    async def _get_stats():
        await es_service.connect()
        
        body = {
            "size": 0,
            "aggs": {
                "by_source": {
                    "terms": {
                        "field": "source",
                        "size": 50
                    },
                    "aggs": {
                        "by_threat_type": {
                            "terms": {
                                "field": "threat_type",
                                "size": 10
                            }
                        },
                        "with_geo": {
                            "filter": {
                                "exists": {"field": "country_code"}
                            }
                        }
                    }
                },
                "total_with_geo": {
                    "filter": {
                        "exists": {"field": "country_code"}
                    }
                }
            }
        }
        
        response = await es_service.client.search(
            index=es_service.ioc_index,
            body=body
        )
        
        await es_service.close()
        
        # Format results
        sources = {}
        for bucket in response["aggregations"]["by_source"]["buckets"]:
            source_name = bucket["key"]
            sources[source_name] = {
                "total": bucket["doc_count"],
                "with_geo": bucket["with_geo"]["doc_count"],
                "threat_types": {
                    t["key"]: t["doc_count"] 
                    for t in bucket["by_threat_type"]["buckets"]
                }
            }
        
        return {
            "sources": sources,
            "total_iocs": sum(s["total"] for s in sources.values()),
            "total_with_geo": response["aggregations"]["total_with_geo"]["doc_count"],
        }
    
    return run_async(_get_stats())


@celery_app.task(name="app.worker.expire_stale_iocs")
def expire_stale_iocs():
    """
    Mark IOCs as inactive if they haven't been seen in their TTL window.
    Runs nightly at 3 AM.
    """
    from app.services.elasticsearch import es_service

    async def _expire():
        await es_service.connect()
        now_iso = datetime.utcnow().isoformat()

        # Mark expired: expires_at < now AND active = true
        body = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"active": True}},
                        {"range": {"expires_at": {"lt": now_iso}}},
                    ]
                }
            },
            "script": {
                "source": "ctx._source.active = false",
                "lang": "painless",
            },
        }

        try:
            resp = await es_service.client.update_by_query(
                index=es_service.ioc_index,
                body=body,
                conflicts="proceed",
                refresh=True,
            )
            expired = resp.get("updated", 0)
            print(f"Expired {expired} stale IOCs")
            await es_service.close()
            return {"expired": expired, "status": "ok"}
        except Exception as e:
            await es_service.close()
            return {"expired": 0, "status": "error", "error": str(e)}

    return run_async(_expire())


@celery_app.task(name="app.worker.check_feed_health")
def check_feed_health():
    """
    Check all feed health and log stale feeds.
    Runs every 30 minutes.
    """
    from app.services.elasticsearch import es_service
    from app.services.feed_monitor import feed_monitor

    async def _check():
        await es_service.connect()
        feed_monitor.client = es_service.client
        stale = await feed_monitor.get_stale_feeds()
        all_health = await feed_monitor.get_all_health()
        await es_service.close()

        if stale:
            print(f"ALERT: Stale feeds detected: {stale}")
        else:
            print(f"All {len(all_health)} feeds healthy")

        return {
            "stale_feeds": stale,
            "total_feeds": len(all_health),
            "healthy": len(all_health) - len(stale),
        }

    return run_async(_check())
