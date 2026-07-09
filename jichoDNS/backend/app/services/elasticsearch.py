"""Elasticsearch service for IOC storage and search."""

import asyncio
from datetime import datetime
from typing import List, Dict, Any, Optional, Union, Tuple
import logging
from elasticsearch import AsyncElasticsearch
from elasticsearch.helpers import async_bulk

from app.core.config import settings
from app.importers.base import Indicator
from app.services.geoip import geoip_service

logger = logging.getLogger(__name__)


class ElasticsearchService:
    """Service for interacting with Elasticsearch."""
    
    def __init__(self):
        self.client: Optional[AsyncElasticsearch] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self.ioc_index = "iocs"
        self.dns_index = "dns_queries"
        self._ioc_index_ready = False
    
    async def connect(self):
        """
        Initialize the Elasticsearch connection, bound to the running loop.

        AsyncElasticsearch (aiohttp transport) latches onto the event loop that
        is running when its first request is issued and cannot be reused from a
        different loop — doing so raises "RuntimeError: Task got Future attached
        to a different loop". The FastAPI process has one long-lived loop, so the
        client is built once and reused. Celery runs every task in a fresh loop
        via app.worker.run_async(); when the cached client belongs to a
        different (now-closed) loop we drop it and rebuild, which also self-heals
        any task that crashed before calling close().
        """
        current_loop = asyncio.get_running_loop()

        if self.client is not None and self._loop is not current_loop:
            # Cached client belongs to another event loop — abandon it without
            # awaiting close() (its loop is gone) and rebuild on this loop.
            self.client = None
            self._loop = None

        if self.client is None:
            es_url = settings.ELASTICSEARCH_URL
            if es_url:
                raw_client = AsyncElasticsearch(
                    [es_url],
                    verify_certs=False,
                    request_timeout=30,
                )
                # Wrap search to always include track_total_hits
                _orig_search = raw_client.search

                async def _search_with_total(*args, **kwargs):
                    body = kwargs.get("body")
                    if body and isinstance(body, dict) and "track_total_hits" not in body:
                        body["track_total_hits"] = True
                    return await _orig_search(*args, **kwargs)

                raw_client.search = _search_with_total
                self.client = raw_client
                self._loop = current_loop

                # Test connection
                try:
                    await self.client.info()
                    logger.info("Connected to Elasticsearch")
                    await self.ensure_ioc_index()
                except Exception as e:
                    logger.error(f"Failed to connect to Elasticsearch: {e}")
                    self.client = None
                    self._loop = None

    async def close(self):
        """Close Elasticsearch connection (never raises)."""
        if self.client:
            try:
                await self.client.close()
            except Exception as e:
                logger.debug(f"Error closing Elasticsearch client: {e}")
            finally:
                self.client = None
                self._loop = None

    # Explicit mapping for the iocs index. Uses the text+keyword multi-field
    # pattern so aggregations / exact-match term filters can consistently target
    # <field>.keyword — matching what dynamic mapping already produced on the
    # existing production index, so this is backward compatible.
    IOC_MAPPING = {
        "properties": {
            "indicator":      {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 1024}}},
            "indicator_type": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
            "threat_type":    {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
            "source":         {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
            "source_url":     {"type": "keyword", "ignore_above": 2048},
            "country_code":   {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 8}}},
            "asn_org":        {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
            "tags":           {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
            "confidence":     {"type": "float"},
            "risk_score":     {"type": "float"},
            "latitude":       {"type": "float"},
            "longitude":      {"type": "float"},
            "first_seen":     {"type": "date"},
            "last_seen":      {"type": "date"},
            "created_at":     {"type": "date"},
            "updated_at":     {"type": "date"},
            "expires_at":     {"type": "date"},
            "active":         {"type": "boolean"},
            "ttl_days":       {"type": "integer"},
        }
    }

    async def ensure_ioc_index(self) -> None:
        """Create the `iocs` index with an explicit mapping if it does not exist.

        No-op if the index already exists (never mutates a live mapping) and only
        runs the existence check once per process. `dynamic` stays enabled, so any
        field not pinned here is still auto-mapped as before.
        """
        if not self.client or self._ioc_index_ready:
            return
        try:
            exists = await self.client.indices.exists(index=self.ioc_index)
            if not exists:
                await self.client.indices.create(
                    index=self.ioc_index,
                    mappings=self.IOC_MAPPING,
                    settings={"index": {"max_result_window": 500000}},
                )
                logger.info(f"Created index with explicit mapping: {self.ioc_index}")
            self._ioc_index_ready = True
        except Exception as e:
            logger.warning(f"Could not ensure iocs index mapping: {e}")
    
    async def store_indicators(
        self, 
        indicators: List[Indicator], 
        enrich_geo: bool = True,
        return_docs: bool = False
    ) -> Any:
        """
        Store indicators in Elasticsearch with optional GeoIP enrichment.
        
        Args:
            indicators: List of Indicator objects to store
            enrich_geo: Whether to enrich with GeoIP data (default: True)
            return_docs: Whether to return stored documents (for WebSocket broadcast)
            
        Returns:
            If return_docs=False: Dict with success/error counts
            If return_docs=True: Tuple of (Dict with counts, List of stored documents)
        """
        if not self.client:
            await self.connect()
        
        if not self.client:
            result = {"success": 0, "errors": len(indicators), "message": "Not connected"}
            return (result, []) if return_docs else result
        
        from datetime import timezone, timedelta

        # Prepare bulk upsert actions (update last_seen if exists, create if new)
        actions = []
        docs = []
        now_iso = datetime.now(timezone.utc).isoformat()
        for indicator in indicators:
            doc = await self._indicator_to_doc_async(indicator, enrich_geo)
            # Set TTL expiry: 30 days from last_seen by default
            ttl_days = 30
            doc["ttl_days"] = ttl_days
            doc["expires_at"] = (
                datetime.now(timezone.utc) + timedelta(days=ttl_days)
            ).isoformat()
            doc["active"] = True

            # Use upsert: create full doc if new, only update last_seen if exists
            doc_id = f"{indicator.indicator_type.value}:{indicator.indicator}"
            action = {
                "_op_type": "update",
                "_index": self.ioc_index,
                "_id": doc_id,
                "doc": doc,
                "doc_as_upsert": True,
                "retry_on_conflict": 3,
            }
            actions.append(action)
            if return_docs:
                docs.append(doc)

        # Bulk upsert
        try:
            success, errors = await async_bulk(
                self.client,
                actions,
                raise_on_error=False,
                stats_only=True,
            )
            result = {"success": success, "errors": errors}
            return (result, docs) if return_docs else result
        except Exception as e:
            logger.error(f"Bulk indexing error: {e}")
            result = {"success": 0, "errors": len(indicators), "message": str(e)}
            return (result, []) if return_docs else result
    
    async def search_indicators(
        self,
        query: str,
        threat_type: Optional[str] = None,
        indicator_type: Optional[str] = None,
        country_code: Optional[str] = None,
        min_confidence: float = 0.0,
        limit: int = 50,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """
        Search for indicators.
        
        Args:
            query: Search query (domain, IP, etc.)
            threat_type: Filter by threat type
            indicator_type: Filter by indicator type
            country_code: Filter by country
            min_confidence: Minimum confidence score
            limit: Max results to return
            offset: Offset for pagination
            
        Returns:
            Search results with hits and total count
        """
        if not self.client:
            await self.connect()
        
        if not self.client:
            return {"hits": [], "total": 0}
        
        # Build query
        must = []
        filter_clauses = []
        
        if query:
            must.append({
                "multi_match": {
                    "query": query,
                    "fields": ["indicator^3", "indicator_text", "tags"],
                    "type": "best_fields",
                }
            })
        
        if threat_type:
            filter_clauses.append({"term": {"threat_type": threat_type}})
        
        if indicator_type:
            filter_clauses.append({"term": {"indicator_type": indicator_type}})
        
        if country_code:
            filter_clauses.append({"term": {"country_code": country_code.upper()}})
        
        if min_confidence > 0:
            filter_clauses.append({"range": {"confidence": {"gte": min_confidence}}})
        
        # Active indicators only
        filter_clauses.append({"term": {"active": True}})
        
        body = {
            "query": {
                "bool": {
                    "must": must if must else [{"match_all": {}}],
                    "filter": filter_clauses,
                }
            },
            "sort": [
                {"last_seen": {"order": "desc"}},
                {"confidence": {"order": "desc"}},
            ],
            "from": offset,
            "size": limit,
        }
        
        try:
            response = await self.client.search(index=self.ioc_index, body=body)
            hits = [hit["_source"] for hit in response["hits"]["hits"]]
            total = response["hits"]["total"]["value"]
            return {"hits": hits, "total": total}
        except Exception as e:
            logger.error(f"Search error: {e}")
            return {"hits": [], "total": 0}
    
    async def get_indicator(self, indicator: str, source: Optional[str] = None) -> Optional[Dict]:
        """
        Get a specific indicator by value.
        
        Args:
            indicator: The indicator value (domain, IP, etc.)
            source: Optional source filter
            
        Returns:
            Indicator document or None
        """
        if not self.client:
            await self.connect()
        
        if not self.client:
            return None
        
        query = {"term": {"indicator": indicator}}
        if source:
            query = {
                "bool": {
                    "must": [
                        {"term": {"indicator": indicator}},
                        {"term": {"source": source}},
                    ]
                }
            }
        
        try:
            response = await self.client.search(
                index=self.ioc_index,
                query=query,
                size=1,
            )
            if response["hits"]["hits"]:
                return response["hits"]["hits"][0]["_source"]
        except Exception as e:
            logger.error(f"Get indicator error: {e}")
        
        return None
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get statistics about stored indicators."""
        if not self.client:
            await self.connect()
        
        if not self.client:
            return {}
        
        try:
            # Get total count
            count_response = await self.client.count(index=self.ioc_index)
            total = count_response["count"]
            
            # Get aggregations. iocs_v2 maps these fields as `keyword` directly
            # (no .keyword sub-field), so aggregate on the bare field name.
            agg_body = {
                "size": 0,
                "aggs": {
                    "by_threat_type": {
                        "terms": {"field": "threat_type", "size": 10}
                    },
                    "by_indicator_type": {
                        "terms": {"field": "indicator_type", "size": 10}
                    },
                    "by_source": {
                        "terms": {"field": "source", "size": 20}
                    },
                    "by_country": {
                        "terms": {"field": "country_code", "size": 60}
                    },
                }
            }
            
            agg_response = await self.client.search(index=self.ioc_index, body=agg_body)
            
            return {
                "total": total,
                "by_threat_type": {
                    b["key"]: b["doc_count"]
                    for b in agg_response["aggregations"]["by_threat_type"]["buckets"]
                },
                "by_indicator_type": {
                    b["key"]: b["doc_count"]
                    for b in agg_response["aggregations"]["by_indicator_type"]["buckets"]
                },
                "by_source": {
                    b["key"]: b["doc_count"]
                    for b in agg_response["aggregations"]["by_source"]["buckets"]
                },
                "by_country": {
                    b["key"]: b["doc_count"]
                    for b in agg_response["aggregations"]["by_country"]["buckets"]
                },
            }
        except Exception as e:
            logger.error(f"Stats error: {e}", exc_info=True)
            raise
    
    async def get_recent_indicators(
        self,
        limit: int = 50,
        since: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get recent indicators for live threat feed.
        
        Args:
            limit: Maximum number of indicators to return
            since: Only return indicators seen since this time
            
        Returns:
            List of indicator documents with geo data
        """
        if not self.client:
            await self.connect()
        
        if not self.client:
            return []
        
        # Build query — return all active indicators (geo data optional)
        filter_clauses = [
            {"term": {"active": True}},
        ]
        
        if since:
            # Check both last_seen and created_at to catch newly imported indicators
            filter_clauses.append({
                "bool": {
                    "should": [
                        {"range": {"last_seen": {"gte": since.isoformat()}}},
                        {"range": {"created_at": {"gte": since.isoformat()}}},
                    ],
                    "minimum_should_match": 1
                }
            })
        
        # Prefer indicators WITH geo data, but include others too
        body = {
            "query": {
                "bool": {
                    "filter": filter_clauses,
                    "should": [
                        {"exists": {"field": "country_code"}},
                    ],
                }
            },
            "sort": [
                {"_score": {"order": "desc"}},
                {"created_at": {"order": "desc"}},
            ],
            "size": limit,
            "_source": [
                "indicator", "indicator_type", "threat_type", "source",
                "confidence", "risk_score", "country_code", "asn", "asn_org",
                "ip_address", "latitude", "longitude", "first_seen", "last_seen", "tags"
            ]
        }
        
        try:
            response = await self.client.search(index=self.ioc_index, body=body)
            return [hit["_source"] for hit in response["hits"]["hits"]]
        except Exception as e:
            logger.error(f"Get recent indicators error: {e}")
            return []
    
    async def get_country_threat_stats(self) -> Dict[str, Dict[str, Any]]:
        """
        Get threat statistics aggregated by country.
        
        Returns:
            Dict mapping country codes to threat stats
        """
        if not self.client:
            await self.connect()
        
        if not self.client:
            return {}
        
        try:
            agg_body = {
                "size": 0,
                "aggs": {
                    "by_country": {
                        "terms": {"field": "country_code", "size": 60},
                        "aggs": {
                            "by_threat_type": {
                                "terms": {"field": "threat_type", "size": 10}
                            },
                            "avg_confidence": {
                                "avg": {"field": "confidence"}
                            }
                        }
                    }
                }
            }
            
            response = await self.client.search(index=self.ioc_index, body=agg_body)
            
            result = {}
            for bucket in response["aggregations"]["by_country"]["buckets"]:
                country_code = bucket["key"]
                threat_types = {
                    b["key"]: b["doc_count"]
                    for b in bucket["by_threat_type"]["buckets"]
                }
                result[country_code] = {
                    "total": bucket["doc_count"],
                    "c2": threat_types.get("c2", 0),
                    "malware": threat_types.get("malware", 0),
                    "phishing": threat_types.get("phishing", 0),
                    "exfiltration": threat_types.get("exfiltration", 0),
                    "avg_confidence": bucket["avg_confidence"]["value"] or 0.5,
                }
            return result
        except Exception as e:
            # ES is up but the query/aggregation failed — do NOT hide it behind an
            # empty map. (An actual ES outage is already handled above by the
            # `if not self.client: return {}` guard, so this only fires on a real
            # query/mapping error that must surface.)
            logger.error(f"Country threat stats error: {e}", exc_info=True)
            raise
    
    async def _indicator_to_doc_async(self, indicator: Indicator, enrich_geo: bool = True) -> Dict[str, Any]:
        """Convert Indicator object to Elasticsearch document with optional GeoIP enrichment."""
        now = datetime.utcnow().isoformat()
        
        doc = {
            "indicator": indicator.indicator,
            "indicator_type": indicator.indicator_type.value,
            "threat_type": indicator.threat_type.value,
            "source": indicator.source,
            "source_url": indicator.source_url,
            "confidence": indicator.confidence,
            "risk_score": indicator.confidence * 100,  # Convert to 0-100 scale
            "tags": indicator.tags,
            "first_seen": indicator.first_seen.isoformat() if indicator.first_seen else now,
            "last_seen": indicator.last_seen.isoformat() if indicator.last_seen else now,
            "created_at": now,
            "updated_at": now,
            "active": True,
            **indicator.metadata,
        }
        
        # Enrich with GeoIP data if enabled (sync call - local DB is fast)
        if enrich_geo:
            geo_data = geoip_service.enrich_indicator_sync(
                indicator.indicator,
                indicator.indicator_type.value
            )
            if geo_data:
                doc.update(geo_data)
        
        return doc
    
    def _indicator_to_doc(self, indicator: Indicator) -> Dict[str, Any]:
        """Convert Indicator object to Elasticsearch document (sync version, no GeoIP)."""
        now = datetime.utcnow().isoformat()
        return {
            "indicator": indicator.indicator,
            "indicator_type": indicator.indicator_type.value,
            "threat_type": indicator.threat_type.value,
            "source": indicator.source,
            "source_url": indicator.source_url,
            "confidence": indicator.confidence,
            "risk_score": indicator.confidence * 100,  # Convert to 0-100 scale
            "tags": indicator.tags,
            "first_seen": indicator.first_seen.isoformat() if indicator.first_seen else now,
            "last_seen": indicator.last_seen.isoformat() if indicator.last_seen else now,
            "created_at": now,
            "updated_at": now,
            "active": True,
            **indicator.metadata,
        }


# Singleton instance
es_service = ElasticsearchService()
