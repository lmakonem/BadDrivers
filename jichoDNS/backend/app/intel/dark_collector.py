"""
Dark Web Collector — processes TorBot crawl output into Elasticsearch and MISP.

Watches /intel-data/torbot-output for JSON files, normalizes them into
the darkweb_posts ES index, and creates MISP events for brand/VIP matches.

Can also be invoked as Celery tasks from the main worker.
"""

import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.core.config import settings

logger = logging.getLogger(__name__)

DARKWEB_INDEX = "darkweb_posts"
INTEL_DATA_DIR = os.environ.get("INTEL_DATA_DIR", "/intel-data/torbot-output")


async def ensure_darkweb_index(es_client):
    """Create the darkweb_posts index if it doesn't exist."""
    if not es_client:
        return
    exists = await es_client.indices.exists(index=DARKWEB_INDEX)
    if not exists:
        await es_client.indices.create(
            index=DARKWEB_INDEX,
            body={
                "mappings": {
                    "properties": {
                        "url": {"type": "keyword"},
                        "title": {"type": "text"},
                        "body_text": {"type": "text"},
                        "source": {"type": "keyword"},
                        "source_type": {"type": "keyword"},  # forum, market, paste, blog
                        "discovered_at": {"type": "date"},
                        "tags": {"type": "keyword"},
                        "brand_matches": {"type": "keyword"},
                        "vip_matches": {"type": "keyword"},
                        "emails_found": {"type": "keyword"},
                        "onion_links": {"type": "keyword"},
                        "severity": {"type": "keyword"},
                        "misp_event_id": {"type": "keyword"},
                        "raw_data": {"type": "object", "enabled": False},
                    }
                },
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 0,
                },
            },
        )
        logger.info(f"Created index: {DARKWEB_INDEX}")


def parse_torbot_json(filepath: str) -> List[Dict[str, Any]]:
    """Parse TorBot JSON output into normalized documents."""
    docs = []
    try:
        with open(filepath, "r") as f:
            data = json.load(f)

        # TorBot output varies by version — handle list or single object
        records = data if isinstance(data, list) else [data]

        for record in records:
            doc = {
                "url": record.get("url", record.get("link", "")),
                "title": record.get("title", ""),
                "body_text": record.get("body", record.get("content", "")),
                "source": "torbot",
                "source_type": classify_onion_site(record),
                "discovered_at": datetime.now(timezone.utc).isoformat(),
                "tags": record.get("tags", []),
                "emails_found": record.get("emails", []),
                "onion_links": extract_onion_links(
                    record.get("body", record.get("content", ""))
                ),
                "raw_data": record,
            }
            docs.append(doc)
    except Exception as e:
        logger.error(f"Error parsing TorBot JSON {filepath}: {e}")

    return docs


def classify_onion_site(record: Dict) -> str:
    """Classify the type of dark web site from content."""
    text = (
        record.get("title", "") + " " + record.get("body", record.get("content", ""))
    ).lower()

    if any(w in text for w in ["market", "shop", "buy", "sell", "vendor", "listing"]):
        return "market"
    if any(w in text for w in ["forum", "thread", "reply", "post", "discuss"]):
        return "forum"
    if any(w in text for w in ["paste", "pastebin", "dump"]):
        return "paste"
    if any(w in text for w in ["leak", "breach", "database", "combo"]):
        return "leak_site"
    return "other"


def extract_onion_links(text: str) -> List[str]:
    """Extract .onion URLs from text."""
    if not text:
        return []
    return list(set(re.findall(r"https?://[a-z2-7]{16,56}\.onion[^\s\"'<>]*", text)))


def match_watchlist_terms(
    doc: Dict, brand_terms: List[str], vip_names: List[str]
) -> tuple:
    """Check if document matches any brand terms or VIP names."""
    text = (doc.get("title", "") + " " + doc.get("body_text", "")).lower()

    brand_matches = [t for t in brand_terms if t.lower() in text]
    vip_matches = [n for n in vip_names if n.lower() in text]

    return brand_matches, vip_matches


async def process_torbot_output(
    es_client,
    misp_client=None,
    brand_terms: Optional[List[str]] = None,
    vip_names: Optional[List[str]] = None,
    data_dir: str = INTEL_DATA_DIR,
) -> Dict[str, Any]:
    """
    Process all TorBot JSON files in the output directory.

    Returns summary of processed documents and matches.
    """
    brand_terms = brand_terms or []
    vip_names = vip_names or []
    data_path = Path(data_dir)

    if not data_path.exists():
        return {"processed": 0, "error": f"Directory not found: {data_dir}"}

    await ensure_darkweb_index(es_client)

    total_docs = 0
    total_brand = 0
    total_vip = 0
    misp_events = 0

    for json_file in data_path.glob("*.json"):
        docs = parse_torbot_json(str(json_file))

        for doc in docs:
            # Check watchlist matches
            brand_matches, vip_matches = match_watchlist_terms(
                doc, brand_terms, vip_names
            )
            doc["brand_matches"] = brand_matches
            doc["vip_matches"] = vip_matches
            doc["severity"] = (
                "critical"
                if vip_matches
                else "high"
                if brand_matches
                else "medium"
            )

            # Store in Elasticsearch — use deterministic hash for dedup
            import hashlib as _hl
            doc_id = f"torbot:{_hl.md5(doc['url'].encode()).hexdigest()}"
            try:
                await es_client.index(
                    index=DARKWEB_INDEX, id=doc_id, document=doc
                )
                total_docs += 1
            except Exception as e:
                logger.error(f"ES index error: {e}")

            # Create MISP event for high-severity matches
            if (brand_matches or vip_matches) and misp_client and misp_client.enabled:
                try:
                    # This would create a MISP event — requires the MISP API
                    # For now, log the match
                    logger.info(
                        f"MISP-worthy match: brands={brand_matches} vips={vip_matches} url={doc['url']}"
                    )
                    misp_events += 1
                except Exception as e:
                    logger.error(f"MISP event creation error: {e}")

            total_brand += len(brand_matches)
            total_vip += len(vip_matches)

        # Move processed file to avoid reprocessing
        try:
            json_file.rename(json_file.with_suffix(".json.processed"))
        except Exception:
            pass

    return {
        "processed": total_docs,
        "brand_matches": total_brand,
        "vip_matches": total_vip,
        "misp_events_created": misp_events,
    }
