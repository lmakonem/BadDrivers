"""
Tor-based dark web crawler.

Uses the Tor SOCKS proxy to crawl .onion sites and clearnet dark web
resources. Results are stored in the darkweb_posts Elasticsearch index.

Runs as a Celery task — no separate TorBot container needed.
"""

import hashlib
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

# Tor SOCKS proxy — runs as intel-tor container or localhost
TOR_PROXY = "socks5://intel-tor:9050"
TOR_PROXY_FALLBACK = "socks5://127.0.0.1:9050"

DARKWEB_INDEX = "darkweb_posts"

# Seed URLs — dark web search engines, paste sites, forums
DEFAULT_SEEDS = [
    # Ahmia — clearnet search engine for .onion sites
    "https://ahmia.fi/search/?q=africa+breach",
    "https://ahmia.fi/search/?q=credential+leak",
    "https://ahmia.fi/search/?q=kenya+hack",
    "https://ahmia.fi/search/?q=banking+fraud+africa",
    "https://ahmia.fi/search/?q=mpesa+fraud",
    "https://ahmia.fi/search/?q=safaricom+leak",
    # IntelX (clearnet, has dark web results)
    "https://intelx.io/?s=africa+breach",
]

# Patterns to extract from crawled pages
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
ONION_RE = re.compile(r"https?://[a-z2-7]{16,56}\.onion[^\s\"'<>]*")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:co\.ke|co\.tz|co\.ug|co\.za|com|org|net)\b")


async def ensure_darkweb_index(es_client):
    """Create darkweb_posts index if not exists."""
    if not es_client:
        return
    try:
        exists = await es_client.indices.exists(index=DARKWEB_INDEX)
        if not exists:
            await es_client.indices.create(
                index=DARKWEB_INDEX,
                body={
                    "mappings": {
                        "properties": {
                            "url": {"type": "keyword"},
                            "title": {"type": "text", "analyzer": "standard"},
                            "body_text": {"type": "text", "analyzer": "standard"},
                            "source": {"type": "keyword"},
                            "source_type": {"type": "keyword"},
                            "crawl_query": {"type": "keyword"},
                            "discovered_at": {"type": "date"},
                            "emails_found": {"type": "keyword"},
                            "onion_links": {"type": "keyword"},
                            "ips_found": {"type": "keyword"},
                            "domains_found": {"type": "keyword"},
                            "severity": {"type": "keyword"},
                            "tags": {"type": "keyword"},
                        }
                    },
                    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
                },
            )
            logger.info(f"Created index: {DARKWEB_INDEX}")
    except Exception as e:
        logger.warning(f"Index creation warning: {e}")


async def crawl_url(url: str, use_tor: bool = False) -> Optional[Dict[str, Any]]:
    """Crawl a single URL and extract dark web intelligence."""
    try:
        proxy = TOR_PROXY if use_tor else None
        timeout = httpx.Timeout(30.0, connect=15.0)

        async with httpx.AsyncClient(
            proxy=proxy,
            timeout=timeout,
            verify=False,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"},
        ) as client:
            response = await client.get(url)
            if response.status_code != 200:
                return None

            text = response.text
            # Extract title
            title_match = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
            title = title_match.group(1).strip()[:500] if title_match else ""

            # Strip HTML tags for body text
            body = re.sub(r"<[^>]+>", " ", text)
            body = re.sub(r"\s+", " ", body).strip()[:10000]

            # Extract IOCs
            emails = list(set(EMAIL_RE.findall(body)))[:50]
            onion_links = list(set(ONION_RE.findall(text)))[:20]
            ips = list(set(IP_RE.findall(body)))[:50]
            domains = list(set(DOMAIN_RE.findall(body.lower())))[:50]

            # Classify source type
            parsed = urlparse(url)
            is_onion = parsed.hostname and parsed.hostname.endswith(".onion")
            source_type = "onion_site" if is_onion else "clearnet_darkweb"

            if "ahmia" in (parsed.hostname or ""):
                source_type = "darkweb_search"
            elif "paste" in (parsed.hostname or ""):
                source_type = "paste_site"
            elif "forum" in body.lower() or "thread" in body.lower():
                source_type = "forum"

            # Determine severity
            severity = "low"
            if emails and len(emails) > 5:
                severity = "high"
            if any(w in body.lower() for w in ["breach", "leak", "dump", "credential", "password"]):
                severity = "high"
            if any(w in body.lower() for w in ["ransom", "encrypt", "bitcoin", "monero"]):
                severity = "critical"

            return {
                "url": url,
                "title": title,
                "body_text": body[:5000],
                "source": parsed.hostname or "unknown",
                "source_type": source_type,
                "discovered_at": datetime.now(timezone.utc).isoformat(),
                "emails_found": emails,
                "onion_links": onion_links,
                "ips_found": ips,
                "domains_found": domains,
                "severity": severity,
                "tags": [source_type, severity],
            }

    except Exception as e:
        logger.warning(f"Crawl error for {url}: {e}")
        return None


async def crawl_ahmia(query: str, max_results: int = 20) -> List[Dict[str, Any]]:
    """Search Ahmia (clearnet Tor search engine) and extract results."""
    results = []
    url = f"https://ahmia.fi/search/?q={query.replace(' ', '+')}"

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(30.0),
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"},
        ) as client:
            response = await client.get(url)
            if response.status_code != 200:
                return results

            text = response.text

            # Extract result links from Ahmia HTML
            # Ahmia results have <a> tags with .onion URLs or redirect URLs
            links = re.findall(r'href="(https?://[^"]*\.onion[^"]*)"', text)
            links += re.findall(r'href="/search/redirect\?search_url=(https?://[^"&]*)"', text)

            # Also extract any .onion URLs from the page text
            onion_urls = list(set(ONION_RE.findall(text)))

            all_urls = list(set(links + onion_urls))[:max_results]

            for result_url in all_urls:
                doc = {
                    "url": result_url,
                    "title": f"Ahmia result for: {query}",
                    "body_text": f"Found via dark web search for '{query}'. URL: {result_url}",
                    "source": "ahmia.fi",
                    "source_type": "darkweb_search",
                    "crawl_query": query,
                    "discovered_at": datetime.now(timezone.utc).isoformat(),
                    "emails_found": [],
                    "onion_links": [result_url] if ".onion" in result_url else [],
                    "ips_found": [],
                    "domains_found": [],
                    "severity": "medium",
                    "tags": ["darkweb_search", query.replace(" ", "_")],
                }
                results.append(doc)

    except Exception as e:
        logger.warning(f"Ahmia search error for '{query}': {e}")

    return results


async def run_dark_web_crawl(
    es_client,
    queries: Optional[List[str]] = None,
    seed_urls: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Run a dark web crawl cycle.

    1. Search Ahmia for each query term
    2. Crawl any provided seed URLs
    3. Store results in darkweb_posts ES index
    """
    if queries is None:
        queries = [
            "africa breach", "kenya hack", "credential leak africa",
            "mpesa fraud", "safaricom", "banking africa leak",
            "south africa breach", "nigeria hack", "credential dump",
        ]

    if seed_urls is None:
        seed_urls = DEFAULT_SEEDS

    await ensure_darkweb_index(es_client)

    all_docs: List[Dict[str, Any]] = []
    errors = 0

    # 1. Ahmia searches
    for query in queries:
        try:
            results = await crawl_ahmia(query, max_results=10)
            all_docs.extend(results)
        except Exception as e:
            logger.warning(f"Ahmia crawl error for '{query}': {e}")
            errors += 1

    # 2. Direct URL crawls (clearnet dark web resources)
    for url in seed_urls:
        try:
            doc = await crawl_url(url, use_tor=".onion" in url)
            if doc:
                all_docs.append(doc)
        except Exception as e:
            logger.warning(f"URL crawl error for {url}: {e}")
            errors += 1

    # 3. Store in ES
    stored = 0
    if all_docs and es_client:
        from elasticsearch.helpers import async_bulk

        actions = []
        for doc in all_docs:
            doc_id = f"dw:{hashlib.md5(doc['url'].encode()).hexdigest()}"
            actions.append({
                "_op_type": "update",
                "_index": DARKWEB_INDEX,
                "_id": doc_id,
                "doc": doc,
                "doc_as_upsert": True,
            })

        try:
            stored, bulk_errors = await async_bulk(es_client, actions, raise_on_error=False)
        except Exception as e:
            logger.error(f"ES bulk error: {e}")

    return {
        "total_crawled": len(all_docs),
        "stored": stored,
        "errors": errors,
        "queries_searched": len(queries),
    }
