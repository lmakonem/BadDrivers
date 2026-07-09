"""
Brand monitor scanning + alert generation.

For each active brand monitor this writes brand_alerts with DETERMINISTIC ids
(md5 of brand_id:alert_type:key) so re-scans upsert instead of duplicating, and
updates the monitor's typosquat_count / last_scan_at:

  * typosquat_detected — look-alike domains that actually RESOLVE (DNS), i.e.
    someone registered them (unregistered variants are noise and never alerted).
  * ioc_match          — live IOC-feed indicators (phishing/C2/malware) whose
    value contains the brand's registrable label (not generic subdomain words).
  * credential_leak     — breach credentials for the brand's own domains.

Scheduled every 3h by app.worker.scan_brand_monitors. DNS resolution is bounded
(cap per brand + bounded concurrency + short timeout) so a full sweep of ~150
brands stays well inside the task time limit and does not hammer the resolver.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import socket
from datetime import datetime, timezone
from typing import Any, Dict, List

from elasticsearch.helpers import async_bulk, async_scan

from app.core.brand_util import apex_domains, specific_brand_terms, registrable_base
from app.core.ownership import bare_domain

logger = logging.getLogger(__name__)

ALERT_INDEX = "brand_alerts"
IOC_INDEX = "iocs"
CRED_INDEX = "credential_exposures"

# DNS-resolution bounds (per brand).
VARIANTS_PER_BRAND = 35        # highest-risk look-alikes to actually DNS-check
DNS_CONCURRENCY = 15
DNS_TIMEOUT = 3.0
# IOC alerts to raise per brand (highest risk first) — avoids flooding.
IOC_ALERTS_PER_BRAND = 25
# Brands scanned concurrently (bounds total in-flight DNS + ES load).
BRAND_CONCURRENCY = 4


def _alert_id(brand_id: str, alert_type: str, key: str) -> str:
    return hashlib.md5(f"{brand_id}:{alert_type}:{key}".encode()).hexdigest()


async def _resolve_registered(variants: List[str]) -> List[str]:
    """Return the subset of variant domains that resolve in DNS (bounded)."""
    sem = asyncio.Semaphore(DNS_CONCURRENCY)
    loop = asyncio.get_running_loop()

    async def check(v: str):
        async with sem:
            try:
                await asyncio.wait_for(
                    loop.run_in_executor(None, socket.gethostbyname, v),
                    timeout=DNS_TIMEOUT,
                )
                return v
            except Exception:
                return None

    results = await asyncio.gather(*[check(v) for v in variants[:VARIANTS_PER_BRAND]])
    return [r for r in results if r]


async def scan_brand_monitor(es, brand_svc, monitor: Dict[str, Any]) -> Dict[str, Any]:
    """Scan one monitor, upsert its brand_alerts, update its counts."""
    brand_id = monitor["id"]
    name = monitor.get("brand_name") or "brand"
    domains = monitor.get("domains") or []
    keywords = monitor.get("keywords") or []
    now = datetime.now(timezone.utc).isoformat()

    common = {
        "brand_name": name,
        "country_code": monitor.get("country_code"),
        "industry": monitor.get("industry"),
        "client_id": monitor.get("client_id"),
        "owner_user_id": monitor.get("owner_user_id"),
    }
    alerts: Dict[str, dict] = {}

    def add(alert_type: str, severity: str, title: str, key: str,
            domain: str = None, similarity: int = None, details: dict = None):
        aid = _alert_id(brand_id, alert_type, key)
        alerts[aid] = {
            "id": aid, "brand_id": brand_id, **common,
            "alert_type": alert_type, "severity": severity, "title": title,
            "domain": domain, "similarity": similarity, "details": details or {},
            "detected_at": now, "acknowledged": False,
        }

    # ── 1. Registered typosquats (DNS-resolved look-alikes) ──────────────────
    typosquat_count = 0
    for apex in apex_domains(domains)[:2]:
        try:
            variants = brand_svc.detect_typosquatting(apex, check_dns=False)
        except Exception as e:
            logger.warning(f"[brand-scan] typosquat gen failed for {apex}: {e}")
            continue
        variants.sort(key=lambda v: getattr(v, "risk_score", 0) or 0, reverse=True)
        vmap = {v.variant: v for v in variants}
        for dom in await _resolve_registered([v.variant for v in variants]):
            v = vmap.get(dom)
            sim = int(getattr(v, "risk_score", 0) or 60) if v else 60
            add(
                "typosquat_detected",
                "critical" if sim >= 80 else "high",
                f"Registered look-alike domain: {dom}",
                key=dom, domain=dom, similarity=sim,
                details={
                    "original": apex,
                    "technique": getattr(getattr(v, "technique", None), "value", "") if v else "",
                },
            )
            typosquat_count += 1

    # ── 2. IOC-feed matches for the brand ────────────────────────────────────
    terms = specific_brand_terms(domains, keywords)
    if terms:
        should = [{"terms": {"indicator": [bare_domain(d) for d in domains if d]}}]
        should += [{"wildcard": {"indicator": f"*{t}*"}} for t in terms[:6]]
        try:
            r = await es.search(
                index=IOC_INDEX,
                query={"bool": {"should": should, "minimum_should_match": 1,
                                "filter": [{"term": {"active": True}}]}},
                sort=[{"risk_score": {"order": "desc", "unmapped_type": "float"}}],
                size=IOC_ALERTS_PER_BRAND,
                _source=["indicator", "threat_type", "source", "risk_score", "indicator_type"],
            )
            for h in r["hits"]["hits"]:
                s = h["_source"]
                risk = float(s.get("risk_score") or 0)
                tt = (s.get("threat_type") or "threat")
                add(
                    "ioc_match",
                    "critical" if risk >= 80 else "high" if risk >= 60 else "medium",
                    f"{tt.upper()} indicator targeting {name}: {s.get('indicator')}",
                    key=str(s.get("indicator")), domain=s.get("indicator"),
                    details={"source": s.get("source"), "threat_type": tt,
                             "risk_score": risk, "indicator_type": s.get("indicator_type")},
                )
        except Exception as e:
            logger.warning(f"[brand-scan] IOC match failed for {name}: {e}")

    # ── 3. Breach credential leaks for the brand's domains ───────────────────
    try:
        if await es.indices.exists(index=CRED_INDEX):
            bare = list({bare_domain(d) for d in domains if d})
            if bare:
                cnt = (await es.count(index=CRED_INDEX, query={"terms": {"domain": bare}}))["count"]
                if cnt > 0:
                    add("credential_leak", "high",
                        f"{cnt} leaked credential(s) found for {name} domains",
                        key="creds", details={"count": cnt, "domains": bare[:10]})
    except Exception as e:
        logger.warning(f"[brand-scan] credential match failed for {name}: {e}")

    # ── Persist: upsert alerts + update the monitor ──────────────────────────
    if alerts:
        actions = [{"_op_type": "index", "_index": ALERT_INDEX, "_id": k, "_source": v}
                   for k, v in alerts.items()]
        try:
            await async_bulk(es, actions, raise_on_error=False)
        except Exception as e:
            logger.warning(f"[brand-scan] alert bulk write failed for {name}: {e}")
    try:
        await es.update(index="brand_monitors", id=brand_id,
                        doc={"typosquat_count": typosquat_count, "last_scan_at": now})
    except Exception as e:
        logger.warning(f"[brand-scan] monitor update failed for {name}: {e}")

    return {"brand": name, "alerts": len(alerts), "typosquats": typosquat_count}


async def scan_all_brand_monitors(es, brand_svc) -> Dict[str, Any]:
    """Scan every active brand monitor (bounded concurrency) and upsert alerts."""
    monitors: List[dict] = []
    async for h in async_scan(
        es, index="brand_monitors",
        query={"query": {"term": {"active": True}}},
    ):
        monitors.append(h["_source"])

    sem = asyncio.Semaphore(BRAND_CONCURRENCY)

    async def _run(mon):
        async with sem:
            try:
                return await scan_brand_monitor(es, brand_svc, mon)
            except Exception as e:
                logger.error(f"[brand-scan] {mon.get('brand_name')}: {e}", exc_info=True)
                return {"brand": mon.get("brand_name"), "error": str(e)}

    results = await asyncio.gather(*[_run(m) for m in monitors])
    try:
        await es.indices.refresh(index=ALERT_INDEX)
    except Exception:
        pass

    total_alerts = sum(r.get("alerts", 0) for r in results)
    total_typos = sum(r.get("typosquats", 0) for r in results)
    with_findings = [r for r in results if r.get("alerts")]
    return {
        "monitors_scanned": len(monitors),
        "total_alerts": total_alerts,
        "total_typosquats": total_typos,
        "brands_with_findings": len(with_findings),
    }
