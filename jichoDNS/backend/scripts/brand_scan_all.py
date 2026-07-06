"""
brand_scan_all.py — Brand protection scan for all ASM clients.
Run inside jichodns-worker: python3 /app/scripts/brand_scan_all.py

False-positive suppression rules:
  1. Brand base < 4 chars → skip TLD permutation (too many unrelated registrations)
  2. Generic words (banco, orange, airtel, standard, fnb, etc.) → exact match only
  3. Same brand name on different African ccTLD → NOT impersonation
  4. Candidate must differ meaningfully from all the client's own domains
  5. dnstwist character-level variants → always genuine, kept
  6. Similarity threshold: candidate must share ≥70% of brand name chars
"""
import asyncio
import difflib
import hashlib
import os
import re
import socket
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

sys.path.insert(0, "/app")
import psycopg2

# ── Config ────────────────────────────────────────────────────────────────────
BATCH_SIZE = 5
BATCH_DELAY = 20

# Generic words that appear in many company names and should NOT drive TLD scanning
GENERIC_WORDS = {
    "banco", "bank", "banque", "orange", "airtel", "mtn", "vodacom",
    "standard", "first", "national", "commercial", "investment", "development",
    "telecommunications", "telecom", "mobile", "wireless", "network",
    "angola", "botswana", "comores", "lesotho", "madagascar", "malawi",
    "mauritius", "mozambique", "namibia", "seychelles", "eswatini",
    "zambia", "zimbabwe", "tanzania", "kenya", "uganda", "ghana",
    "africa", "african", "international", "group", "holdings", "limited",
    "commerce", "industrie", "federale", "developpement",
}

# All African ccTLDs — same brand on a different African ccTLD is NOT impersonation
AFRICAN_CCTLDS = {
    "co.za", "co.ke", "co.tz", "co.ug", "co.bw", "co.zw", "co.zm", "co.mz",
    "co.ls", "co.sz", "co.na", "co.mu", "co.ao", "co.mg", "co.mw", "co.rw",
    "co.ng", "co.gh", "co.et", "co.sn", "com.na", "com.mu", "com.gh",
    "ng", "gh", "ke", "tz", "ug", "bw", "zw", "zm", "mz", "ls", "sz",
    "na", "mu", "ao", "mg", "mw", "rw", "sn", "ci", "cm", "cd", "sc",
    "km", "et", "dz", "ma", "eg", "tn", "ly", "sd",
}

# Phishing-specific TLDs (higher confidence when brand resolves here)
PHISHING_TLDS = {"tk", "ml", "ga", "cf", "gq", "top", "club", "live", "shop", "pw"}

# Suspicious combo suffixes that signal fraud
SUSPICIOUS_SUFFIXES = [
    "online", "mobile", "pay", "secure", "login", "verify", "account",
    "banking", "bank", "payment", "transfer", "support", "help",
    "official", "real", "genuine", "legit", "auth",
]

DNSTWIST_TIMEOUT = 90


def extract_brand_identity(client_name: str, domains: List[str], industry: str) -> Dict[str, Any]:
    """Extract brand keyword, domains, and check if brand base is usable."""
    name = client_name.strip()
    stopwords = {
        "the", "of", "and", "for", "in", "a", "an", "de", "la", "le", "du",
        "des", "et", "bank", "banque", "banco", "telecom", "telecommunications",
        "wireless", "mobile", "networks", "corporation", "corp", "ltd", "limited",
        "group", "holdings", "international", "africa", "african", "national",
        "commercial", "investment", "development", "industry",
    }
    words = re.split(r"[\s\-_/&]+", name.lower())
    meaningful = [w for w in words if w and w not in stopwords and len(w) > 2]
    primary = meaningful[0] if meaningful else words[0] if words else name.lower()

    # Extract base names from domains (strip www., strip TLD)
    domain_bases = []
    for d in domains:
        d = d.lstrip("www.").lower()
        # Remove any African ccTLD
        for tld in sorted(AFRICAN_CCTLDS, key=len, reverse=True):
            if d.endswith("." + tld):
                base = d[: -(len(tld) + 1)]
                domain_bases.append(base)
                break
        else:
            parts = d.split(".")
            domain_bases.append(parts[0])

    domain_bases = list(set(domain_bases))

    # Is the brand base a generic word? If so, skip TLD permutation entirely
    is_generic = primary in GENERIC_WORDS or len(primary) < 4

    keywords = list(set([primary] + domain_bases))
    keywords = [k for k in keywords if k and len(k) > 2 and k not in GENERIC_WORDS]

    return {
        "brand_name": name,
        "primary_keyword": primary,
        "keywords": keywords,
        "domain_bases": domain_bases,
        "industry": industry,
        "is_generic": is_generic,
        "skip_tld_scan": is_generic or len(primary) < 4,
    }


def is_false_positive(candidate: str, original_domains: List[str], domain_bases: List[str], client_name: str) -> Optional[str]:
    """
    Return a reason string if candidate is a false positive, else None.
    """
    cand = candidate.lower().strip()

    # 1. Candidate IS one of the original legitimate domains
    legit = set(d.lower().lstrip("www.") for d in original_domains)
    if cand in legit or f"www.{cand}" in legit:
        return "is_legitimate_domain"

    # 2. Extract the candidate's base and TLD
    cand_parts = cand.split(".")
    cand_base = cand_parts[0]
    cand_tld = ".".join(cand_parts[1:])

    # 3. Same exact base on a different African ccTLD → not impersonation
    # (e.g. unitel.co.za when brand is unitel.co.ao)
    for base in domain_bases:
        if cand_base == base and cand_tld in AFRICAN_CCTLDS:
            return f"same_brand_african_cctld:{cand_tld}"

    # 4. Candidate base too short for reliable matching (< 4 chars)
    if len(cand_base) < 4:
        return "base_too_short"

    # 5. Base is a generic word
    if cand_base in GENERIC_WORDS:
        return "generic_word_base"

    # 6. Candidate shares no meaningful similarity with any brand base
    max_sim = 0.0
    for base in domain_bases:
        sim = difflib.SequenceMatcher(None, base, cand_base).ratio()
        max_sim = max(max_sim, sim)
    # Must be at least 55% similar to brand base (catches combosquats like "unitel-bank.com")
    # AND must actually contain the brand keyword or have high char overlap
    brand_in_cand = any(base in cand_base or cand_base in base for base in domain_bases)
    if max_sim < 0.55 and not brand_in_cand:
        return f"low_similarity:{max_sim:.2f}"

    # 7. Country name in candidate without brand keyword → not impersonation
    # e.g. "angola.com" for client "Angola Telecom" whose base is "angolatelecom"
    # Only flag if brand base is actually present in candidate
    primary_base = domain_bases[0] if domain_bases else ""
    if len(primary_base) > 4 and primary_base not in cand and not any(b in cand for b in domain_bases if len(b) > 4):
        return "brand_base_not_in_candidate"

    return None  # Genuine candidate


def severity_for_candidate(candidate: str, has_mx: bool, resolved_ip: str, tld: str) -> str:
    """Determine severity based on risk factors."""
    cand = candidate.lower()
    if tld in PHISHING_TLDS:
        return "critical"
    if has_mx:
        return "critical"  # MX = likely phishing email
    if any(suf in cand for suf in SUSPICIOUS_SUFFIXES):
        return "high"
    return "medium"


def check_dns_resolves(domain: str, timeout: float = 2.0) -> Optional[str]:
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyname(domain)
    except Exception:
        return None


async def run_dnstwist(domain: str) -> List[Dict]:
    """Run dnstwist for genuine character-level typosquats."""
    try:
        import dnstwist
        loop = asyncio.get_event_loop()

        def _twist():
            try:
                twist = dnstwist.DomainFuzz(domain)
                twist.generate()
                twist.check(registered=True, threads=20)
                return [
                    d for d in twist.domains
                    if (d.get("dns_a") or d.get("dns_aaaa") or d.get("dns_mx"))
                    and d.get("fuzzer") not in ("original",)
                ]
            except Exception:
                return []

        return await asyncio.wait_for(
            loop.run_in_executor(None, _twist),
            timeout=DNSTWIST_TIMEOUT,
        )
    except (asyncio.TimeoutError, Exception):
        return []


async def check_crtsh(keyword: str, domain_bases: List[str], original_domains: List[str]) -> List[Dict]:
    """Search crt.sh for SSL certs issued to lookalike domains."""
    if len(keyword) < 5:
        return []
    import httpx
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(
                f"https://crt.sh/?q=%25{keyword}%25&output=json",
                headers={"Accept": "application/json"},
            )
            if r.status_code != 200:
                return []
            data = r.json()
            seen: Set[str] = set()
            results = []
            legit = set(d.lower().lstrip("www.") for d in original_domains)
            for entry in data[:200]:
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lstrip("*.")
                    if not name or name in seen:
                        continue
                    seen.add(name)
                    if name in legit or any(name.endswith("." + d) for d in legit):
                        continue
                    fp = is_false_positive(name, original_domains, domain_bases, keyword)
                    if fp:
                        continue
                    results.append({
                        "domain": name,
                        "issuer": entry.get("issuer_name", ""),
                        "not_before": entry.get("not_before", ""),
                    })
                    if len(results) >= 10:
                        break
            return results
    except Exception:
        return []


async def run_brand_scan_for_client(
    client_id: int, client_name: str, country_code: str, industry: str,
    domains: List[str], es: Any,
) -> Dict[str, Any]:
    now = datetime.utcnow().isoformat()
    identity = extract_brand_identity(client_name, domains, industry)
    primary_domain = next((d for d in domains if not d.startswith("www.")), domains[0] if domains else "")
    primary_base = identity["domain_bases"][0] if identity["domain_bases"] else identity["primary_keyword"]

    results = {"typosquats": 0, "crt_hits": 0, "ioc_hits": 0, "cred_hits": 0, "dw_hits": 0, "findings_created": 0}

    monitor_id = hashlib.md5(f"client:{client_id}".encode()).hexdigest()
    await es.index(index="brand_monitors", id=monitor_id, document={
        "id": monitor_id, "client_id": client_id, "brand_name": identity["brand_name"],
        "primary_keyword": identity["primary_keyword"], "domains": domains,
        "keywords": identity["keywords"], "industry": industry,
        "country_code": country_code, "active": True, "scan_frequency_hours": 24,
        "last_scan_at": now, "updated_at": now, "typosquat_count": 0, "created_at": now,
    })

    async def upsert_alert(atype: str, sev: str, title: str, domain: str, details: Dict, sim: float = 0.0):
        aid = hashlib.md5(f"{client_id}:{atype}:{domain}:{title}".encode()).hexdigest()
        await es.index(index="brand_alerts", id=aid, document={
            "id": aid, "brand_id": monitor_id, "client_id": client_id,
            "brand_name": client_name, "country_code": country_code,
            "industry": industry, "alert_type": atype, "severity": sev,
            "title": title, "domain": domain, "similarity": round(sim * 100),
            "details": details, "detected_at": now, "acknowledged": False,
        })
        return aid

    async def create_finding(title: str, sev: str, category: str, desc: str, asset: str, rem: str, evidence: Dict):
        fid = hashlib.md5(f"{client_id}:{category}:{asset}:{title}".encode()).hexdigest()
        await es.index(index=f"asm_client_{client_id}_findings", id=fid, document={
            "id": fid, "client_id": client_id,
            "asset_id": hashlib.md5(asset.encode()).hexdigest(),
            "asset_value": asset, "asset_type": "domain", "category": category,
            "title": title, "severity": sev, "description": desc,
            "remediation": rem, "evidence": evidence, "status": "open",
            "source": "brand_protection", "first_seen": now, "last_seen": now,
            "cve_id": None, "cvss_score": None, "epss_score": None,
            "is_cisa_kev": False, "is_exploitable": False, "references": [],
        })
        results["findings_created"] += 1

    # ── 1. dnstwist — genuine character-level typosquats ──────────────────────
    if primary_domain and not identity["skip_tld_scan"]:
        for t in await run_dnstwist(primary_domain):
            variant = (t.get("domain") or "").lower()
            if not variant or variant == primary_domain:
                continue
            fp = is_false_positive(variant, domains, identity["domain_bases"], client_name)
            if fp:
                continue
            fuzzer = t.get("fuzzer", "unknown")
            has_mx = bool(t.get("dns_mx"))
            sev = "critical" if has_mx else "high"
            results["typosquats"] += 1
            await upsert_alert("typosquat_detected", sev,
                f"Typosquat: {variant} (impersonating {primary_domain})", variant,
                {"fuzzer": fuzzer, "dns_a": t.get("dns_a"), "dns_mx": t.get("dns_mx"),
                 "original_domain": primary_domain, "whois_registrar": t.get("whois_registrar")}, 0.88)
            await create_finding(
                f"Typosquat Detected: {variant}", sev, "brand_impersonation",
                f"Character-level typosquat of {primary_domain} found registered. "
                f"Technique: {fuzzer}. {'Has MX — may be used for phishing emails. ' if has_mx else ''}"
                f"DNS A: {t.get('dns_a','N/A')}.",
                variant,
                f"Submit takedown to registrar. Add to DNS blocklist. Alert customers.",
                t,
            )

    # ── 2. TLD permutation — only non-generic brands with real base > 4 chars ─
    if not identity["skip_tld_scan"] and len(primary_base) >= 4 and primary_base not in GENERIC_WORDS:
        # Build targeted candidate list: brand-base + suspicious combos + phishing TLDs
        candidates: List[str] = []
        for base in identity["domain_bases"]:
            if len(base) < 4 or base in GENERIC_WORDS:
                continue
            # Only generic + phishing TLDs (not other African ccTLDs)
            for tld in ["com", "net", "org", "info", "biz", "co", "app", "io", "online", "site",
                        "xyz", "digital", "pay", "finance", "bank", "money"] + list(PHISHING_TLDS):
                candidates.append(f"{base}.{tld}")
            # Combosquat variants with suspicious suffixes
            for suf in SUSPICIOUS_SUFFIXES[:6]:
                candidates.append(f"{base}{suf}.com")
                candidates.append(f"{base}-{suf}.com")

        # Exclude legitimate and duplicates
        legit_set = set(d.lower().lstrip("www.") for d in domains)
        candidates = list(set(c for c in candidates if c not in legit_set))

        # Resolve in parallel batches of 30
        loop = asyncio.get_event_loop()
        for i in range(0, min(len(candidates), 120), 30):
            batch = candidates[i:i+30]
            resolved_ips = await asyncio.gather(*[loop.run_in_executor(None, check_dns_resolves, d) for d in batch])
            for domain, ip in zip(batch, resolved_ips):
                if not ip:
                    continue
                fp = is_false_positive(domain, domains, identity["domain_bases"], client_name)
                if fp:
                    continue
                cand_parts = domain.split(".")
                tld = ".".join(cand_parts[1:])
                has_mx = False  # Would need MX lookup; skip for speed
                cand_base = cand_parts[0]
                # Check for suspicious suffix in base
                is_combo = any(suf in cand_base for suf in SUSPICIOUS_SUFFIXES)
                sev = severity_for_candidate(domain, has_mx, ip, tld)
                if tld in PHISHING_TLDS:
                    sev = "critical"
                elif is_combo:
                    sev = "high"
                else:
                    sev = "medium"

                sim = max(difflib.SequenceMatcher(None, b, cand_base).ratio() for b in identity["domain_bases"] if b)
                results["typosquats"] += 1
                await upsert_alert("domain_registered", sev,
                    f"Brand Squatting: {domain}", domain,
                    {"resolved_ip": ip, "original_domains": domains,
                     "is_combosquat": is_combo, "tld_type": "phishing" if tld in PHISHING_TLDS else "generic"}, sim)
                await create_finding(
                    f"Brand Domain Squatting: {domain}", sev, "brand_impersonation",
                    f"Domain {domain} (IP: {ip}) is registered and impersonates the {client_name} brand. "
                    f"{'Uses a phishing-associated TLD. ' if tld in PHISHING_TLDS else ''}"
                    f"{'Contains suspicious keyword suggesting fraud. ' if is_combo else ''}",
                    domain,
                    "Submit takedown request to registrar. Add to firewall blocklist. Alert customers.",
                    {"resolved_ip": ip, "domain": domain, "tld": tld},
                )

    # ── 3. Certificate Transparency ───────────────────────────────────────────
    if not identity["skip_tld_scan"] and len(identity["primary_keyword"]) >= 5:
        for hit in await check_crtsh(identity["primary_keyword"], identity["domain_bases"], domains):
            cert_domain = hit["domain"]
            results["crt_hits"] += 1
            await upsert_alert("ssl_certificate", "medium",
                f"SSL Cert Issued for Lookalike: {cert_domain}", cert_domain,
                {"issuer": hit.get("issuer"), "not_before": hit.get("not_before"),
                 "keyword_matched": identity["primary_keyword"]}, 0.6)
            await create_finding(
                f"Lookalike SSL Certificate: {cert_domain}", "medium", "brand_impersonation",
                f"An SSL cert was issued for {cert_domain} containing brand keyword '{identity['primary_keyword']}'. "
                f"Issuer: {hit.get('issuer', 'unknown')}. May indicate a phishing site.",
                cert_domain, "Report to CA for revocation if malicious.", hit,
            )

    # ── 4. IOC feed — specific brand names only, no generic words ────────────
    _GENERIC_IOC = {
        "orange", "telecom", "telkom", "openserve", "mobile", "airtel", "mtn",
        "vodacom", "standard", "first", "national", "bank",
    }
    try:
        specific_bases = [b for b in identity["domain_bases"] if len(b) >= 4 and b not in _GENERIC_IOC]
        bare_plain = [d.lstrip("www.") for d in domains if d]
        ioc_should = (
            [{"terms": {"indicator": bare_plain}}] +
            [{"wildcard": {"indicator": f"*{b}*"}} for b in specific_bases[:3]]
        )
        if ioc_should and specific_bases:
            resp = await es.search(index="iocs",
                query={"bool": {"should": ioc_should, "minimum_should_match": 1,
                                "filter": [{"term": {"active": True}}]}},
                size=50, _source=["indicator", "indicator_type", "threat_type", "source", "risk_score"])
            hits = [h["_source"] for h in resp["hits"]["hits"]
                    if not is_false_positive(h["_source"].get("indicator",""), domains, identity["domain_bases"], client_name)]
            results["ioc_hits"] = len(hits)
            # Group by threat_type → one brand_alert + one finding per type
            by_threat: Dict[str, list] = {}
            for src in hits:
                by_threat.setdefault(src.get("threat_type","unknown"), []).append(src)
            for threat_type, ioc_list in by_threat.items():
                worst = max(ioc_list, key=lambda x: float(x.get("risk_score", 0)))
                sev = "critical" if float(worst.get("risk_score", 0)) >= 80 else "high"
                await upsert_alert("ti_hit", sev,
                    f"Threat Intel: {len(ioc_list)} {threat_type} IOC(s) match {client_name}",
                    worst.get("indicator","")[:80],
                    {"count": len(ioc_list), "threat_type": threat_type,
                     "sample_indicator": worst.get("indicator"),
                     "source": worst.get("source"), "risk_score": worst.get("risk_score"),
                     "indicators": [h.get("indicator") for h in ioc_list[:10]]}, 0.9)
                await create_finding(
                    f"Threat Intel: {len(ioc_list)} {threat_type} IOC(s)", sev, "ti_hit",
                    f"{len(ioc_list)} active {threat_type} indicators matching {client_name} "
                    f"found in platform threat feed. Highest risk: {worst.get('indicator')} "
                    f"(score={worst.get('risk_score')}, source={worst.get('source')}).",
                    worst.get("indicator", primary_domain),
                    "Block at DNS/perimeter. Investigate internal connections. Alert customers.",
                    {"threat_type": threat_type, "count": len(ioc_list),
                     "indicators": [h.get("indicator") for h in ioc_list[:10]]},
                )
    except Exception:
        pass

    # ── 5. Credential exposures — per breach source ───────────────────────────
    try:
        bare_plain = [d.lstrip("www.") for d in domains if d]
        dom_should = [{"term": {"domain": d}} for d in bare_plain[:5]]
        if dom_should:
            count_resp = await es.count(index="credential_exposures",
                body={"query": {"bool": {"should": dom_should, "minimum_should_match": 1}}})
            total_creds = count_resp.get("count", 0)
            if total_creds > 0:
                results["cred_hits"] = total_creds
                agg_resp = await es.search(
                    index="credential_exposures",
                    query={"bool": {"should": dom_should, "minimum_should_match": 1}},
                    size=5, sort=[{"severity": "asc"}, {"breach_date": "desc"}],
                    _source=["email", "domain", "password_type", "source_name", "breach_date", "severity"],
                    aggs={
                        "by_source": {"terms": {"field": "source_name", "size": 20}},
                        "by_type":   {"terms": {"field": "password_type", "size": 10}},
                        "plaintext": {"filter": {"term": {"password_type": "plaintext"}}},
                    },
                )
                samples = [h["_source"] for h in agg_resp["hits"]["hits"]]
                aggs = agg_resp.get("aggregations", {})
                plaintext_count = aggs.get("plaintext", {}).get("doc_count", 0)
                by_source = {b["key"]: b["doc_count"] for b in aggs.get("by_source", {}).get("buckets", [])}
                by_type   = {b["key"]: b["doc_count"] for b in aggs.get("by_type",   {}).get("buckets", [])}
                has_plaintext = plaintext_count > 0
                sev = "critical" if (has_plaintext or total_creds > 100) else "high" if total_creds > 10 else "medium"
                # One summary brand_alert
                await upsert_alert("credential_leak", sev,
                    f"Credential Leak: {total_creds:,} records — {client_name}",
                    bare_plain[0] if bare_plain else client_name,
                    {"total_exposed": total_creds, "plaintext_count": plaintext_count,
                     "has_plaintext": has_plaintext, "by_source": by_source, "by_type": by_type,
                     "sample_emails": [s.get("email","") for s in samples[:3]],
                     "domains_checked": bare_plain}, 0.99)
                # One ASM finding per breach source
                for source_name, source_count in by_source.items():
                    await create_finding(
                        f"Credential Leak: {source_count:,} records from «{source_name}»",
                        sev, "credential_leak",
                        f"{source_count:,} credentials for {client_name} domains "
                        f"({'PLAINTEXT passwords — ' if has_plaintext else ''}"
                        f"found in '{source_name}'. "
                        f"Affected: {', '.join(bare_plain[:3])}. Total: {total_creds:,}.",
                        bare_plain[0] if bare_plain else client_name,
                        "Force password reset. Enable MFA. Notify users under POPIA/GDPR.",
                        {"source_name": source_name, "source_count": source_count,
                         "total_exposed": total_creds, "plaintext_count": plaintext_count,
                         "domains": bare_plain},
                    )
    except Exception:
        pass

    # ── 6. Dark web ───────────────────────────────────────────────────────────
    try:
        dw_should = []
        for b in identity["domain_bases"][:3]:
            if len(b) >= 4:
                dw_should.append({"match_phrase": {"body_text": b}})
        if dw_should:
            resp = await es.search(index="darkweb_posts",
                query={"bool": {"should": dw_should, "minimum_should_match": 1}}, size=5,
                _source=["url", "title", "body_text", "source", "severity", "discovered_at"])
            for h in resp["hits"]["hits"]:
                src = h["_source"]
                results["dw_hits"] += 1
                await create_finding(
                    f"Dark Web Mention: {str(src.get('title',''))[:60]}", src.get("severity", "high"),
                    "darkweb_mention",
                    f"{client_name} mentioned in dark web crawl. Source: {src.get('source')}. "
                    f"URL: {src.get('url','')}.",
                    src.get("url", "darkweb"),
                    "Review content. Engage IR if sensitive data is exposed.", src,
                )
    except Exception:
        pass

    # ── Update monitor typosquat count ─────────────────────────────────────────
    try:
        await es.update(index="brand_monitors", id=monitor_id,
            body={"doc": {"typosquat_count": results["typosquats"], "last_scan_at": now, "updated_at": now}})
    except Exception:
        pass

    return results


async def main():
    from app.services.elasticsearch import es_service
    await es_service.connect()
    es = es_service.client

    conn = psycopg2.connect(os.environ["DATABASE_URL"])
    cur = conn.cursor()
    cur.execute("""
        SELECT ac.id, ac.name, ac.country_code, ac.industry,
               array_agg(DISTINCT s->>'value') FILTER (WHERE s->>'value' IS NOT NULL)
        FROM asm_clients ac
        JOIN asm_discovery_groups ag ON ag.client_id = ac.id AND ag.is_active = TRUE
        CROSS JOIN LATERAL jsonb_array_elements(ag.seeds::jsonb) AS s
        WHERE s->>'type' = 'domain'
        GROUP BY ac.id, ac.name, ac.country_code, ac.industry ORDER BY ac.id
    """)
    clients = cur.fetchall()
    conn.close()

    total = len(clients)
    print(f"[brand_scan] {total} clients  batch={BATCH_SIZE}  delay={BATCH_DELAY}s", flush=True)

    grand = {"typosquats": 0, "crt": 0, "ioc": 0, "cred": 0, "dw": 0, "findings": 0}
    for i in range(0, total, BATCH_SIZE):
        batch = clients[i:i+BATCH_SIZE]
        bn = i // BATCH_SIZE + 1
        tb = (total + BATCH_SIZE - 1) // BATCH_SIZE
        print(f"\n[brand_scan] === Batch {bn}/{tb} ===", flush=True)
        for cid, name, cc, industry, domains in batch:
            domains = [d for d in (domains or []) if d]
            if not domains:
                print(f"  SKIP  id={cid:3d} {name}", flush=True)
                continue
            try:
                r = await run_brand_scan_for_client(cid, name, cc or "?", industry or "Unknown", domains, es)
                for k in grand:
                    grand[k] += r.get(k[:-1] if k.endswith("s") else k, 0) if k != "findings" else r.get("findings_created", 0)
                grand["crt"] += r.get("crt_hits", 0)
                grand["ioc"] += r.get("ioc_hits", 0)
                grand["cred"] += r.get("cred_hits", 0)
                grand["dw"] += r.get("dw_hits", 0)
                print(f"  DONE  id={cid:3d} {name:<40} typo={r['typosquats']:3d} "
                      f"crt={r['crt_hits']:2d} ioc={r['ioc_hits']:2d} cred={r['cred_hits']:4d} "
                      f"findings={r['findings_created']:3d}", flush=True)
            except Exception as e:
                print(f"  ERROR id={cid:3d} {name}: {e}", flush=True)
        if i + BATCH_SIZE < total:
            print(f"  sleeping {BATCH_DELAY}s...", flush=True)
            await asyncio.sleep(BATCH_DELAY)

    print(f"\n[brand_scan] COMPLETE — findings={grand['findings']}", flush=True)
    await es_service.close()

if __name__ == "__main__":
    asyncio.run(main())
