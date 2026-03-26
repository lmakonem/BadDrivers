# JichoSec Platform — Master Planning Board

> Last updated: 2026-03-17  
> Status: Active Development

---

## Table of Contents

1. [Data Feed Inventory & Integration Design](#1-data-feed-inventory--integration-design)
2. [Data Quality Requirements](#2-data-quality-requirements)
3. [Master TODO List](#3-master-todo-list)
4. [Testing & Data Quality Tests](#4-testing--data-quality-tests)
5. [Backend Changes Required](#5-backend-changes-required)
6. [Frontend Changes Required](#6-frontend-changes-required)

---

## 1. Data Feed Inventory & Integration Design

### 1.1 Threat Intelligence Feeds

| Feed | Type | Format | Frequency | Auth | Status | Priority |
|------|------|--------|-----------|------|--------|----------|
| **URLhaus** (Abuse.ch) | Malware URLs | CSV/JSON | 5 min | None | ✅ Active | P0 |
| **SSL Blacklist** (Abuse.ch) | C2 SSL certs | CSV | 5 min | None | ✅ Active | P0 |
| **ThreatFox** (Abuse.ch) | IOCs (all types) | JSON API | 5 min | None | ✅ Active | P0 |
| **Feodo Tracker** (Abuse.ch) | Botnet C2 IPs | CSV/JSON | 5 min | None | ⚠️ Partial | P0 |
| **MalwareBazaar** (Abuse.ch) | Malware hashes | JSON API | 15 min | None | ❌ Missing | P0 |
| **PhishTank** | Phishing URLs | JSON | 1 hour | API key | ⚠️ Partial | P0 |
| **OpenPhish** | Phishing URLs | TXT | 1 hour | None | ⚠️ Partial | P1 |
| **AlienVault OTX** | Multi-type IOCs | JSON API | 15 min | API key | ⚠️ Partial | P1 |
| **Emerging Threats** | IDS rules + IPs | TXT | Daily | None | ❌ Missing | P1 |
| **MISP Feeds** | MISP format | JSON | Hourly | None | ❌ Missing | P1 |
| **Botvrij.eu** | Malicious domains/IPs | TXT | Daily | None | ❌ Missing | P2 |
| **CI Army** | Bad IPs | TXT | Daily | None | ❌ Missing | P2 |
| **Blocklist.de** | Attack IPs by category | TXT | Daily | None | ❌ Missing | P2 |
| **Spamhaus DROP** | Hijacked IP blocks | TXT | Daily | None | ❌ Missing | P2 |
| **Bambenek C2** | DGA C2 domains | TXT | Daily | None | ❌ Missing | P2 |

**Integration design for each:**
```
Importer base class (backend/app/importers/base.py)
  → fetch() — download from source URL
  → parse() — normalise to IOC schema
  → enrich() — add GeoIP, ASN, WHOIS
  → store() — bulk upsert to Elasticsearch iocs index
  → schedule() — Celery beat task every N minutes
```

**IOC Schema (Elasticsearch):**
```json
{
  "indicator":      "string (domain/ip/url/hash)",
  "indicator_type": "domain|ip|url|hash_md5|hash_sha1|hash_sha256",
  "threat_type":    "c2|malware|phishing|spam|scanner|dga",
  "source":         "urlhaus|sslbl|threatfox|...",
  "source_url":     "original feed URL",
  "malware":        "AsyncRAT|Mozi|Emotet|...",
  "country_code":   "KE|NG|ZA|...",
  "country":        "Kenya|Nigeria|...",
  "asn":            "AS12345",
  "asn_org":        "Safaricom PLC",
  "risk_score":     0-100,
  "confidence":     0-100,
  "tags":           ["africa", "financial", "c2"],
  "first_seen":     "ISO8601",
  "last_seen":      "ISO8601",
  "expires_at":     "ISO8601",
  "active":         true/false,
  "ttl_days":       30
}
```

---

### 1.2 Dark Web Monitoring Feeds

| Source | Type | Method | Auth | Status | Priority |
|--------|------|--------|------|--------|----------|
| **Have I Been Pwned API v3** | Email breach lookup | REST API | API key | ❌ Missing | P0 |
| **Dehashed** | Credential search | REST API | Paid key | ❌ Missing | P0 |
| **IntelX** (Intelligence X) | Paste/leak search | REST API | API key | ❌ Missing | P1 |
| **Flare.io** | Dark web monitoring | REST API | Paid | ❌ Missing | P1 |
| **Breachdetector** | Breach aggregation | REST API | Free | ❌ Missing | P1 |
| **Pastebin scraper** | Paste monitoring | Scrape | None | ❌ Missing | P2 |
| **Telegram monitoring** | Channel scraping | Bot API | Bot token | ❌ Missing | P2 |
| **Manual breach uploads** | Admin-uploaded dumps | File upload | Admin auth | ❌ Missing | P1 |

**Integration design:**
```
DarkWebMonitor service
  → schedule_hibp_check(domain) — check all emails for domain
  → ingest_breach_file(file)    — parse and index uploaded dump
  → scan_pastes(keywords)       — search pastes for org keywords
  → monitor_telegram(channels)  — Telegram Bot API listener
  → store → darkweb_leaks / darkweb_mentions / data_breaches indices
```

**Required API keys to obtain:**
- `HIBP_API_KEY` — https://haveibeenpwned.com/API/Key ($3.50/month)
- `DEHASHED_API_KEY` — https://dehashed.com/pricing
- `INTELX_API_KEY` — https://intelx.io/product
- `TELEGRAM_BOT_TOKEN` — @BotFather on Telegram

---

### 1.3 Brand Protection Feeds

| Source | Type | Method | Status | Priority |
|--------|------|--------|--------|----------|
| **DNSTwist** | Typosquat generation | Local binary | ✅ Active | P0 |
| **Certificate Transparency (crt.sh)** | New cert issuance | REST API | ⚠️ Partial | P0 |
| **WhoisXML API** | Domain registration | REST API | ❌ Missing | P1 |
| **DomainTools** | Domain WHOIS/history | REST API | ❌ Missing | P1 |
| **Google Safe Browsing** | Phishing verdict | REST API | API key | ❌ Missing | P1 |
| **VirusTotal URLs** | Phishing verdict | REST API | API key | ⚠️ Partial | P1 |
| **PhishCheck** | Phishing score | REST API | None | ❌ Missing | P2 |
| **Brand domain watchlist** | Manual list | Config | ⚠️ Partial | P0 |

**African brand watchlist to maintain:**
```
Mobile money:  M-Pesa, Airtel Money, MTN MoMo, Orange Money, EcoCash
Banks:         KCB, Equity Bank, Standard Bank, FNB, ABSA, Zenith, GTBank
Telcos:        Safaricom, MTN, Airtel, Glo, Vodacom, Econet, Telkom
E-commerce:    Jumia, Takealot, Konga, Kilimall
Fintech:       Flutterwave, Paystack, Chipper Cash, Wave
```

**Integration design:**
```
BrandProtectionService
  → run_dnstwist(domain)         — generate typosquats locally
  → monitor_crtsh(domain)        — poll crt.sh for new certs
  → check_whois(domain)          — WHOIS registration date/registrar
  → verify_phishing(url)         — GSB + VT verdict
  → score_risk(domain)           — composite risk score
  → alert_if_new(domain)         — create brand_alert if unseen
  → store → typosquat_domains / brand_alerts / brand_monitors
```

---

### 1.4 Attack Surface Management Feeds

| Source | Type | Method | Status | Priority |
|--------|------|--------|--------|----------|
| **Shodan** | Open ports, banners | REST API | ⚠️ Partial | P0 |
| **Censys** | TLS/device scan | REST API | API key | ❌ Missing | P1 |
| **Subfinder** | Subdomain enum | Local binary | ❌ Missing | P0 |
| **Amass** | Subdomain + ASN enum | Local binary | ❌ Missing | P0 |
| **crt.sh** | Cert subdomain enum | REST API | ⚠️ Partial | P0 |
| **NVD CVE API** | CVE data | REST API | None/key | ❌ Missing | P0 |
| **OSV (Google)** | Open source vulns | REST API | None | ❌ Missing | P1 |
| **Nuclei templates** | Active vuln scan | Local binary | ❌ Missing | P2 |
| **SSL Labs API** | SSL/TLS grading | REST API | None | ❌ Missing | P1 |

**Integration design:**
```
AttackSurfaceService
  → discover_subdomains(domain)  — crt.sh + amass + subfinder
  → scan_ports(ip)               — Shodan lookup (no active scan)
  → check_ssl(domain)            — SSL Labs + cert expiry
  → lookup_cves(cpe)             — NVD API CVE lookup
  → score_asset(asset)           — composite risk score
  → detect_changes()             — diff against last scan
  → store → assets / vulnerabilities indices
```

---

### 1.5 AI Threat Reports

| Component | Technology | Status | Priority |
|-----------|-----------|--------|----------|
| **Vertex AI (Gemini Pro)** | Report generation | ⚠️ Partial | P0 |
| **GCP Project** | Cloud credentials | ⚠️ Needs key | P0 |
| **Prompt templates** | Executive/Incident/IOC | ❌ Missing | P0 |
| **Report storage** | Elasticsearch | ⚠️ Index exists | P1 |
| **Scheduled weekly reports** | Celery beat | ❌ Missing | P1 |
| **Interactive chat (RAG)** | Gemini + ES context | ❌ Missing | P2 |

---

### 1.6 API & Integrations

| Integration | Type | Status | Priority |
|-------------|------|--------|----------|
| **Splunk Add-on** | Technology add-on | ❌ Missing | P1 |
| **Microsoft Sentinel connector** | Data connector | ❌ Missing | P1 |
| **IBM QRadar app** | DSM | ❌ Missing | P2 |
| **MISP feed export** | MISP JSON format | ❌ Missing | P1 |
| **STIX 2.1 export** | STIX/TAXII | ❌ Missing | P1 |
| **Webhook delivery** | Push notifications | ⚠️ Partial | P0 |
| **API rate limiting** | Redis token bucket | ❌ Missing | P0 |
| **API key management** | DB + hashing | ⚠️ Partial | P0 |

---

## 2. Data Quality Requirements

### 2.1 IOC Quality Standards

Each IOC stored must meet these quality gates:

| Field | Requirement | Validation |
|-------|------------|------------|
| `indicator` | Non-empty, valid format | Regex per type |
| `indicator_type` | One of 6 known types | Enum validation |
| `threat_type` | One of 7 known types | Enum validation |
| `source` | Known feed name | Allowlist |
| `first_seen` | Valid ISO8601, not future | Date parse + compare |
| `last_seen` | >= first_seen | Date comparison |
| `risk_score` | 0–100 integer | Range check |
| `confidence` | 0–100 integer | Range check |
| `active` | Boolean | Type check |
| `country_code` | ISO 3166-1 alpha-2 | Regex [A-Z]{2} |

### 2.2 Feed Freshness SLAs

| Feed | Max Acceptable Age | Alert Threshold |
|------|--------------------|-----------------|
| URLhaus | 15 min | 30 min |
| SSLBL | 15 min | 30 min |
| ThreatFox | 15 min | 30 min |
| Feodo Tracker | 30 min | 1 hour |
| PhishTank | 2 hours | 4 hours |
| AlienVault OTX | 1 hour | 2 hours |
| Dark web leaks | 24 hours | 48 hours |
| Brand typosquats | 6 hours | 12 hours |
| ASM assets | 24 hours | 48 hours |

### 2.3 Deduplication Rules

```
IOCs: deduplicate on (indicator + indicator_type) — upsert last_seen
Leaks: deduplicate on (email + breach_name) 
Typosquats: deduplicate on (typosquat_domain + original_domain)
Assets: deduplicate on (hostname + customer_id)
Vulns: deduplicate on (asset_id + cve_id) or (asset_id + title)
```

### 2.4 Enrichment Requirements

Every IOC must be enriched with:
- **GeoIP**: country, city, lat/lon (MaxMind GeoLite2 or ip-api.com)
- **ASN**: ASN number + org name (MaxMind or Shodan)
- **WHOIS**: registrar, registration date (for domains only)
- **Reverse DNS**: PTR record (for IPs only)
- **VirusTotal**: detection ratio (for high-confidence IOCs only)

---

## 3. Master TODO List

### 🔴 P0 — Critical (blocks core functionality)

#### Threat Intelligence
- [ ] **TI-01** Fix Feodo Tracker importer — currently returns empty (URL changed)
- [ ] **TI-02** Implement MalwareBazaar importer (`backend/app/importers/malwarebazaar.py`)
- [ ] **TI-03** Implement IOC TTL/expiry — mark stale IOCs `active=false` after N days
- [ ] **TI-04** Fix Celery beat schedule — importers not running on schedule (verify with `celery inspect active`)
- [ ] **TI-05** Add feed health monitoring — alert when a feed hasn't updated in > SLA window
- [ ] **TI-06** Implement deduplication — upsert by (indicator + indicator_type) not create-new
- [ ] **TI-07** Add GeoIP enrichment pipeline — every new IOC gets country_code + asn filled

#### Dark Web
- [ ] **DW-01** Integrate HIBP API — check all monitored domains' emails against HIBP
- [ ] **DW-02** Implement breach file ingestion — admin endpoint to upload credential dump CSVs
- [ ] **DW-03** Fix darkweb_leaks schema — `date_discovered` must be indexed as `date` type in ES

#### Brand Protection
- [ ] **BP-01** Complete crt.sh importer — currently only returns mock data
- [ ] **BP-02** Fix DNSTwist scheduler — not running periodically, only on-demand
- [ ] **BP-03** Add Google Safe Browsing API check for confirmed phishing domains
- [ ] **BP-04** Build African brand watchlist management — CRUD API for brand entries

#### ASM
- [ ] **ASM-01** Install Subfinder binary in Docker container — currently missing
- [ ] **ASM-02** Integrate NVD CVE API — replace mock vulnerability data with real CVEs
- [ ] **ASM-03** Fix `DiscoveryResult` object missing `total_ips` attribute (500 error on /asm/discover)

#### API
- [ ] **API-01** Implement Redis token-bucket rate limiting on all API endpoints
- [ ] **API-02** Complete API key authentication — currently bypassed in dev mode
- [ ] **API-03** Fix WebSocket `/api/v1/ws/iocs` — broadcasts ping but no real IOC events

### 🟠 P1 — High (important features)

#### Threat Intelligence
- [ ] **TI-08** Implement AlienVault OTX importer properly (currently skeleton)
- [ ] **TI-09** Implement Emerging Threats rules parser
- [ ] **TI-10** Add Botvrij.eu, CI Army, Blocklist.de importers
- [ ] **TI-11** Add MISP feed import/export capability
- [ ] **TI-12** Implement STIX 2.1 export endpoint
- [ ] **TI-13** Add bulk IOC lookup endpoint (up to 1000 indicators per request)

#### Dark Web
- [ ] **DW-04** Integrate IntelX API for paste/leak searching
- [ ] **DW-05** Build Telegram channel monitor for African cybercrime channels
- [ ] **DW-06** Implement dark web alert email notifications

#### Brand Protection
- [ ] **BP-05** Integrate WhoisXML API for domain registration dates
- [ ] **BP-06** Build takedown request workflow (generate abuse report emails)
- [ ] **BP-07** Implement similarity scoring — Levenshtein + visual homoglyph detection

#### ASM
- [ ] **ASM-04** Integrate Censys for passive scanning data
- [ ] **ASM-05** Implement SSL Labs API for TLS grading
- [ ] **ASM-06** Build asset change detection — diff scans, alert on new exposed services
- [ ] **ASM-07** Add CVE severity scoring — CVSS v3 from NVD

#### AI Reports
- [ ] **AI-01** Set up GCP project + service account for Vertex AI
- [ ] **AI-02** Build prompt template library (executive, incident, IOC, weekly)
- [ ] **AI-03** Implement scheduled weekly report generation via Celery beat
- [ ] **AI-04** Add report export as PDF and HTML

#### Integrations
- [ ] **INT-01** Build Splunk Technology Add-on (TA) for JichoSec IOC feed
- [ ] **INT-02** Build Microsoft Sentinel data connector
- [ ] **INT-03** Implement MISP feed endpoint (`/api/v1/misp/feed`)
- [ ] **INT-04** Build webhook delivery queue with retry logic

### 🟡 P2 — Medium (enhancements)

- [ ] **TI-14** Add Bambenek C2 domain feed
- [ ] **TI-15** Implement DGA detection ML model via Vertex AI
- [ ] **TI-16** Add RIPE Atlas active DNS measurement integration
- [ ] **DW-07** Pastebin scraper for credential monitoring
- [ ] **DW-08** Dark web market price tracking (ransomware groups)
- [ ] **BP-08** Social media impersonation detection (Twitter/X, Facebook)
- [ ] **ASM-08** Nuclei active vulnerability scanning (opt-in per asset)
- [ ] **ASM-09** Technology detection (Wappalyzer-style)
- [ ] **AI-05** Interactive threat chat (RAG against Elasticsearch)
- [ ] **INT-05** IBM QRadar DSM
- [ ] **INT-06** Elastic Security integration (ECS-formatted events)

---

## 4. Testing & Data Quality Tests

### 4.1 Feed Health Tests

Run these checks every 15 minutes via Celery beat:

```python
# backend/app/tests/test_feed_health.py

def test_urlhaus_freshness():
    """URLhaus must have IOCs added in last 30 minutes"""
    latest = es.search(index="iocs", query={"term": {"source": "urlhaus"}},
                       sort=[{"first_seen": "desc"}], size=1)
    age = datetime.utcnow() - parse(latest[0]["first_seen"])
    assert age.seconds < 1800, f"URLhaus stale: last IOC {age} ago"

def test_sslbl_freshness():
    latest = es.search(index="iocs", query={"term": {"source": "sslbl"}}, ...)
    assert age.seconds < 1800

def test_ioc_count_floor():
    """Total active IOCs must never drop below 30,000"""
    count = es.count(index="iocs", query={"term": {"active": True}})
    assert count >= 30000, f"IOC count dropped to {count}"

def test_no_duplicate_iocs():
    """Check deduplication — no two docs with same indicator+type"""
    result = es.search(index="iocs", aggs={
        "dups": {"terms": {"field": "indicator", "min_doc_count": 2, "size": 10}}
    })
    assert len(result["dups"]["buckets"]) == 0

def test_all_iocs_have_country():
    """All IOCs must have country_code set"""
    missing = es.count(index="iocs", query={"bool": {"must_not": {"exists": {"field": "country_code"}}}})
    assert missing == 0, f"{missing} IOCs missing country_code"

def test_risk_score_range():
    """All risk scores must be 0-100"""
    invalid = es.count(index="iocs", query={"bool": {"should": [
        {"range": {"risk_score": {"lt": 0}}},
        {"range": {"risk_score": {"gt": 100}}}
    ]}})
    assert invalid == 0
```

### 4.2 Data Schema Tests

```python
# backend/app/tests/test_data_schema.py

def test_ioc_schema_required_fields():
    """Sample 100 IOCs and verify all required fields present"""
    sample = es.search(index="iocs", size=100)
    required = ["indicator", "indicator_type", "threat_type", "source", "first_seen", "active"]
    for ioc in sample:
        for field in required:
            assert field in ioc, f"IOC {ioc.get('indicator')} missing {field}"

def test_indicator_type_valid():
    valid_types = {"domain","ip","url","hash_md5","hash_sha1","hash_sha256"}
    sample = es.search(index="iocs", size=500)
    for ioc in sample:
        assert ioc["indicator_type"] in valid_types

def test_country_code_format():
    """country_code must be 2-letter ISO"""
    import re
    sample = es.search(index="iocs", query={"exists": {"field": "country_code"}}, size=500)
    for ioc in sample:
        assert re.match(r'^[A-Z]{2}$', ioc["country_code"]), f"Bad country_code: {ioc['country_code']}"

def test_darkweb_leaks_schema():
    required = ["affected_domain", "severity", "date_discovered"]
    sample = es.search(index="darkweb_leaks", size=50)
    for doc in sample:
        for field in required:
            assert field in doc

def test_typosquat_domains_schema():
    required = ["typosquat_domain", "original_domain", "brand_name", "technique", "risk_score"]
    sample = es.search(index="typosquat_domains", size=50)
    for doc in sample:
        for field in required:
            assert field in doc

def test_assets_schema():
    required = ["asset_value", "asset_type", "status", "created_at"]
    sample = es.search(index="assets", size=50)
    for doc in sample:
        for field in required:
            assert field in doc
```

### 4.3 API Integration Tests

```python
# backend/app/tests/test_api.py

def test_indicators_stats_returns_nonzero():
    r = client.get("/api/v1/indicators/stats")
    assert r.status_code == 200
    data = r.json()
    assert data["total"] > 0
    assert "by_threat_type" in data
    assert data["by_threat_type"]["malware"] > 0

def test_domain_analysis():
    r = client.post("/api/v1/analysis/domain", json={"domain": "asyncrat-c2.duckdns.org"})
    assert r.status_code == 200
    data = r.json()
    assert data["risk_score"] > 50  # known bad domain

def test_indicators_lookup_known_bad():
    r = client.get("/api/v1/indicators/lookup/185.220.101.47")
    assert r.status_code == 200
    data = r.json()
    assert data.get("found") == True
    assert data["threat_type"] in ["c2", "malware"]

def test_darkweb_stats_returns_data():
    r = client.get("/api/v1/darkweb/stats")
    assert r.status_code == 200
    data = r.json()
    assert data["total_leaks"] > 0

def test_brand_stats_returns_data():
    r = client.get("/api/v1/brand/stats")
    assert r.status_code == 200

def test_asm_stats_returns_data():
    r = client.get("/api/v1/asm/stats")
    assert r.status_code == 200
    data = r.json()
    assert data["total_assets"] > 0

def test_websocket_connects():
    with client.websocket_connect("/api/v1/ws/iocs") as ws:
        data = ws.receive_json()
        assert data["type"] in ["ping", "new_iocs", "connected"]

def test_rate_limiting():
    """Unauthenticated requests must be rate limited after 100 req/min"""
    responses = [client.get("/api/v1/indicators/stats") for _ in range(110)]
    assert any(r.status_code == 429 for r in responses[-10:])
```

### 4.4 Frontend Data Display Tests

Manual checklist to verify after each deployment:

```
Portal Dashboard
  [ ] Total IOC count matches /api/v1/indicators/stats
  [ ] Threat distribution chart shows malware/c2/phishing
  [ ] Recent indicators table loads within 3 seconds
  [ ] Auto-refresh works every 5 minutes

Dark Web Dashboard
  [ ] Leak count matches /api/v1/darkweb/stats
  [ ] Severity breakdown shows critical/high/medium/low
  [ ] Recent leaks table shows real data (not mock)

ASM Dashboard
  [ ] Asset count > 0
  [ ] Vulnerability list shows CVE IDs
  [ ] Discovery form calls /api/v1/asm/discover

Brand Protection
  [ ] Typosquat count > 0
  [ ] Phishing site count shown
  [ ] Add brand form calls /api/v1/brand/monitor

Landing Page
  [ ] Map loads within 5 seconds
  [ ] Live console shows events within 10 seconds
  [ ] All 6 module links go to correct portal pages
```

### 4.5 Continuous Monitoring Checks

Set up these as Kibana Watcher alerts or Celery beat tasks:

| Check | Frequency | Alert Condition |
|-------|-----------|-----------------|
| Feed freshness | 15 min | Any feed > 2x SLA age |
| IOC count floor | 1 hour | Total IOCs < 30,000 |
| API error rate | 5 min | Error rate > 5% |
| ES disk space | 1 hour | Disk > 80% |
| Container health | 2 min | Any container not healthy |
| WebSocket uptime | 5 min | WS endpoint unreachable |

---

## 5. Backend Changes Required

### 5.1 New Files to Create

```
backend/app/importers/
  ├── malwarebazaar.py      # Abuse.ch MalwareBazaar hash feed
  ├── emerging_threats.py   # ET open rules + IP list
  ├── bambenek.py           # Bambenek C2 domains
  ├── botvrij.py            # Botvrij domain + IP feeds
  ├── ci_army.py            # CI Army bad IP list
  ├── blocklist_de.py       # Blocklist.de per-category IPs
  ├── spamhaus.py           # Spamhaus DROP/EDROP
  └── misp_feed.py          # Generic MISP feed importer

backend/app/services/
  ├── hibp.py               # Have I Been Pwned integration
  ├── intelx.py             # Intelligence X API
  ├── nvd.py                # NVD CVE API client
  ├── whoisxml.py           # WhoisXML domain intelligence
  ├── gsb.py                # Google Safe Browsing API
  ├── feed_monitor.py       # Feed health & freshness monitor
  └── enrichment.py         # Unified enrichment pipeline (GeoIP+ASN+WHOIS)

backend/app/api/v1/endpoints/
  ├── misp.py               # MISP feed export endpoint
  ├── stix.py               # STIX 2.1 export endpoint
  └── webhooks.py           # Webhook delivery management

backend/app/tests/
  ├── test_feed_health.py   # Feed freshness + count tests
  ├── test_data_schema.py   # Schema validation tests
  ├── test_api.py           # API integration tests
  └── conftest.py           # Shared fixtures
```

### 5.2 Files to Modify

| File | Change |
|------|--------|
| `backend/app/worker.py` | Add beat schedules for all new importers |
| `backend/app/importers/abusech.py` | Fix Feodo Tracker URL, add MalwareBazaar |
| `backend/app/importers/base.py` | Add deduplication logic (upsert vs insert) |
| `backend/app/services/elasticsearch.py` | Add `upsert_ioc()` method, fix index mappings |
| `backend/app/services/brand_protection.py` | Fix crt.sh integration, add WHOIS lookup |
| `backend/app/services/attack_surface.py` | Fix `DiscoveryResult.total_ips`, add NVD CVE |
| `backend/app/services/darkweb.py` | Add HIBP integration, fix date field mapping |
| `backend/app/core/config.py` | Add new API key env vars (HIBP, IntelX, etc.) |
| `backend/app/api/v1/endpoints/asm.py` | Fix 500 on /discover endpoint |
| `backend/app/api/v1/endpoints/brand.py` | Fix stats endpoint, add bulk typosquat check |
| `backend/app/main.py` | Add rate limiting middleware |

### 5.3 Database / Index Changes

```python
# Elasticsearch index mapping updates needed:

# iocs — add missing fields
"expires_at":    {"type": "date"},
"ttl_days":      {"type": "integer"},
"asn":           {"type": "keyword"},
"asn_org":       {"type": "keyword"},
"malware":       {"type": "keyword"},
"confidence":    {"type": "integer"},

# darkweb_leaks — fix date field
"date_discovered": {"type": "date"},   # was missing date type

# New index: feed_health
{
    "feed_name":    {"type": "keyword"},
    "last_success": {"type": "date"},
    "last_error":   {"type": "date"},
    "ioc_count":    {"type": "long"},
    "status":       {"type": "keyword"}  # healthy|stale|error
}
```

### 5.4 Environment Variables to Add

```bash
# .env.example additions
HIBP_API_KEY=               # Have I Been Pwned
INTELX_API_KEY=             # Intelligence X
WHOISXML_API_KEY=           # WhoisXML
GOOGLE_SAFE_BROWSING_KEY=   # Google Safe Browsing
DEHASHED_API_KEY=           # Dehashed
TELEGRAM_BOT_TOKEN=         # Telegram monitoring bot
CENSYS_API_ID=              # Censys
CENSYS_API_SECRET=          # Censys
NVD_API_KEY=                # NVD (optional, higher rate limit)
WEBHOOK_SIGNING_SECRET=     # Outbound webhook HMAC secret
```

---

## 6. Frontend Changes Required

### 6.1 Portal Dashboard (`portal/page.tsx`)
- [ ] Connect threat distribution chart to real API (currently uses computed data)
- [ ] Add feed health status panel — show which feeds are stale
- [ ] Add IOC trend chart (last 7/30 days) — needs new API endpoint
- [ ] Add top attacked countries table with flag icons
- [ ] Add MITRE ATT&CK technique mapping panel

### 6.2 Dark Web Dashboard (`portal/darkweb/page.tsx`)
- [ ] Add email domain exposure check form — calls `/api/v1/darkweb/exposure/{email}`
- [ ] Add breach timeline chart (area chart by date_discovered)
- [ ] Show real leaked record counts from API (currently falls back to mock)
- [ ] Add Telegram mention stream panel
- [ ] Add breach severity heatmap by month

### 6.3 Brand Protection Dashboard (`portal/brand/page.tsx`)
- [ ] Add domain input → live typosquat check on submit
- [ ] Add similarity score visual (gauge per typosquat)
- [ ] Add certificate transparency log timeline
- [ ] Link "Take action" button to actual takedown request API
- [ ] Add African brand quick-add buttons (M-Pesa, Safaricom, etc.)

### 6.4 ASM Dashboard (`portal/asm/page.tsx`)
- [ ] Fix discovery form — handle 500 error on submit gracefully
- [ ] Add CVE detail panel (clicking a vuln shows full NVD description)
- [ ] Add asset timeline chart (new assets discovered over time)
- [ ] Add port/service heatmap across all assets
- [ ] Add SSL certificate expiry countdown per asset

### 6.5 Reports Dashboard (`portal/reports/page.tsx`)
- [ ] Connect to Vertex AI API — real report generation
- [ ] Add report type selector (Executive / Incident / IOC / Weekly)
- [ ] Add PDF download button for generated reports
- [ ] Add report history list with search/filter
- [ ] Add AI chat interface for threat Q&A

### 6.6 New Pages Needed
- [ ] `/portal/alerts` — unify all alerts (dark web + brand + ASM + TI) in one feed
- [ ] `/portal/settings` — API key management, webhook config, notification prefs
- [ ] `/portal/feeds` — feed health dashboard (importer status, last run, IOC counts)
- [ ] `/analysis` — standalone domain/IP/URL/hash lookup (public, no auth required)

### 6.7 Global Frontend Issues
- [ ] Add proper authentication flow — login/logout, session management, JWT
- [ ] Add loading skeletons instead of "Loading..." text on all portal pages
- [ ] Add empty state illustrations when indices have no data
- [ ] Make all tables sortable and searchable
- [ ] Add CSV/JSON export button to all data tables
- [ ] Fix mobile layout on portal pages (currently broken below 768px)
- [ ] Add dark mode toggle (currently forced dark)
- [ ] Add proper error boundaries with fallback UI

---

## Priority Matrix Summary

```
                  HIGH IMPACT   LOW IMPACT
QUICK WIN    |  Feed fixes     |  UI polish    |
             |  API rate limit |  Dark mode    |
─────────────┼─────────────────┼───────────────┤
BIG BET      |  HIBP/IntelX    |  QRadar DSM   |
             |  NVD CVEs       |  Nuclei scans |
             |  Vertex AI      |               |
```

**Immediate focus (Sprint 1 — 2 weeks):**
1. TI-01 Fix Feodo Tracker
2. TI-03 IOC TTL/expiry
3. TI-04 Fix Celery beat schedule
4. TI-07 GeoIP enrichment
5. ASM-03 Fix /asm/discover 500 error
6. API-01 Rate limiting
7. API-03 Fix WebSocket real events
8. DW-01 HIBP integration
9. BP-01 Complete crt.sh importer
10. AI-01 GCP setup for Vertex AI
