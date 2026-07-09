# JichoDNS — Final Data-Accuracy Audit

## 1. Executive summary

The raw threat-intelligence backbone is genuine: ~154,000 live IOCs importing in real time, a real WebSocket burst stream, real MaxMind GeoIP, deterministic DNS/DGA scoring, and correctly owner-scoped auth, watchlists, and reports. **But most of what a logged-in user actually *sees* is not trustworthy.** A single Elasticsearch `.keyword` mapping bug silently zeroes the portal dashboard, the alerts feed, generated reports, and the entire Dark Web Intel feed even though the data exists — and two whole corpora are pure fabrication: a **7,324-record "credential breach" index** and the professional-tier **`/darkweb/*` API**, both served as real intelligence. Net: the data *source* is real; roughly half the rendered *surfaces* are either broken-to-empty or synthetic. **Single biggest risk:** the fabricated credential corpus attributes plaintext-password breaches to real, named African banks, telcos, universities, and government agencies (Safaricom, NHIF, KRA, Standard Bank, Vodacom, University of Nairobi…) and mandates password resets for incidents that never happened — reputationally and legally exposing.

Tally: **1 critical, 13 high, 9 medium, 17 low**, plus **13 surfaces verified genuinely real**. Two prior "critical/high" calls were downgraded on live re-verification (darkweb API → high; Stripe placeholder-price → low — the real cause is an unconfigured, fail-closed Stripe integration, not a bad price ID).

## 2. Findings (ranked by severity)

| Severity | Feature | Classification | What the user sees | Fix | Risk |
|---|---|---|---|---|---|
| **Critical** | Credentials | fabricated | 7,324 "breach" rows for real orgs (M-Pesa, KRA, Std Bank…) — all synthetic (RNG name-permutation emails, sha256("123456")) | Purge `source=breach_database`; gate read path | risky |
| **High** | Credentials | misgated | `ALLOW_MOCK_DATA=false` only stops re-seeding; the fabricated corpus stays and read path is ungated | Delete synthetic docs + add prod guard to `search_credentials`/`credential_stats` | moderate |
| **High** | ASM | fabricated | Clients 122/127 shown CRITICAL "plaintext credential leak — reset now" for Std Bank/Vodacom (invented) | Suppress `darkweb://` findings; purge seed corpus | risky |
| **High** | Dark Web Monitoring | fabricated | `/darkweb/exposure/{email}` returns random `is_exposed:true` naming Collection1/LinkedIn for real employees | Gate `_generate_demo_exposure` behind `ALLOW_MOCK_DATA`; never emit synthetic `is_exposed:true` | moderate |
| **High** | Dark Web Monitoring | synthetic | `/darkweb/leaks|mentions|breaches|scan-pastes` serve random fake intel to paying tier (indices don't exist) | Gate all `_generate_demo_*` or unregister `/darkweb/*` router | moderate |
| **High** | Threat Map | broken | Flagship live map loads 0 IOCs (HTTP 422); "Waiting for threats…" over empty map | Fetch within public caps or reorder routes (see §4) | moderate |
| **High** | Threat Map | fabricated | "CN → Kenya" attacks; victim country is `Math.random()` over African list; "Top Targets" invented | Drop source→target framing / label illustrative; no RNG victim | moderate |
| **High** | Dashboard + `/indicators/stats` | broken | Risk score frozen at 40, empty threat-distribution chart, no IOC alerts, empty "Recent Alerts" — despite 154k IOCs | Drop `.keyword` in `public.py`+`get_stats()` (§4) | safe |
| **High** | Alerts feed | broken | "No alerts found — you're all caught up" on alerts page, bell, and dashboard despite 115k active malicious IOCs | Drop `.keyword` in `alerts_api.py` (§4) | moderate |
| **High** | Dark Web Intel | broken | Feed + all stat cards + Watch Alerts read 0 ("All clear") while 59k+ real IOCs match | Drop `.keyword` in `darkweb_intel.py` (§4) | moderate |
| **High** | ASM | broken | "Total Assets 9,796 / Open Ports 2,818" (real ~154/~34); same asset repeated up to 230× | Deterministic asset IDs + upsert + reindex/dedupe | moderate |
| **High** | Reports | broken | Every report: "No data available", "from 0 intelligence sources", High-Confidence 0 | Drop `.keyword` in `_fetch_ioc_stats` (§4) | moderate |
| **High** | Reports | broken | "Credential Exposures: 0" in every report (agg 400s, swallowed) vs 7,324 records | Use `password_type.keyword` in `_fetch_credential_stats` | moderate |
| **High** | Billing / Pricing | broken | Sells metered API keys, tiered limits, `X-RateLimit` headers — none exist; a user can't even mint a key | Implement key auth+metering or remove the claims | moderate |
| **Medium** | Threat Map | broken | `/regions/countries` + `/regions/map` always empty (missing `get_region_scores`) | Implement method or remove endpoints + docs | moderate |
| **Medium** | Dashboard | hardcoded | Trend badges "+12.5% / −8.3% / +5.2% / +3.1% vs last week" are constants (comment: "Could calculate…") | Compute from history or remove badges | safe |
| **Medium** | Search | broken | Universal search "Threat Indicators" returns 0 for `paypal`/keyword/substring; "OSINT" source 404s | Wildcard/prefix on keyword fields; drop dead `osint`/`indicator_text` | moderate |
| **Medium** | Landing | hardcoded | "12 feeds" (header/card) vs "15+" (pricing/demo/about); real = 14 registered, 10 healthy | Drive one value from `feed_health` | safe |
| **Medium** | Landing | fabricated | `/blog` invents C-suite authors, "97% accuracy", "50,000 campaigns", 97 fake articles (6 exist, all `#`) | Remove or label "Sample/coming-soon" | safe |
| **Medium** | ASM | stale | 64 mock-era services (`version 1.0.0`, null banner) mixed with real Dovecot/SMTP inventory | One-time purge of `version:1.0.0`+null-banner docs | moderate |
| **Medium** | Dark Web Intel | empty | "MISP Intel (AfISAC)" card + source filter advertised; 0 backing docs (no API key) | Wire real MISP feed or remove card/filter/subtitle | moderate |
| **Medium** | Reports | broken | "Dark Web Threats: 0" in every report vs 78,729 matching IOCs | Drop `.keyword` in `_fetch_darkweb_stats` (§4) | moderate |
| **Medium** | Billing / Pricing | hardcoded | Rate limits contradict: 1,000/mo vs 100/day vs stored 3,000/mo; per-min/burst unbacked | Pick one model; align copy+config+billing+signup default | safe |
| **Low** | Threat Map | synthetic | (latent) un-geolocated IOCs get a random country on the map | Bucket as "Unknown"; remove RNG fill | moderate |
| **Low** | Threat Map | real-inaccurate | C2/Phishing arc colors don't match legend (`/map`) | One shared `THREAT_COLORS` map | safe |
| **Low** | Indicators/Regions | broken | `/regions/countries|{code}|asns` are hardcoded empty/zero stubs (TODO) | Implement from ES aggs or remove + de-doc | moderate |
| **Low** | Indicators | real-inaccurate | "Africa's threats" but only 1.5% of geo IOCs are African (map is CN/NL/US) | Enrich African feeds or scope messaging | safe |
| **Low** | Landing | hardcoded | About + signup say "37,000+ indicators"; real = 154k (>4×) | Compute from `iocs_v2` or drop the number | safe |
| **Low** | Landing | fabricated | Careers: "team across 12 countries" + 5 roles; real = single operator | Remove unverifiable scale claim / only list open roles | safe |
| **Low** | Brand | synthetic | `/brand/typosquats` returns 192 never-registered variants of one test domain (orphaned) | Delete index or only persist registered lookalikes | moderate |
| **Low** | Brand | broken | All 153 brands show blank country/industry + telecom icon (even banks) — fields not stored | Backfill from `asm_clients`; unify monitor-creation schema | safe |
| **Low** | Dark Web Intel | real-inaccurate | "Dark Web Crawl" shows 8 ahmia.fi/intelx.io seed pages as high-severity forum posts | Skip seed pages; gate severity on extracted IOCs | moderate |
| **Low** | Credentials | broken | `/credentials/stats` agg 400s → silently returns mislabeled `iocs_phishing` (0) | Use `password_type.keyword` | safe |
| **Low** | Alerts | synthetic | (latent) synthesized alerts carry fake "2h/4h/6h ago" times + generic descriptions | Source timestamps from real IOC `created_at` / consume `/alerts/feed` | safe |
| **Low** | Reports | fabricated | Report card says "95 pages" for a single-scroll HTML doc | Drop `pages` field or compute at print | safe |
| **Low** | Reports | synthetic | "Sample Reports" tab renders 5 fake reports in prod (badged "Sample") | Gate `/samples` behind `ALLOW_MOCK_DATA`/demo flag | safe |
| **Low** | Account/Settings | hardcoded | Notification toggles pre-checked ON — no store, no email backend exists | Relabel coming-soon / drop ON states | safe |
| **Low** | Account | real-inaccurate | Pricing says free = 1,000/mo; real provisioned = 3,000/mo | Align signup default + model + billing + copy | safe |
| **Low** | Billing / Pricing | broken | "Upgrade to Pro" dead-ends (Stripe unconfigured → 503 "contact sales") | Disable button / route to /contact until Stripe wired | moderate |
| **Low** | Billing / Pricing | hardcoded | "Start Free Trial" CTA → plain free account, no trial exists | Add `trial_period_days` or relabel "Get Started" | safe |

## 3. Per-feature verdict (all 12)

1. **Live Threat Map + WebSocket — BROKEN.** Real IOC/WS data, but the flagship map loads 0 (422 route-shadow) and fabricates African victims via RNG.
2. **Indicators / Regions / Analysis / Search — MIXED.** DNS/DGA analysis is genuinely real; search is broken for keywords; regions endpoints are empty stubs; live feed is real but 98% non-African.
3. **Landing / marketing numbers — MIXED→SYNTHETIC.** Hero console is real; feed counts contradict; blog/careers fabricate authors, stats, and company scale.
4. **ASM — MIXED.** Multi-tenant scoping is sound and asset banners are real, but counts are inflated ~63×, credential findings are fabricated, and 64 mock services persist.
5. **Brand Protection — REAL (honest-empty).** 153 real, owner-scoped monitors; alerts genuinely empty (never scanned); metadata columns render blank; orphaned synthetic typosquat index.
6. **Dark Web Monitoring — SYNTHETIC.** The professional-tier `/darkweb/*` API fabricates leaks/mentions/breaches/per-person exposure verdicts, ungated.
7. **Dark Web Intel — BROKEN.** The real portal page is honest, but the feed/stats/watch-alerts read 0 due to `.keyword` mismap; MISP is a phantom source; crawl tab surfaces seed pages.
8. **Credentials / breach exposure — SYNTHETIC.** Redaction + scoping are correctly built, but 100% of the served corpus is fabricated and the read path is ungated.
9. **Alerts feed — BROKEN.** Feed returns 0 everywhere (mismap); trend/timestamps hardcoded; the sample-alert set is correctly gated off.
10. **Reports (in-app portal) — BROKEN.** Ownership scoping is correct; every breakdown (IOC/credential/dark-web) reads 0 and "pages" is fabricated.
11. **Intel Watchlists + Account/Auth — REAL.** `/auth/me`, tier display, and watchlists are genuine and scoped; only the notification toggles and free-tier quota copy mislead.
12. **Billing / Pricing — BROKEN.** Webhook signature verification is fail-closed and correct, but checkout is unconfigured, metered API access is vaporware, and rate-limit numbers contradict across pages.

**Verified genuinely real (no action):** underlying IOC index + WS stream, Hero console/map data, DNS/DGA analysis, ASM tenant isolation, brand monitors, dark-web portal page + crawler + watchlist scoping, credential redaction/scoping, alerts mock-gating, report ownership scoping, `/auth/me` + tier, watchlists, Stripe webhook signature verification.

## 4. Remediation plan

### Safe fixes — apply now (config / mapping / gating / copy)

**A. The `.keyword` mapping bug — one convention fix restores ~6 major surfaces.** On `iocs_v2`, `threat_type/source/country_code/indicator/indicator_type/severity` are already `keyword`-typed, so `.keyword` targets a non-existent sub-field and returns empty. **Remove `.keyword`** in:
- `backend/app/api/v1/endpoints/public.py:31-33` (threat_type, source, country_code)
- `backend/app/services/elasticsearch.py:352,357,360` (`get_stats`: threat_type, indicator_type, source, country_code)
- `backend/app/api/v1/endpoints/alerts_api.py:62,65,112,115` (threat_type, indicator, severity, email)
- `backend/app/api/v1/endpoints/darkweb_intel.py:43,45,50,51,56,58,59` + `90,92` + `153-156` + `361`
- `backend/app/services/report_generator.py:174-180` (`_fetch_ioc_stats`) + `207-211` (`_fetch_darkweb_stats`)

**Opposite direction** — on `credential_exposures`, `password_type` is `text` *with* a `.keyword` sub-field, so **add `.keyword`**:
- `backend/app/api/v1/endpoints/credentials.py:237` → `password_type.keyword`
- `backend/app/services/report_generator.py:240` → `password_type.keyword`

Add one smoke test asserting `/indicators/stats.by_threat_type`, `/alerts/feed`, `/darkweb-intel/stats`, and report breakdowns are non-empty when high-risk IOCs exist.

**B. Frontend hardcoded / marketing copy.**
- `frontend/src/app/portal/page.tsx:373-378` — remove/compute `trends:{iocs:12.5,alerts:-8.3,risk:5.2,assets:3.1}`; also fix the `Object.keys(by_threat_type).length` / `by_source` fallbacks at ~:370-372 that mislabel key-counts as "Active Alerts"/"Assets Monitored".
- Feed count: unify `Header.tsx:20` ("12 feeds"), `Features.tsx:28` ("12"), `Pricing.tsx:30` ("15+"), `DemoSection.tsx:84`, `about/page.tsx:41` → one `feed_health`-derived number (14 registered / 10 healthy).
- Indicator count: `about/page.tsx:41` + `signup/page.tsx:12` "37,000+" → compute from `iocs_v2` or drop.
- `blog/page.tsx` — remove fabricated authors/97-count/50k/97% or label "Sample".
- `careers/page.tsx:38,95-166` — drop "12 countries"; list only genuinely open roles.
- Threat colors: unify `THREAT_COLORS` across `RealThreatMap.tsx:13-14`, `ThreatMapLive.tsx:63-64`, `Hero.tsx:243`.
- `Pricing.tsx:37` — "Start Free Trial" → "Get Started".
- `settings/page.tsx:185-198` — relabel notification card coming-soon; drop pre-checked ON.
- `report_generator.py:145` — drop the fabricated `pages` metric (or compute at render).

**C. Gating / quota alignment.**
- Free-tier quota: align `auth.py:103` (3000) + `models/user.py:40` (3000) + `admin.py:251-252` (3000) with `billing.py:36` (1000) and pricing copy — pick one and reconcile the per-min/burst table in `docs/api/page.tsx`.
- Gate `/reports/samples` behind `ALLOW_MOCK_DATA` (currently ungated in prod).

### Moderate (code change — needs testing)
- **Threat map 422:** make `RealThreatMap.tsx:176` request within public caps (`limit≤500`, `since_minutes≤1440`) or give the map a dedicated higher-cap public endpoint / reorder routers in `api/v1/__init__.py`. Verify the replay pool animates end-to-end.
- **ASM inflation:** deterministic asset IDs (MD5 of client+type+value, mirroring `asm_enterprise.py:485`) + `doc_as_upsert`; one-time reindex/dedupe `asm_client_*_assets`; recompute PG `total_assets/open_ports`.
- **Darkweb `/darkweb/*` fabrication:** gate every `_generate_demo_*` behind `ALLOW_MOCK_DATA`, flip `endpoints/darkweb.py:152 include_demo` to the flag, and `_generate_demo_exposure` must never emit `is_exposed:true` — or simplest, unregister the `/darkweb/*` router (`api/v1/__init__.py:68-71`) since the real product is `/darkweb-intel/*`.
- Implement `get_region_scores` (or remove `/regions/*` stubs + docs); universal-search wildcard/prefix on keyword fields; MISP feed wiring or removal; crawl-doc filtering (skip seed hosts, gate severity on extracted IOCs).
- **Billing:** wire a real Stripe `price_...` + populate `STRIPE_SECRET_KEY`/`STRIPE_WEBHOOK_SECRET` (all empty in prod), or disable the Pro CTA; implement or remove the metered-API/rate-limit product.

### Risky (prod data purge — needs decision)
- **Purge the fabricated credential corpus:** `delete_by_query source=breach_database` on `credential_exposures` (all 7,324 docs, seeded 2026-07-06T22:23Z) **and** add an `is_production`/`ALLOW_MOCK_DATA` guard to `search_credentials`/`credential_stats` so the Credential Leaks tab shows empty, not fake, until a real feed exists. Remove `AFRICAN_BREACH_SEEDS` from prod images.
- **Suppress/purge ASM `credential_leak` findings** whose evidence `source_url` uses the `darkweb://` scheme (clients 122, 127) — they are downstream of the same fabricated corpus. Re-run correlation only against a genuine breach source.

## 5. Coverage gaps (from the completeness note)

- **Portal Dashboard (`/portal`)** — now substantially covered (trend deltas, frozen risk score, synthesized "Recent Alerts", empty feed are all findings above). **Residual, not yet a finding:** the fallback tiles `activeAlerts || Object.keys(by_threat_type).length` and `assetsMonitored || Object.keys(by_source).length` (`page.tsx:370-372`) silently relabel IOC key-counts as "Active Alerts"/"Assets Monitored" — and `by_source` is empty in prod, so "Assets Monitored" can collapse to 0. Fold into the mapping/hardcoded fixes.
- **Not audited — unbacked docs/marketing claims that should be verified before shipping:** `/api-docs` "Query over **100,000** indicators" (a third, different count vs "37,000+" and "154k"); `/docs` **"99.9% API Uptime SLA"**, **"SOC 2 Type II Certified"**, **"<4hr Response Time"** (compliance/reliability claims — confirm true or remove).
- **RIPE Atlas** — `atlas.py` now honestly returns HTTP 501, but `/docs` (`docs/page.tsx:105`) still advertises "RIPE Atlas integration provides real-time DNS measurements from African vantage points." Docs-vs-reality mismatch a customer can hit; remove or mark roadmap.
- **`/portal/settings` Access Control grid** (`settings/page.tsx:203-400`) — admin-only, real PG data, but the per-user Grant/Revoke grid doesn't reflect *current* access state (can misrepresent who sees what). Note: prod `asm_client_access` is missing `access_level/granted_by/granted_at` columns, so the grant/list admin paths will 500 (fails closed — no isolation risk, but a broken admin path).
- **`misp`, `admin`, `forms` routers** — uncovered but low-risk: `misp` fails honestly when unconfigured, `admin` has no frontend consumer, `forms` is write-only. Recommended spot-check: confirm prod has no MISP key so `/misp/search`/`/correlate` return empty rather than stale data.