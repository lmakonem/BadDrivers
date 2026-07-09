# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

JichoDNS ("jicho" = "eye" in Swahili) is an Africa-focused DNS threat-intelligence platform: a FastAPI backend that aggregates ~12 free threat feeds into Elasticsearch, a Celery worker/beat fleet that runs the imports, and a Next.js 14 frontend with a live attack-arc threat map plus a customer portal (ASM, brand protection, dark-web intel, reports).

`AGENTS.md` predates most of the code — it still marks the frontend, models, and importers as "to be added" though all exist. Trust the tree and this file over `AGENTS.md` for structure; `AGENTS.md` remains useful for code-style conventions and the Africa-specific domain notes. Several advertised features are genuinely *planned, not built*: RIPE Atlas (`/api/v1/atlas/*` → 501), ML/Vertex scoring (reports are deterministic ES-aggregation HTML), and paid API-key issuance/metering (auth is JWT-only). See `docs/REMEDIATION_BACKLOG.md`.

## Repo-root gotcha

The git root is the **parent** `~/repos`, not `~/repos/jichoDNS` — `git rev-parse --show-toplevel` returns `/Users/lmakonem/repos`. Run branch/commit/status scoped to this subtree (e.g. `git add jichoDNS/…`). The active branch is `security-hardening`.

## Commands

All backend commands run from `backend/`:

```bash
# Full local stack (postgres, clickhouse, redis, api, worker, scheduler, frontend)
docker-compose up -d          # from repo root; API :8000, frontend :3000
docker-compose exec api alembic upgrade head   # migrations

# Tests (pytest-asyncio auto mode — no per-test decorator needed)
cd backend && pytest
pytest tests/test_security.py -v      # single file
pytest -k webhook                     # single test by keyword

# Lint (ruff — deliberately a minimal *blocking* baseline: only E9/F63/F7/F82)
cd backend && ruff check .

# Run API / workers outside Docker
uvicorn app.main:app --reload
celery -A app.worker worker --loglevel=info --concurrency=4
celery -A app.worker beat --loglevel=info     # the periodic-import scheduler

# Bootstrap an admin user
python backend/create_admin.py

# Frontend (from frontend/)
npm run dev | build | lint
```

**Elasticsearch and Kibana are NOT in `docker-compose.yml`** — they run externally (on the DB host in prod). Point `ELASTICSEARCH_URL` at a reachable ES 8.x or most of the platform is inert. This surprises people; the compose stack alone will boot but return empty IOC data.

## Architecture — the load-bearing parts

**One `backend/app` package, three process roles.** The same code runs as (1) the FastAPI API (`app.main:app`), (2) Celery workers, and (3) Celery beat. They share models, config, and services but differ in one critical way below.

**Dual DB-engine pattern (do not break this).** `app/core/database.py` builds a *pooled* async engine for the API (one long-lived uvicorn event loop) but a *NullPool* engine for Celery. Each Celery task runs in a fresh event loop via `run_async()` in `app/worker.py`; a pooled asyncpg connection is bound to the loop that created it, so reusing it from a later task's loop raises "got Future attached to a different loop". `configure_for_worker()` rebinds the module-level `engine`/`async_session_maker` to NullPool, called once per worker child from the `worker_process_init` signal. Worker tasks therefore import `async_session_maker` *lazily inside the task body* so they pick up the rebind — keep that pattern.

**Feeds → ES → live map.** Importers in `app/importers/` (URLhaus, ThreatFox, Feodo, SSLBL+JA3, MalwareBazaar, OpenPhish, PhishTank, AbuseIPDB, AlienVault OTX, crt.sh, DNSTwist, MISP) all subclass `base.py` and flow through `_generic_import()` in `worker.py`: fetch → `es_service.store_indicators()` → `feed_monitor.record_run()` → `publish_new_iocs()`. That last call publishes geo-enriched IOCs to the Redis channel `jichodns:iocs:new`, which the WebSocket endpoint fans out to the browser threat map. Feed health is recorded from the *storage* outcome, not the fetch outcome. Beat schedule (frequency per feed) lives in `worker.py`.

**Datastore split:** Elasticsearch (index `iocs`, also `dns_queries`, `threat_reports`, `brand_monitors`, `darkweb_posts`, `credential_exposures`, feed-health) is the real workhorse and IOC store. PostgreSQL holds relational/tenant data (`users`, `api_keys`, ASM clients/groups/findings, watchlists, form submissions). Redis is the Celery broker/result backend *and* the WebSocket pub/sub bus. ClickHouse is provisioned but lightly used.

**API router auth tiers** (`app/api/v1/__init__.py` is the map): endpoints are grouped as public (`auth`, `forms`, `public` map data, `billing` webhook, `websocket`), JWT-required (`indicators`, `regions`, `analysis`, `reports`, `search`, `alerts`, `misp`, `admin`, `atlas`), and tier-gated via `require_tier(...)` in `app/api/deps.py` — `darkweb`/`brand`/`intel`/`darkweb-intel` need **professional**, `asm` needs **enterprise**. Admins bypass tier gates. When adding an endpoint, wire its auth level here, not just in the endpoint.

**ASM subsystem.** `ASMEnterpriseService.run_full_scan` (`services/asm_enterprise.py`, orchestrated by the `run_asm_discovery` Celery task) does subdomain/IP/port/SSL discovery → HTTP fingerprint → TI correlation against the live `iocs` index → CVE enrichment (EPSS + CISA KEV) → risk grade → webhook alerts. `asm_scheduled_rescan` runs every 30 min and dispatches any client whose `next_scan_at` has elapsed (interval set per client via `scan_interval_minutes`; `0` = manual only).

**Client reports (`reports/`) are a separate pipeline from the app.** `_scan_driver.py` runs *inside the jichodns-api container* to reuse the ASM engine and network position, emitting one JSON blob. `build_report.py <body.md> <meta.json> <out.pdf>` renders house-style PDFs via `weasyprint` + `report.css` (needs weasyprint system libs). These PDFs are shipped to real clients (Congolese gov tax/customs authorities — DGI, DGDA, etc.).

## Security posture (this is the `security-hardening` branch's whole point)

- **`config.py` fails closed in production.** With `ENVIRONMENT=production`, a missing/placeholder `SECRET_KEY` or a `STRIPE_SECRET_KEY` without `STRIPE_WEBHOOK_SECRET` raises at startup. Dev/test backfills a placeholder so the app boots with no `.env`.
- **`ALLOW_MOCK_DATA` must stay `False` in prod.** When False, any ASM/intel source lacking a real API key returns *empty*, never fabricated assets/findings/report text — because that output feeds real client PDFs. The ASM engine has historically fabricated subdomains; verify before shipping.
- **`core/net_guard.py`** is the SSRF guard: resolve every A/AAAA answer, block loopback/RFC1918/link-local (incl. `169.254.169.254` IMDS)/reserved, fail closed on mixed public/private (rebinding), collapse IPv4-mapped/6to4/Teredo. Use `assert_public_url()` / `resolve_public_ips()` before any server-side fetch or scan of user input. On-demand scans are also rate-capped (`ASM_SCAN_RATE_*`) as an anti-proxy backstop.
- **`core/ownership.py`** enforces multi-tenancy: `get_owned_domains()` scopes the global credential/breach corpus to a user's watchlist + ASM-client domains, and `redact_credential(s)()` strips `password`/`password_hash` from every read path. Reports/brand monitors carry `owner_user_id` and are filtered inline in their endpoints.
- **OpenAPI docs are gated** — `docs_url`/`openapi_url` are off by default; `/docs`, `/redoc`, `/openapi.json` require a valid bearer token or admin session (`_has_auth` in `main.py`).
- JWTs are HS256 signed with `SECRET_KEY` (`SESSION_SECRET_KEY` separate for the sqladmin cookie); login runs `dummy_verify()` on the no-user path to equalize timing against enumeration.

## Production topology

Not the stale `.50/.51` IPs in `AGENTS.md`. Current prod is VM **119 `jichodns01`** on Proxmox `ludus01` (192.168.38.195), reached via DNAT (`:3030`→frontend, `:8030`→API, `:22311`→SSH) because ludus01 has no LAN bridge, and exposed publicly through a Cloudflare named tunnel at `jichosec.defendanddetect.com`. Full runbook: `docs/DEPLOYMENT_PROXMOX.md`. Deploy automation lives in `ansible/` (`site.yml`, roles: common/docker/database/app/intel) and `.github/workflows/deploy.yml`. Secret rotation: `docs/SECRET_ROTATION_RUNBOOK.md`.
