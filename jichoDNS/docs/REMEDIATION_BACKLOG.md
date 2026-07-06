# Remediation Backlog — deferred items from the 2026-07-06 audit

The `security-hardening` branch fixes the security, correctness, stability, and honesty
(fail-closed) defects that are safe to change without re-architecting or building new
features. The items below are **real findings** that are **features or large refactors**,
not point fixes — they are tracked here so they are not lost. Ordered by priority.

| # | Item | Why deferred | Severity | Rough effort |
|---|------|--------------|----------|--------------|
| 1 | **Implement or remove RIPE Atlas** (`atlas.py`) | Endpoints are TODO stubs returning empty/hardcoded data. Either build the Atlas client/scheduler or remove the endpoints + the feature claim + `RIPE_ATLAS_API_KEY` from "required" env. This branch takes the honest path (labels it not-implemented); building it is a feature. | high | 1–2 wks |
| 2 | **Real ML classification or accurate re-labeling** (`vertex_ai.py`, `dns_analysis.py`) | "Vertex AI ML C2/Exfil/Phishing detection" does not exist — it's a passthrough of upstream feed labels. This branch stops presenting mock AI output; building real inference (the entropy/DGA heuristics are a legit start) is a feature. | high | 2–4 wks |
| 3 | **Functional Africa threat-map choropleth** (`elasticsearch.py` region scoring, `regions.py`) | `get_region_scores()` / per-threat-type region risk are never computed. This branch fixes the silent-empty ES aggregation bug; making the full choropleth work end-to-end (persist per-threat-type region scores, wire the reader) is a feature build. | high | 1–2 wks |
| 4 | **Alembic migrations** | App relies on `create_all` which never ALTERs tables; the ownership fields added on this branch need a migration path. Introduce Alembic (already a dependency) and baseline the schema. | medium | 2–4 days |
| 5 | **Split god-file services into layers** (`attack_surface.py` 1832L, `asm_enterprise.py`, `brand_protection.py`, `darkweb.py`) | Fusing domain models + integration clients + orchestration + ES persistence is the primary reason the codebase is untestable. Extract models / per-provider integrations / repository / thin orchestrator. Big, mechanical, risky to do alongside security fixes. | medium | 1–2 wks |
| 6 | **Consolidate duplicated subsystems** | Two ASM engines (`attack_surface` + `asm_enterprise`, plus a dead `asm_service` singleton) and dark-web logic split across a service + `intel/` + two endpoint modules. Pick the authoritative path and delete the rest. | medium | 3–5 days |
| 7 | **Standardize API response envelope + pagination** | AGENTS.md mandates `{data, meta}` + cursor pagination; zero endpoints implement it and error semantics are mixed (HTTP 200 error-bodies vs 500). Sweep all endpoints to one contract. | medium | 3–5 days |
| 8 | **Token storage → httpOnly cookies** (`frontend/src/lib/auth.ts`) | JWTs in localStorage + a non-httpOnly cookie means any XSS = account takeover. The proper fix is server-set httpOnly cookies, which requires backend auth-flow changes (cookie issuance, CSRF). This branch removes the worst XSS *path* (report print) but the storage model change is a coordinated FE+BE feature. | high | 3–5 days |
| 9 | **Real dark-web / breach ingestion** | `darkweb` + credential data are entirely synthetic (`_generate_demo_*`). This branch gates the mock behind an explicit `ALLOW_MOCK_DATA` flag (off in prod); wiring real sources (HIBP/Intelligence X/Tor collectors) is a feature. | medium | 1–2 wks |
| 10 | **Settings persistence + notification backend** (`settings/page.tsx`, alerts) | UI actions are no-ops because the backend endpoints don't exist. This branch disables+labels the no-op controls; building real persistence is a feature. | medium | 3–5 days |

**Principle applied on this branch:** where a capability is advertised but not built, the
safe change is to **fail closed and tell the truth** (skip mock sources, label
not-implemented, gate demo data behind `ALLOW_MOCK_DATA=false` in prod) rather than ship
fabricated output. Building the real capability is tracked above.
