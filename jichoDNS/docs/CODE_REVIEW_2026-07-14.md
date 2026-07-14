# Code & Platform Review — 2026-07-14

Deep review of the `security-hardening` branch across four fronts (backend
security, backend correctness, frontend, infra) plus a live platform-health
check. This records what was **fixed** and what remains as **backlog** with a
recommended path. Fixes were deployed to prod (VM 119) and the full backend
suite (80 tests) is green.

## Fixed & deployed

| # | Severity | Area | Issue | Fix |
|---|----------|------|-------|-----|
| 1 | HIGH | Backend / XSS | Report `title`/`custom_prompt` interpolated raw into report HTML served as `text/html`; admins bypass owner scoping → stored XSS in the report/admin origin. | HTML-escape both at the single choke point (`report_generator._build_result`) + serve report HTML with a no-JS CSP (`default-src 'none'`), `nosniff`, `X-Frame-Options: DENY` (`reports.py`). |
| 2 | HIGH | Backend / SSRF | ASM `send_webhook` posted to a tenant-supplied URL with no `net_guard` — blind SSRF into the metadata/RFC1918 plane, also via the 30-min scheduled rescan. | `assert_public_url()` inside `send_webhook` (+ `follow_redirects=False`), and a `field_validator` on `ClientCreate`/`ClientUpdate` rejecting unsafe URLs with 422 at write time. |
| 3 | HIGH | Infra | No `restart:` policy on any of the 7 prod containers — a reboot/OOM left prod down until manual SSH. | `restart: unless-stopped` in compose + applied live zero-downtime via `docker update`. |
| 4 | HIGH | Frontend | Admin access-control actions used `apiFetchJSON` (never throws) so `catch` was dead — "Access granted/revoked" shown even on 403/500. | Switched the four mutations to `apiFetchJSONOrThrow`; refetch authoritative access list after each. |
| 5 | MED-HIGH | Frontend | Any transient `/refresh` failure (5xx/tunnel hiccup/network) cleared tokens → spurious logout mid-work; concurrent 401s raced competing refreshes. | `refreshAccessToken` clears only on definitive 401/403; single-flight shared promise; `apiFetch` bounces to `/login?next=` only when the session was truly invalidated. |
| 6 | MEDIUM | Backend / correctness | `_import_misp` recorded feed health `success=True` and fanned docs to the live map even when ES was down / nothing stored. | Derive success from `success_count`; skip publish + record error when storage failed. |
| 7 | MEDIUM | Backend / MITM | `MISP_VERIFY_SSL` defaulted to `False` — API key sent over unverified TLS; IOC-injection risk. | Default `True` (MISP endpoint has a valid Let's Encrypt cert; verified). |
| 8 | MEDIUM | Backend / tenancy | `d.lstrip("www.")` in `brand.py` (×2) strips any leading run of `w/./` chars (`wise.com`→`ise.com`), losing results and risking a cross-tenant credential match on collision. | Use `ownership.bare_domain()` (correct prefix strip). |
| 9 | MEDIUM | Infra / headers | No security headers on the API or the browser-facing portal. | ASGI middleware in `main.py` (nosniff, frame-deny, referrer-policy, HSTS); `next.config.js` `headers()` (same + `frame-ancestors 'none'`, Permissions-Policy). |
| 10 | MEDIUM | Infra / CORS | Prod CORS allowed a cleartext `http://` origin with `allow_credentials=True`. | Drop non-HTTPS origins from the allow-list when `is_production`. |
| 11 | LOW | Infra / ops | passlib 1.7.4 + bcrypt 4.1.2 spam a trapped `__about__` traceback on every hash, burying real errors. | Pin `bcrypt==4.0.1` (needs an image rebuild to take effect — see below). |

Regression tests added: `tests/test_review_fixes.py` (report escaping, webhook
SSRF guard + validator, `bare_domain`). Live-verified on prod: security headers
present on API + report HTML; a report generated with `<script>`/`<img onerror>`
payloads renders fully escaped with the no-JS CSP.

## Backlog (recommended, not yet applied — need a maintenance window or larger change)

- **HIGH — Redis is unauthenticated on the shared docker network.** The intel
  stack (SpiderFoot/TorBot) joins `jichodns-network`; any container can inject
  Celery tasks = RCE in the worker. Fix needs a coordinated `requirepass` +
  `REDIS_URL` change across api/worker/scheduler + restart → do in a window.
- **HIGH — prod runs `uvicorn --reload` on a rw bind-mount, single process.**
  Correct fix is a `docker-compose.prod.yml` override (`--workers`, no reload,
  drop dev bind-mounts, `target: runner`, add the ES service, healthchecks,
  `${VAR:?}` required-vars). Note: the current rsync+reload deploy model depends
  on the bind-mount, so this is a deliberate ops change, not a hot patch.
- **HIGH — compose defaults `SECRET_KEY`/`ENVIRONMENT` to dev placeholders.** A
  `.env` slip boots prod with the public JWT key. Use `${SECRET_KEY:?}` /
  `${ENVIRONMENT:?}` in the prod compose.
- **HIGH — `.github/workflows/deploy.yml` + `ansible/inventory.yml`** still point
  at the decommissioned `23.150.68.201` over password SSH with host-key checking
  off, and would render the full vault to whatever answers that IP. Disable the
  deploy job or repoint at VM 119 with key-only auth before it can fire.
- **MEDIUM — no server-side token revocation / logout.** A stolen refresh token
  is valid 7 days with no kill switch. Add a `jti` denylist + `/logout`.
- **MEDIUM — bcrypt pin needs an image rebuild** to land on prod (installed in
  the image, not the bind-mount). Roll in with the next `docker compose build`.
- **MEDIUM — ES IOC field mapping**: `IOC_MAPPING` maps `threat_type`/
  `country_code`/etc. as `text`, but `get_stats`/`search` aggregate/term-filter
  on the bare field → "fielddata disabled" / silent empty country filter on any
  *fresh* ES. Masked on current prod (index pre-created as keyword). Reconcile
  `iocs` vs `iocs_v2` and map those fields as `keyword` before any ES rebuild.
- **MEDIUM — dashboard fabricates alerts + a floor-40 risk score** (`portal/page.tsx`).
  Violates the no-fabrication rule; wire to the real `/alerts/feed` and drop the
  synthetic score.
- **LOW — clickable links to live malicious domains** in brand/asm pages; defang
  and keep only urlscan/VT pivots.
- **LOW — intel-tor container unhealthy for 7 weeks**; ClickHouse 23.8-alpine is
  EOL; GeoIP DB baked from unpinned mirrors with no checksum.

## Confirmed-solid (reviewed, no change needed)

Dual DB-engine / event-loop pattern (both Postgres-touching Celery tasks import
`async_session_maker` lazily); `ALLOW_MOCK_DATA=False` genuinely fails closed (no
fabrication path); `_generic_import` records health from storage; login timing
equalization; owner-scoped credential/report/brand/ASM reads; Stripe webhook
fails closed; sqladmin re-validates admin per request with Strict cookies;
on-demand ASM scan path is rate-capped + ownership-checked + SSRF-guarded;
no `dangerouslySetInnerHTML`; report iframes omit `allow-scripts`; `?next=`
open-redirect is sanitized; WS feed is deliberately tokenless.
