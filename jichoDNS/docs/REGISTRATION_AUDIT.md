# Registration & Access Audit — updated 2026-07-14 (RESOLVED)

History: first pass 2026-07-09 ("users cannot register" — flow worked headless,
symptom unreproduced, `/register` rate limit staged). Second pass 2026-07-14
found the real bug, shipped the email pipeline, and deployed everything.

## Root causes found (2026-07-14)

1. **Email matching was case-sensitive end-to-end** — the actual "failing to
   create a user" bug. `register` and `login` did exact `User.email ==` matches
   and stored the email as typed. Mobile keyboards auto-capitalize, so a user
   who signed up as `Name@x.com` could never log in as `name@x.com` (proven
   live on prod: mixed-case register → 202, lowercase login → 401). Real user
   affected: `Nyamhungac@zfc.co.zw` (user id 8, registered 2026-07-09).
2. **No email pipeline existed at all.** `is_verified` was set False and never
   flipped; no SMTP config, no sender, no verify endpoint, no resend. Users who
   expected a confirmation email concluded signup had failed.

## Fixes shipped (deployed to prod 2026-07-14)

**Backend** (`security-hardening` branch):
- `normalize_email()` (strip + lowercase) applied at register, login, and
  resend; login lookup is `lower(email)`-based for pre-fix rows. Prod data
  migrated: `UPDATE users SET email = lower(email)` (2 rows, no collisions).
- Email service `app/services/email_service.py` — stdlib smtplib via
  `asyncio.to_thread` (no new prod deps), fail-safe (mail failure never breaks
  registration), **console mode** when `SMTP_HOST` is unset: the full message
  incl. verification link is written to the API log.
- Verification flow: signed JWT (`type="email_verify"`, 48 h,
  `create_email_verification_token`) emailed on registration via
  BackgroundTasks (post-response → no timing leak); `POST /verify-email`
  (idempotent, POST-only so mail scanners can't consume links, token must match
  the account's current email); `POST /resend-verification` (generic 202
  anti-enumeration, per-IP capped 6/h).
- `REQUIRE_EMAIL_VERIFICATION` setting (default **False** so existing accounts
  are not locked out); when True, unverified logins get 403.
- `/register` per-IP rate limit (10/h, from 2026-07-09) deployed and verified
  live (11th request → 429 + Retry-After).

**Frontend** (rebuilt + redeployed):
- `/verify-email` page (public in middleware) — POSTs the token, shows
  success/expired states.
- Portal banner for unverified users with a "Resend email" button.
- `lib/auth.ts`: client-side email normalization, 20 s timeouts on auth fetches
  (no more frozen "Creating account…"), and proper 422 error rendering
  (FastAPI validation errors are arrays — previously showed `[object Object]`).

**Config surface:** SMTP_* / EMAIL_FROM / PUBLIC_BASE_URL /
REQUIRE_EMAIL_VERIFICATION in `config.py`, `.env.example`, and
`ansible/roles/app/templates/env.prod.j2`.

## Tests

- `backend/tests/test_auth_flow.py` — 17 endpoint tests over in-memory SQLite
  (register normalization, duplicate-register anti-enumeration, case-insensitive
  login, verify/expiry/type-confusion/stale-email, resend paths, verification
  gate). Needs `aiosqlite` (test-only, in requirements.txt).
- `backend/tests/test_email_and_ratelimit.py` — limiter caps + fail-open,
  console mode, SMTP failure/success paths.
- Full suite green in the prod api container 2026-07-14 (70 tests).
- Live prod E2E 2026-07-14: register (mixed case) → 202 → token from log →
  verify 200 → lowercase login 200 → `/me` `is_verified: true`. Probe accounts
  deleted afterwards; rate-limit keys cleared.

## To enable real email delivery (the one remaining manual step)

Console mode works today (links land in `docker compose logs api`). To send
real mail, set in `/opt/jichodns/.env` and `docker compose restart api`:

```bash
SMTP_HOST=<relay>          # e.g. smtp.gmail.com / provider SMTP
SMTP_PORT=587              # 465 switches to implicit TLS automatically
SMTP_USERNAME=<user>
SMTP_PASSWORD=<app-password>
EMAIL_FROM=<sender address the relay is authorized for>
```

SPF/DKIM for `defendanddetect.com` must authorize the relay or mail will land
in spam. Once historical users are verified, consider
`REQUIRE_EMAIL_VERIFICATION=true`.

## Remaining (non-blocking, from 2026-07-09)

- Cosmetic portal 403 noise: free tier calls brand/asm/darkweb `/stats` → 403,
  degrades gracefully. Optional: gate by `hasAccess(user.tier)`.
- httpOnly-cookie migration for the auth token (TODO noted in `auth.ts`).

`main` is branch-protected (PR-only); land via PR from `security-hardening`.
