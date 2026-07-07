# JichoDNS Deployment — Proxmox/ludus01 (2026-05-22)

This runbook documents the redeployment of JichoDNS to internal Proxmox infrastructure after the original Killdeer/plover.digital VMs were deleted.

## Topology

| Layer | Where | Notes |
|---|---|---|
| Hypervisor | `ludus01` @ 192.168.38.195 (Proxmox 9.1.5, 80 vCPU / 251 GiB / 1.65 TiB free `local`) | Single-node, not clustered with acirt01 |
| VM | `jichodns01` — VMID **119** on node `ludus`, cloned from template **104** (`ubuntu-24.04-x64-server-template`) | 8 vCPU / 16 GiB RAM / 200 GiB disk |
| VM NIC | `vmbr1000` (transit 192.0.2.0/24), DHCP → **192.0.2.55** | See [Why DNAT, not bridged](#why-dnat-not-bridged) |
| LAN reachability | DNAT on `ludus01:eno1 (192.168.38.195)` | See port table below |
| Public exposure | Cloudflare named tunnel → `jichosec.defendanddetect.com` | See [Cloudflare tunnel](#cloudflare-tunnel) |

## DNAT port table

iptables PREROUTING rules on **ludus01** (persisted via `netfilter-persistent` / `/etc/iptables/rules.v4`):

| External (LAN/VPN) | Internal (VM) | Service |
|---|---|---|
| `192.168.38.195:3030` | `192.0.2.55:3000` | jichoDNS frontend (Next.js) |
| `192.168.38.195:8030` | `192.0.2.55:8000` | jichoDNS API (FastAPI) |
| `192.168.38.195:22311` | `192.0.2.55:22` | SSH into jichodns01 |

Quick test from a LAN host:
```
curl -o /dev/null -w '%{http_code}\n' http://192.168.38.195:3030/
curl -o /dev/null -w '%{http_code}\n' http://192.168.38.195:8030/health
ssh howard@192.168.38.195 -p 22311
```

## SSH access

The VM is reachable two ways:

```
# Via DNAT port on ludus01
ssh howard@192.168.38.195 -p 22311

# Via ProxyJump through ludus01 (use during provisioning / DNAT troubleshooting)
ssh -J root@192.168.38.195 howard@192.0.2.55
```

`howard` has NOPASSWD sudo and Docker group membership. Authorized keys: `id_rsa.pub` and `id_ed25519.pub` from `lmakonem@Howards-MBP*`.

## Why DNAT, not bridged

Compared to acirt01 (which has `vmbr0` bridging `enp66s0f3`), **ludus01 has no LAN-attached bridge**:

- `eno1` is the only physical NIC with carrier (eno2/3/4 have no cable plugged).
- `eno1` is directly assigned `192.168.38.195/24` in `/etc/network/interfaces` — not a bridge member.
- All `vmbr*` on ludus01 are either transit (`vmbr1000` = 192.0.2.0/24) or Ludus-managed lab ranges (`vmbr1xxx`).

Putting a VM on `192.168.38.x` directly would require either:
1. Reconfiguring `eno1` to become a bridge member of a new `vmbr0` — host-network outage risk on a 62+ day uptime prod node serving 27 running labs.
2. Plugging a cable into `eno2/3/4` (physical DC visit).

The agentops01 + siem* pattern uses transit + DNAT for the same reason. We followed that pattern here.

**If you ever want to revisit**: the safest path is option (2) — plug an unused NIC, define `vmbr0` with it, attach VM 119 to vmbr0, drop the DNAT rules. Zero risk to existing host networking.

## Cloudflare tunnel

The VM runs `cloudflared` as a named tunnel; ingress is `jichosec.defendanddetect.com → http://localhost:3000`. The tunnel terminates *on jichodns01 itself* (not on ludus01), so Cloudflare never touches the 192.168.38.x or 192.0.2.x networks — the agent makes outbound HTTPS to CF edge.

- **Tunnel name**: `jichodns-prod`
- **Tunnel UUID**: `a1af8c99-12d1-42e7-af54-c48c7d3cb91e` (created 2026-03-25 — predates this redeploy, kept the same UUID so DNS routing stayed valid)
- **Account**: `Hmukanda@gmail.com's Account` (`02f5acca21a2df7e5bf3eb4b7ccdbe21`)

Files on jichodns01:
- `/etc/cloudflared/config.yml` — ingress rules (local-managed, not Zero Trust dashboard managed)
- `/etc/cloudflared/jichodns-prod.json` — tunnel credentials (derived from the connector token; rotate with `cloudflared tunnel rotate jichodns-prod` and update this file from the new token)
- `~howard/.cloudflared/cert.pem` — Cloudflare account cert; needed to create *new* tunnels but NOT to run the existing one. Do not delete.
- `/etc/systemd/system/cloudflared.service` — runs as root, `--config /etc/cloudflared/config.yml tunnel run` (NOT `--token` mode — token mode is remote-managed and silently 503s if you also have local config).

To redirect to a different origin, edit `/etc/cloudflared/config.yml` (only the `service:` line) and `sudo systemctl restart cloudflared`.

**Gotcha from this deploy**: `cloudflared service install <TOKEN>` puts the tunnel in *remote-managed* mode — ingress is then expected to be set via the Cloudflare Zero Trust dashboard, not local config.yml. That returned 503 because no public-hostname mapping existed in the dashboard for this hostname. Fix used here: decode the token (`base64 -d` → JSON with `a`/`s`/`t` fields), write it to `jichodns-prod.json` as Cloudflare's expected `{AccountTag, TunnelID, TunnelName, TunnelSecret}` shape, and run with `--config` instead of `--token`. That makes the tunnel *local-managed* and the config.yml ingress takes effect.

## App stack (Docker Compose)

- Repo: `/opt/jichodns` (owned by `howard`)
- Compose file: `docker-compose.yml` (single file, not the ansible-rendered `docker-compose.db.yml` + `docker-compose.app.yml` split — the ansible deploy was for plover.digital and would need adapting to land here)
- Services: `postgres`, `clickhouse`, `redis`, `api`, `frontend`, `worker`, `scheduler`
- Env file: `/opt/jichodns/.env` (mode 600, owned by howard) — sourced from `jichoDNS/ansible/group_vars/all/vault.yml`

### Operational notes (recurring gotchas during first bring-up)

1. **Frontend `target: development` did not exist** in the Dockerfile (only `builder` and `runner` stages). Patched to `target: runner`. If you re-rsync from the Mac, re-apply or fix upstream.
2. **Frontend dev volumes (`./frontend:/app`, `/app/node_modules`, `/app/.next`) shadowed the built image** — Next.js standalone output was unreachable, `node server.js` errored "module not found". Removed from compose on the VM. Same caveat as above for re-rsyncs.
3. **`backend/migrations/init.sql` and `clickhouse_init.sql` don't exist** in the repo — Docker auto-creates them as empty dirs. ClickHouse exits 74 on first start (`Is a directory`). On subsequent starts the data volume is already initialized so init is skipped — but a fresh `docker compose down -v` would re-trigger. Workaround: create real (or empty) files.
4. **No Elasticsearch service in repo compose** — backend defaults to `localhost:9200` which fails inside a container. Patched on the VM: added a `jichodns-elasticsearch` service (image `elasticsearch:8.13.4`, single-node, security off, 1 GiB heap), `es_data` volume, and set `ELASTICSEARCH_URL=http://elasticsearch:9200` on api/worker/scheduler.
5. **`es_service.get_region_scores()` is called by the public `/regions/map` and `/regions/countries` endpoints but is *never defined*** (only `get_country_threat_stats()` exists in `backend/app/services/elasticsearch.py`). The calls in `public.py` are wrapped in `try/except`, so they swallow the `AttributeError` and return an **empty** FeatureCollection / item list — the choropleth is not populated. This was **not** fixed on the VM; building the region-score reader is deferred (see [REMEDIATION_BACKLOG.md](REMEDIATION_BACKLOG.md#L12) item 3).
6. **Terms aggregations on `country_code` and `threat_type` returned zero buckets** — those fields are indexed as `text` (with auto `.keyword` multi-field). ES 8 requires `.keyword` for terms aggs on text. Patched `get_country_threat_stats()` to use `country_code.keyword` / `threat_type.keyword`.
7. **`NEXT_PUBLIC_API_URL=http://localhost:8000`** in compose meant the frontend told user browsers to fetch from *their own* localhost. Changed to empty string so the frontend issues relative `/api/v1/*` calls and Cloudflare path-routes them to the backend.
8. **Cloudflare tunnel ingress only routed to frontend (:3000).** API calls returned the Next 404 page. Updated `/etc/cloudflared/config.yml` to path-route: `^/api/.*` → `http://localhost:8000`, else → `http://localhost:3000`.
9. **Celery beat scheduler crashed: `Permission denied: 'celerybeat-schedule'`** — Celery writes its state file in the working dir, which is read-only under our user. Override command to `celery -A app.worker beat --loglevel=info --schedule=/tmp/celerybeat-schedule`.
10. **GeoIP database not bundled.** Downloaded db-ip's free city MMDB to `/opt/jichodns/backend/data/GeoLite2-City.mmdb`. The geoip2 Python reader treats it like MaxMind's GeoLite2-City. Refresh monthly (URL pattern: `https://download.db-ip.com/free/dbip-city-lite-YYYY-MM.mmdb.gz`).

### Authentication

Default admin (bootstrap 2026-05-22):
- Email: `hmukanda@gmail.com`
- (Password is stored out-of-band; rotate with `docker exec jichodns-api python create_admin.py <email> <new-password>`.)

Auth is applied **at the router level** in `backend/app/api/v1/__init__.py` — only the `auth`, `forms`, `public`, `billing`, and `websocket` routers are mounted without `dependencies=[Depends(get_current_user)]`. That makes the **only** anonymous surface:

- `/api/v1/auth/*`, `/api/v1/forms/*`
- the landing-page/public-map endpoints served by `public.router`: `/api/v1/indicators/stats`, `/api/v1/indicators/live/feed`, `/api/v1/regions/countries`, `/api/v1/regions/map`
- `/api/v1/billing/webhook` (Stripe webhook; `checkout`/`portal` verify auth in-endpoint)
- the WebSocket route (live map)

**Everything else is JWT-protected** (`dependencies=[Depends(get_current_user)]` on the router): all of `/api/v1/indicators/*`, `/api/v1/regions/*` (beyond the two public paths above), `/api/v1/analysis/*`, `/api/v1/atlas/*` (which *additionally* return HTTP 501 — not implemented), `/api/v1/darkweb/*`, `/api/v1/reports/*`, `/api/v1/asm/*`, `/api/v1/brand/*`, `/api/v1/intel/*`, `/api/v1/search/*`, `/api/v1/alerts/*`, `/api/v1/credentials/*`, `/api/v1/darkweb-intel/*`, and `/api/v1/misp/*`. (Earlier drafts of this runbook wrongly listed `/analysis`, `/darkweb/*`, `/reports/*`, `/brand/*`, `/atlas/*`, and `/misp/*` as anonymous — they are not.)

Endpoints **admin-only** (`Depends(get_current_admin)`): `/api/v1/admin/*` (stats, users, submissions).

### Data flow / feeds

Beat schedule kicks every 5 min – 6 hr. Feeds that work without an API key (already firing on schedule):
- URLhaus (5 min) — 30k IOCs imported on first run
- ThreatFox (5 min)
- Feodo Tracker (5 min)
- SSL Blacklist (15 min) + JA3 (30 min)
- OpenPhish (30 min)
- crt.sh (30 min)

Feeds requiring API keys (currently blank in `.env`, no-op):
- AbuseIPDB, PhishTank, AlienVault OTX, MISP, VirusTotal, Shodan, HIBP, IntelX, Censys, Dehashed, Telegram bot.

Add a key by editing `/opt/jichodns/.env` on the VM, then `docker compose restart api worker scheduler`.

### Pending upstream cleanups

These were patched on the VM only. Mirror them in `~/repos/jichoDNS` and PR:
- `docker-compose.yml`: change `frontend.build.target` from `development` to `runner`; drop frontend dev bind-mounts; add `elasticsearch` service + `es_data` volume + `ELASTICSEARCH_URL` env on api/worker/scheduler; change `NEXT_PUBLIC_API_URL` to empty string; add `--schedule=/tmp/celerybeat-schedule` to scheduler command.
- `backend/app/services/elasticsearch.py`: `.keyword` field fix for terms aggs (done). NOTE: `get_region_scores()` is still **not implemented** — the public region endpoints call it and fall back to empty; building it is a feature (backlog #3), not a mirror.
- Auth for the user-scoped routers (`brand`, `darkweb`, `reports`, `asm`, `intel`, etc.) is now enforced **at the router-mount level** in `backend/app/api/v1/__init__.py` (`dependencies=[Depends(get_current_user)]`) rather than per-endpoint — see the Authentication section above for the anonymous/protected split.
- Add `backend/migrations/{init.sql,clickhouse_init.sql}` (can be empty files).
- Bundle/script-fetch a GeoLite2-City.mmdb (or document the db-ip fallback).

## Quick operations

```bash
# Service status
ssh howard@192.168.38.195 -p 22311 'cd /opt/jichodns && docker compose ps'

# Logs
ssh howard@192.168.38.195 -p 22311 'docker logs jichodns-api --tail 100 -f'

# Restart everything
ssh howard@192.168.38.195 -p 22311 'cd /opt/jichodns && docker compose restart'

# Update code (from your Mac)
cd ~/repos/jichoDNS && tar czf - --exclude=.git --exclude=node_modules --exclude=.next . | \
  ssh -J root@192.168.38.195 howard@192.0.2.55 'cd /opt/jichodns && tar xzf -'
ssh howard@192.168.38.195 -p 22311 'cd /opt/jichodns && docker compose up -d --build'

# Inspect DNAT
ssh root@192.168.38.195 'iptables -t nat -L PREROUTING -n --line-numbers | grep jichodns'
```

## Decommission checklist

If you ever need to tear this down cleanly:

```bash
# On jichodns01
sudo systemctl stop cloudflared && sudo systemctl disable cloudflared
cd /opt/jichodns && docker compose down -v

# On ludus01
iptables -t nat -D PREROUTING -p tcp -d 192.168.38.195 --dport 3030 -j DNAT --to-destination 192.0.2.55:3000
iptables -t nat -D PREROUTING -p tcp -d 192.168.38.195 --dport 8030 -j DNAT --to-destination 192.0.2.55:8000
iptables -t nat -D PREROUTING -p tcp -d 192.168.38.195 --dport 22311 -j DNAT --to-destination 192.0.2.55:22
netfilter-persistent save
qm stop 119 && qm destroy 119 --purge
```
