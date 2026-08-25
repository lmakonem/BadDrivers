# ACTIVE C2 CONFIG -- source-of-truth pointer (F9)

There is exactly **one source-of-truth config per intent**. Everything else that used to
live here (`httpx_config.toml`, `_fixed`, `_opsec`, `_hardened`, `httpx_agent_configs*.json`,
`httpx_minimal.json`) was redundant or broken and has been removed. httpx accepts TOML or JSON;
TOML is the source-of-truth here, derive JSON at deploy time if a container needs it.

| Intent | File | Callback (build param) | Counts as actor coverage? |
|---|---|---|---|
| **LAB** (unmonitored range only) | `generic_cdn_beacon.lab.toml` | `http://10.23.20.10:82` | **NO** -- generic beacon, no actor |
| **OPS-hygiene** (monitored, non-attributed) | `generic_cdn_beacon.ops.toml` | `https://<REDIR_FQDN>:443` | **NO** -- generic hardened shape |
| **OPS-actor: LockBit** (monitored) | `../../profiles/lockbit-icbc.httpx.toml` as `raw_c2_config` | `https://<REDIR_FQDN>:443` | **YES** -- LockBit ICBC beacon (see JA3 caveat, F3) |
| **OPS-actor: Qilin** (monitored) | `../../profiles/qilin-ocsp.httpx.toml` as `raw_c2_config` | `https://<REDIR_FQDN>:443` | **YES** -- Qilin OCSP-spoof |

## Actor-attributed ops build (F2)

For any **monitored** run that should count as actor coverage, the payload MUST:

1. Callback to the **redirector FQDN on 443** (never the raw Mythic IP, never port 82). The
   redirector terminates TLS with a real Let's Encrypt cert (`../../redirectors/nginx.conf`),
   which is what normalizes JA3S/JARM to a mainstream nginx stack (exercises **N6**) instead of
   the default Mythic listener fingerprint.
2. Load the actor profile as `raw_c2_config`:
   - LockBit -> `../../profiles/lockbit-icbc.httpx.toml` (62s / 37% jitter, GET `/_next.css` +
     POST `/boards`, Host `user.compdatasystems.com`, base64x2 + 814-byte strip).
   - Qilin -> `../../profiles/qilin-ocsp.httpx.toml` (forged `Host: ocsp.verisign.com`).
3. Set the actor host-side items at build time (LockBit: `spawnto` = wuauclt, SMB pipe
   `fullduplex_84` -- see `../HOST-EMULATION-LOCKBIT.md`, F4).

Accepted caveat (F3): the LockBit-specific **JA3 `a0e9f5d64349fb13191bc781f81f42e1`** is NOT
reproduced -- Apollo is .NET/SChannel and emits a .NET JA3/JA4H, not the CS malleable JA3.
"Hunt for LockBit's JA3" is therefore not exercised by this agent; logged as accepted, not forced.

## LAB-ONLY build (never counted as coverage)

The `http://10.23.20.10:82` + `generic_cdn_beacon.lab.toml` build is the Run-1 baseline. It is
LAB-ONLY (raw IP, non-standard port, cleartext HTTP) and MUST NOT appear in any actor-coverage
tally.

## Rules (do not violate)

1. The **LAB** config is HTTP on port 82 to a raw IP. It reproduces **no documented actor**.
   Never label a LAB run as FIN8/LockBit/Qilin emulation. It exercises the Run-1 baseline
   (static tells) only.
2. The **OPS-hygiene** config is a **generic** hardened traffic shape. It exercises network
   hygiene analytics (N3, N6) but is **not** attributed to any actor.
3. `fin8_cdn` was a **misnomer** (renamed to `generic_cdn_beacon`, F1): FIN8/Sardonic is a
   non-TLS binary protocol on TCP/443 and is not representable in httpx. Real FIN8 coverage is
   the Track-2 build (see `../../tasks/F1-sardonic-fin8-payload.md`).

## Deployed server-side default keys (httpx agent_configs.json)

The Mythic httpx container's default set was realigned off the `fin8_cdn` misnomer to match this repo:

| Server default key | inner `name` | maps to repo file |
|---|---|---|
| `generic_cdn_beacon` | `generic_cdn_beacon` | `generic_cdn_beacon.lab.toml` |
| `generic_cdn_beacon_ops` | `generic_cdn_beacon_ops` | `generic_cdn_beacon.ops.toml` |

## Removed in F9 (redundant / broken)

- `httpx_config.toml` -- invalid `headers = { ... }` inline-table shape
- `httpx_config_fixed.toml` -- superseded by `generic_cdn_beacon.lab.toml`
- `httpx_config_opsec.toml` -- duplicate of the ops shape with a different transform order
- `httpx_config_hardened.toml` -- renamed to `generic_cdn_beacon.ops.toml`
- `httpx_agent_configs.json`, `httpx_agent_configs_clean.json` -- server-side JSON duplicates
- `httpx_minimal.json` -- **broken**: `message.location = ""` places agent data nowhere
