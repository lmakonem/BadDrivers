# ACTIVE C2 CONFIG -- source-of-truth pointer (F9)

There is exactly **one source-of-truth config per intent**. Everything else that used to
live here (`httpx_config.toml`, `_fixed`, `_opsec`, `_hardened`, `httpx_agent_configs*.json`,
`httpx_minimal.json`) was redundant or broken and has been removed. httpx accepts TOML or JSON;
TOML is the source-of-truth here, derive JSON at deploy time if a container needs it.

| Intent | File | Callback (build param) | Counts as actor coverage? |
|---|---|---|---|
| **LAB** (unmonitored range only) | `generic_cdn_beacon.lab.toml` | `http://10.23.20.10:82` | **NO** -- generic beacon, no actor |
| **OPS-hygiene** (monitored, non-attributed) | `generic_cdn_beacon.ops.toml` | `https://<REDIR_FQDN>:443` | **NO** -- generic hardened shape |
| _actor rows added under F2 below_ | | | |

## Rules (do not violate)

1. The **LAB** config is HTTP on port 82 to a raw IP. It reproduces **no documented actor**.
   Never label a LAB run as FIN8/LockBit/Qilin emulation. It exercises the Run-1 baseline
   (static tells) only.
2. The **OPS-hygiene** config is a **generic** hardened traffic shape. It exercises network
   hygiene analytics (N3, N6) but is **not** attributed to any actor.
3. `fin8_cdn` was a **misnomer** (renamed to `generic_cdn_beacon`, F1): FIN8/Sardonic is a
   non-TLS binary protocol on TCP/443 and is not representable in httpx. Real FIN8 coverage is
   the Track-2 build (see `../../tasks/F1-sardonic-fin8-payload.md`).

## Removed in F9 (redundant / broken)

- `httpx_config.toml` -- invalid `headers = { ... }` inline-table shape
- `httpx_config_fixed.toml` -- superseded by `generic_cdn_beacon.lab.toml`
- `httpx_config_opsec.toml` -- duplicate of the ops shape with a different transform order
- `httpx_config_hardened.toml` -- renamed to `generic_cdn_beacon.ops.toml`
- `httpx_agent_configs.json`, `httpx_agent_configs_clean.json` -- server-side JSON duplicates
- `httpx_minimal.json` -- **broken**: `message.location = ""` places agent data nowhere
