# REMEDIATION LEDGER — emulation fidelity audit (F1–F10)

Implements the ranked audit findings. Branch: **`remediation/emulation-audit-fixes`** off
`security-hardening`. One atomic commit per finding (stacked, since six findings edit the same
tracked docs — independent branches would only manufacture conflicts on shared files). Each commit
is an isolated reviewable diff and individually revertible via `git revert <sha>`.

Per-change rule honored: every change either **moves a detection** (previously fired on nothing) or
**clarifies a labeling/honesty state**. No change moves zero detections and clarifies nothing.

## Ledger

| # | Group | Change summary | Acceptance criterion | Status | Commit |
|---|---|---|---|---|---|
| **F9** | A | Collapse 7 `fin8_cdn` variants → one lab + one ops config; delete broken `httpx_minimal.json`; add `ACTIVE-CONFIG.md` + DEPLOYMENT pointer | **Honesty:** one source-of-truth per intent; broken config removed; active-config pointer exists | ✅ done | `9969a3d` |
| **F2** | A | Ops build → redirector FQDN:443 + actor `raw_c2_config`; port-82 build labeled LAB-ONLY | **Honesty + enabling:** ops path exercises N6/N3 on a real profile; LAB-ONLY excluded from coverage | ✅ done | `8c3ccc2` |
| **F7** | A | XOR key `"mythic"` → per-op random; actor timing (62/37); OPSEC priority reorder | **Honesty:** removes framework-name IOC; priority matches detections ranking; timing feeds N2 on the actor's real cadence | ✅ done | `6a593bc` |
| **F6** | B | Remove jsdelivr/unpkg callback guidance; actor-accurate egress (sslip.io / aged domains / forged-OCSP) | **Honesty:** broken/inauthentic fronting guidance gone; egress matches actors; avoids N4 self-tell | ✅ done | `751d21a` |
| **F8** | B | JA4H row in OPSEC "Detected Indicators", marked unfixable at this layer | **Honesty (N1):** checklist stops implying UA/port hardening is sufficient; N1 surfaced as governing tell | ✅ done | `5f16bea` |
| **F3** | B | Log LockBit JA3 as accepted, out-of-scope IOC | **Honesty:** accepted-gap logged; LockBit-JA3 hunt documented as not exercised | ✅ done | `610d166` |
| **F4** | C | Apollo build: `spawnto`=wuauclt + SMB pipe `fullduplex_84` + one task each | **Detection:** **H2 + H3 now fire** (previously fired on nothing) | ✅ done | `20d9d78` |
| **F1** | D | Scaffold task: Sardonic/FIN8 binary payload type; interim rename `fin8_cdn`→`generic_cdn_beacon` | **Honesty:** generic beacon no longer miscounted as FIN8; real FIN8 surface tracked | 🟡 scaffolded | `a94a1eb` |
| **F5** | D | Scaffold task: adopt CTID FIN7 plan; demote MSSQL/certutil to lab access shim | **Honesty:** shim excluded from actor initial-access coverage; FIN7 ordering tracked | 🟡 scaffolded | `84e80e0` |
| **F10** | D | Scaffold task: add Chisel tunnel (T1572) + ScreenConnect:8880 RMM (T1219) | **Honesty:** T1572/T1219 gap tracked; new analytics required (none exist yet) | 🟡 scaffolded | `d6b8ef8` |

Baseline (not a finding): `072c100` tracks the well-aligned assets the acceptance criteria
reference (`detections/`, `profiles/`, `redirectors/`, `runbook.md`, `README.md`).

## Accepted / out-of-scope IOCs (F3)

| IOC | Actor | Why not reproduced | Disposition |
|---|---|---|---|
| JA3 `a0e9f5d64349fb13191bc781f81f42e1` | LockBit | Apollo is .NET/SChannel; emits a .NET JA3/JA4H, not the CS malleable JA3 | Accepted; would need a native agent (Track-2). N1 still fires. |

## Detections newly exercised (closed finding → analytic)

| Finding | Analytic | Before | After |
|---|---|---|---|
| **F4** | **H3** (Sysmon 8, CreateRemoteThread → `wuauclt.exe`) | fired on nothing | fires — spawnto=wuauclt + fork&run task |
| **F4** | **H2** (Sysmon 17/18, named pipe `fullduplex_84`) | fired on nothing | fires — smb profile pipename=fullduplex_84 + link |
| F2 | **N6** (real-cert TLS via redirector), **N3** (low URI cardinality on a real profile) | trivially caught on the port-82 lab shape | exercised on the ops/redirector path with an actor profile |
| F7 | **N2** (RITA periodicity) | ran on an invented 60/50 cadence | runs on LockBit's documented 62/37 cadence |
| F8 | **N1** (JA4H vs UA) | implied "mitigated" by UA/port hardening | surfaced as the governing, unfixable tell |
| F6 | **N4** (Host/SNI/ASN disagreement) | risked a self-inflicted SNI-vs-Host tell via fronting | egress guidance avoids the self-tell |

**Net new host detections that now fire (previously dead): H2, H3** (both via F4).
Group-D tasks (F1 non-TLS-on-443; F10 T1572/T1219) require **new analytics** to be authored before
they can be measured — flagged in each task spec, not silently counted.

## What was preserved (not regressed)

LockBit profile fidelity, Qilin OCSP tell, the nginx redirector, `detections/elastic-sysmon.md`,
and the README attribution honesty are untouched and now version-controlled (baseline commit).
