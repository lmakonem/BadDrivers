# TASK F5 — Adopt the CTID FIN7 emulation plan for kill-chain ordering   [SCAFFOLD ONLY]

**Status:** not started (scaffold). The MSSQL `xp_cmdshell` + `certutil` delivery is relabeled a
**"lab access shim"** in this pass (DEPLOYMENT.md Phase 6, runbook.md step 4); adopting the real
FIN7 ordering is the tracked work below.

## Scope
Drive the campaign storyline with the published **CTID FIN7 adversary-emulation plan** so the
kill-chain ordering and **initial access** match FIN7 (G0046) instead of a lab convenience. The
current GOAD MSSQL `xp_cmdshell` -> `certutil` path is a delivery shim; it tests SQL-child-process
+ certutil analytics (useful) but leaves FIN7's real initial-access telemetry untested
(spearphishing + weaponized docs/LNK + more_eggs, T1566.001/.002; `msxsl.exe` LOLBIN, T1218).

## Public references
- CTID `adversary_emulation_library` — FIN7 plan (human + machine-readable YAML):
  https://github.com/center-for-threat-informed-defense/adversary_emulation_library
- MITRE ATT&CK G0046 (FIN7 / Carbanak); Mandiant/GTIG FIN7 reporting.
- Existing lab chain: `runbook.md` step 4 (the shim to demote), Episode-1 SQL RCE writeup.

## Milestones
1. Map each CTID FIN7 phase to an Apollo task chain over the LockBit/Qilin ops profile.
2. Replace the MSSQL initial access with a FIN7-accurate vector (spearphish -> more_eggs) for the
   emulation storyline; keep MSSQL only as an explicitly labeled "lab access shim."
3. Sequence the existing detections (N1-N6, H2/H3) to fire in CTID order, not in isolation.

## Acceptance detection
Initial-access telemetry appropriate to FIN7 (child-of-Office / LNK spawn, `msxsl.exe` more_eggs,
T1566/T1218) is exercised rather than SQL-server child-process + certutil; the MSSQL/certutil path
is documented as a "lab access shim" and excluded from FIN7 initial-access coverage.
