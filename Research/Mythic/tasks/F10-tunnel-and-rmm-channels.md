# TASK F10 — Add one tunnel (Chisel) + one RMM channel (ScreenConnect:8880)   [SCAFFOLD ONLY]

**Status:** not started (scaffold). These are existing-tool selections, not new tooling, but they
need **new analytics authored** — `detections/elastic-sysmon.md` currently has no tunnel/RMM rule,
so there is nothing to fire yet (logged honestly).

## Scope
Exercise the two biggest untested surfaces in the lab, both used by the modeled actors:
- **Protocol tunneling (T1572)** — Chisel (Qilin renames it `fos`; DragonForce/others tunnel to
  trycloudflare). Add one Chisel client->server tunnel from the target.
- **Remote access software as C2 (T1219)** — ScreenConnect on non-standard port **8880** (Qilin's
  documented pattern). Install/point one ScreenConnect client at a lab relay.

## Public references
- Chisel: https://github.com/jpillora/chisel ; MITRE ATT&CK T1572.
- ConnectWise ScreenConnect; MITRE ATT&CK T1219; The DFIR Report / Talos Qilin (ScreenConnect:8880,
  Chisel `fos`, SystemBC/COROXY).
- Mandiant M-Trends 2025 — RMM-as-C2 is the dominant 2025 pattern (highest-ROI gap).

## Milestones
1. Author `detections/` analytics FIRST (else acceptance cannot be measured):
   - tunnel: long-lived single TCP flow, high duty cycle, non-browser process (Chisel), to a rare dst.
   - RMM: egress to ScreenConnect vendor cloud / relay on 8880; RMM binary signer + child processes.
2. Run Chisel tunnel + ScreenConnect:8880 from the target through the lab.
3. Confirm both analytics fire; unit-test with Atomic Red Team (T1572, T1219 atomics).

## Acceptance detection
New tunnel-detection analytic (T1572) and RMM-egress analytic (T1219) fire on the Chisel tunnel and
the ScreenConnect:8880 channel respectively. Both analytics are net-new (none exist today).
