# Mythic Adversary-Emulation Lab

Complete red-team C2 emulation lab for authorized pentesting and detection engineering on GOAD. Two tracks:

- **Track 1 (borrow):** Apollo agent + pre-built actor profiles (LockBit / Qilin) + redirector configs
- **Track 2 (build):** Full custom Sardonic agent (PayloadType + C2 profile) + IaC-deployed Proxmox redirector

Mythic server: `10.23.20.10:7443` (callback), reachable per `reference_mythic_access` memory.
Blue side: Nawi / Elastic SOC. Attacker box: Kali `192.168.36.100`.

## Quick navigation

**Start here:** `RECOMMENDATION.md` (which track, which actor, which agent)
**Deep research:** `RESEARCH.md` (threat actors, protocols, detection)

## Directory map

| Path | What it is | For which track |
|---|---|---|
| `TRACK2-README.md` | **Track 2 complete guide** - agent build, IaC deployment, operations | Track 2 (full build) |
| `profiles/` | Two drop-in `httpx` actor profiles (LockBit/Qilin), Tyche borrow pipeline | Track 1 (fast, pre-built) |
| `redirectors/` | nginx / Apache mod_rewrite configs for the Mythic listener | Track 1 (L7) |
| `detections/` | Elastic + Sysmon detection rules for both tracks | Both |
| `runbook.md` | Track 1: end-to-end build + deliver (uses built-in profiles) | Track 1 |
| `agent-dev-plan.md` | Track 2 (old): reference docs (superseded by TRACK2-README.md) | Track 2 (historical) |
| `track2-sardonic-agent/` | **Track 2: complete source code** - PayloadType, C2 profile, implant, IaC | Track 2 (the build itself) |
| `RESEARCH.md` | Full synthesized CTI: agents, C2 model, threat actors, protocols, detection | Reference |

## Attribution honesty (read this)

No authoritative primary IR (CISA, MITRE, Mandiant/GTIG, Microsoft) attributes **Mythic** by name
to any financial- or retail-sector actor **except one**: UNC2165 (Evil Corp / Indrik Spider)
operating under RansomHub, documented running Mythic + the ViperTunnel private tunneler with
COM-hijack persistence (Mandiant M-Trends 2025 / GTIG 2025). Everyone else in this lab
(FIN7, FIN8, LockBit, Qilin, Scattered Spider, ...) historically ran **Cobalt Strike** plus
open-source tunnelers plus wholesale RMM abuse.

So using Mythic to emulate these actors is a **deliberate, defensible substitution**, not observed
tradecraft. It is also forward-looking: Mandiant telemetry shows classic Cobalt Strike Beacon fell
from ~60% of intrusions (2021) to ~2% (2025) while open-source frameworks (Mythic, Havoc,
AdaptixC2) and RMM-as-C2 rose. We emulate the **traffic shape and TTPs**, not the exact binary.
Every profile file states which actor indicator it reproduces and which source documents it.

## Scope / authorization

Isolated lab (GOAD VLANs, `10.23.x` + `192.168.36.x`), owned infrastructure, defensive and
educational purpose. No third-party targets. Profiles are traffic-shaping configuration; redirector
configs are infrastructure; detections are for the defender. The agent-dev track is a plan plus
framework scaffold: the implant code is yours to write in the lab.
