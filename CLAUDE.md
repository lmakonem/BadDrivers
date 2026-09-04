# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Building & Testing

**Prerequisites:** Windows 10/11 + Visual Studio 2019+ + CMake 3.20+

### Build

```bash
mkdir build && cd build
cmake -G "Visual Studio 17 2022" ..
cmake --build . --config Release
# Binaries: build/Release/*.exe
```

Cross-compile from macOS/Linux (MinGW):
```bash
x86_64-w64-mingw32-g++ -O2 -s -fno-ident \
    -static-libgcc -static-libstdc++ src/cascade.cpp \
    -lws2_32 -lntdll -ldbghelp -lpsapi -ladvapi32 \
    -o build/Release/cascade.exe
```

### End-to-end test suite (lab VM - requires Proxmox + Windows 11 22H2 VM)

Tests run via Proxmox `qm guest exec` from any machine with SSH access to the Proxmox host.
Prerequisites: `cascade.exe` + `BiosToolCommonDriver.sys` deployed to `C:\Users\Public\` on the guest.

```bash
# Single run (27 feature checks):
python3 tests/cascade_e2e.py

# 5 consecutive runs with clean snapshot revert between each:
python3 tests/run_suite.py --runs 5 --snap cascade-test-base
```

Certified: 5 consecutive 28/0 PASS runs on Win11 22H2 build 22621, 2026-08-29.

### Architecture Overview

| Component | Role | File |
|-----------|------|------|
| Consolidated tool | All BYOVD modes (BiosToolCommonDriver backend) | `src/cascade.cpp` |
| Legacy single-binary | PdFwKrnl backend | `src/warp.cpp` |
| Mock test | Offline EPROCESS/PPL logic validator (no driver) | `src/mock_driver_test.cpp` |
| E2E test suite | 27-check automated run via Proxmox qm exec | `tests/cascade_e2e.py` |
| Suite orchestrator | N-run cert loop with snapshot revert | `tests/run_suite.py` |

## What this track is for
BYOVD (Bring Your Own Vulnerable Driver) and kernel-primitive research: abusing signed but
vulnerable drivers for arbitrary kernel read/write, stripping LSASS PPL, and credential / memory
dumping in the modern EDR era. Seeded from the g3tsyst3m "BYOVD and Looting LSASS" writeup
(PdFwKrnl.sys, IOCTL `0x80002014`, EPROCESS Protection-byte overwrite, `NtCreateProcessEx` clone
plus callback-intercepted `MiniDumpWriteDump`, XOR-obfuscated dump). This is the starting scope,
not a fixed mandate: confirm or adjust it with the researcher before building.

## Inherited rules (source of truth is the parent, do not duplicate)
This is a subfolder of the `Research/` opencode workspace. The workspace file `../CLAUDE.md`
(a symlink to `../AGENTS.md`) governs, and must be read each session, for:
- the file-based memory protocol at `../memory/` (index `../memory/MEMORY.md`): open the relevant
  `memory/*.md` before acting, persist durable non-obvious facts after, dedup against the index,
  delete when wrong.
- authorization + OPSEC first (own isolated labs / in-scope engagements only, never real
  third-party systems, no live secrets in-repo), and the auditable methodology
  scope -> recon -> enum -> exploit -> post-exploit -> report (capture the exact command and its
  output; state failures with their output; do not narrate success).
- style: no em or en dashes anywhere (commas / colons / parens / periods; hyphen only for ranges);
  terse and decisive; PoCs safe-by-default (dry-run first, explicit target flag, no destructive
  default, secrets from env or the store).
Only add track-specific guidance below; do not restate the above.

## Track-specific working notes
- This is Windows kernel / EDR-internals work. EPROCESS offsets are build-specific (e.g. the
  Protection byte at `0x5FA` on Win11 build 26200). Resolve offsets dynamically where practical
  rather than hardcoding, and record the exact Windows build any offset was verified on.
- Vulnerable drivers are hash-blocklisted per version, not per family. For any driver used, record
  its exact SHA256, source (loldrivers.io / malshare), and signing details. Keep driver binaries
  and dumps out of git.

## Related tracks and memory (the emulation and detection counterparts)
- `../Mythic/` C2 emulation lab. BYOVD / PPL-strip
  tradecraft developed here is what gets emulated there.
- Detection side lives outside this workspace (Nawi SOC + the Elastic SIEM): driver-load
  (Sysmon EID 6 / SCM 7045), lsass handle-access, and runtime PPL-drop are the events to map
  coverage against. Lab consoles reachable over the VPN: [[reference-lab-bench]].
- `../CredHunter/` is the sibling credential-focused track: check it before duplicating dump or
  parsing tooling.
- The parent `memory/MEMORY.md` indexes every active subfolder; add `BadDrivers` to it once scope is confirmed.
