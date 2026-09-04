# AGENTS.md — AI assistant guidance for this repo

## Build

**Prerequisites:** Windows 10/11 x64, Visual Studio 2022+, CMake 3.20+

```bash
mkdir build && cd build
cmake -G "Visual Studio 17 2022" ..
cmake --build . --config Release
# Binaries land in build/Release/
```

Cross-compile from macOS/Linux (requires `mingw-w64`):

```bash
bash scripts/build.sh
```

## Testing

The offline offset validator builds and runs on any platform with `g++`:

```bash
g++ -O2 -std=c++17 src/mock_driver_test.cpp -o mock_driver_test && ./mock_driver_test
```

Full end-to-end suite requires a Windows 11 22H2 VM accessible via Proxmox `qm guest exec`.
Configure via environment variables (see `tests/cascade_e2e.py` docstring):

```bash
export BADDRIVERS_PVE="root@<proxmox-host>"
export BADDRIVERS_VMID="<vm-id>"
export BADDRIVERS_EXE='C:\Users\Public\cascade.exe'
export BADDRIVERS_DRV='C:\Users\Public\BiosToolCommonDriver.sys'
python3 tests/cascade_e2e.py
```

## Architecture

| Component | Role | File |
|-----------|------|------|
| `cascade.exe` | All BYOVD modes (BiosToolCommonDriver/ktapi/pdfwkrnl) | `src/cascade.cpp` |
| `warp.exe` | Legacy single-binary (PdFwKrnl backend) | `src/warp.cpp` |
| `mock_driver_test` | Offline EPROCESS/PPL offset validator | `src/mock_driver_test.cpp` |
| `byovd_dump_bof.o` | Beacon Object File for C2 in-memory exec | `src/byovd_dump_bof.c` |
| `probe.ps1` | Pre-flight: HVCI/CG/Defender recon | `deploy/probe.ps1` |
| `run_chain.ps1` | Full chain orchestrator | `tools/run_chain.ps1` |
| E2E suite | 28-check automated run | `tests/cascade_e2e.py` |

## Style rules

- No live secrets in-repo; IPs and credentials via environment variables only
- Driver binaries and memory dumps stay out of git
- Dry-run first (`--dry-run`), explicit target flag, no destructive defaults
- Record exact Windows build number for any offset verified
- Keep driver SHA-256 and signing details in code comments, not in commit messages

## Scope

BYOVD and kernel-primitive research: signed but vulnerable drivers for arbitrary kernel
read/write, LSASS PPL strip, and credential/memory dumping in the modern EDR era.
Isolated lab use only. Own infrastructure, in-scope engagements only.
