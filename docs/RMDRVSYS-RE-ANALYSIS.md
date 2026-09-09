# RMDRVSYS.sys Reverse Engineering Analysis

**Date:** 2026-09-09 (updated)  
**Status:** PRELIMINARY — Needs Ghidra analysis  
**Driver:** RMDRVSYS.sys (ADLINK PXI Resource Manager)  
**SHA256:** b24f0d3db0a24214c98260b89a039aa6af9eb4d1f90a412bbe4406ef5becf195  
**Size:** 20,840 bytes  
**PDB:** `c:\jenkins\workspace\pxi_resourcemanager_odm_teradyne\adrmsrv_sys\adrmsrv_sys\amd64\RMDRVSYS.pdb`

---

## Summary

**FINDING: RMDRVSYS is a NOVEL BYOVD candidate with MmMapIoSpace capability.**

The driver is NOT on loldrivers.io. It is signed by ADLINK TECHNOLOGY INC with a valid DigiCert certificate (2023-2026). Requires deeper reverse engineering to understand IOCTL structure.

---

## Device Information

- **Device Name:** `\Device\RMDRVSYS`
- **Symbolic Link:** `\DosDevices\RMDRVSYS`
- **User-mode Path:** `\\.\RMDRVSYS`
- **Signer:** ADLINK TECHNOLOGY INC (DigiCert EV, valid 2023-2026)
- **Architecture:** x64

---

## Imports (Capabilities)

| Import | Purpose |
|--------|---------|
| `MmMapIoSpace` | Physical memory mapping |
| `MmUnmapIoSpace` | Unmap physical memory |
| `HalGetBusDataByOffset` | PCI configuration space access |
| `IoCreateDevice` | Device object creation |
| `IoCreateSymbolicLink` | User-mode accessible path |
| `ExAllocatePool` | Memory allocation |
| `KeInitializeMutex` | Synchronization |

---

## PE Structure

| Section | Virtual Address | Raw Offset | Size |
|---------|-----------------|------------|------|
| .text | 0x1000 | 0x400 | 0x1800 |
| .rdata | 0x3000 | 0x1C00 | 0x200 |
| .data | 0x4000 | 0x1E00 | 0x200 |
| .pdata | 0x5000 | 0x2000 | 0x200 |
| INIT | 0x6000 | 0x2200 | 0x400 |
| .rsrc | 0x7000 | 0x2600 | 0x400 |

---

## IOCTL Analysis (Incomplete)

### Potential IOCTL Base
- Found reference to `0x80000010` at offset 0x138D
- This suggests the driver may use the 0x8000XXXX IOCTL range
- Full IOCTL enumeration requires Ghidra disassembly

### Suspected IOCTL Functions
Based on imports, the driver likely supports:
1. **Physical Memory Read** - via MmMapIoSpace
2. **Physical Memory Write** - via MmMapIoSpace
3. **PCI Config Read** - via HalGetBusDataByOffset
4. **PCI BAR Mapping** - combining PCI config + MmMapIoSpace

---

## Why It's a Good Candidate

1. **NOT on loldrivers.io** — Novel, undocumented
2. **Valid certificate** — DigiCert EV, expires 2026
3. **MmMapIoSpace present** — Physical memory access capability
4. **Industrial vendor** — ADLINK/Teradyne test equipment, not gaming/overclocking
5. **Small size** — 20KB, easier to analyze

---

## Next Steps for Full RE

1. **Load in Ghidra** — Import and analyze `RMDRVSYS.sys`
2. **Find IRP_MJ_DEVICE_CONTROL handler** — Follow DriverEntry → MajorFunction[14]
3. **Identify IOCTL dispatch** — Map out all supported IOCTLs
4. **Document buffer structures** — Input/output buffer layouts
5. **Implement cascade backend** — Add `--driver-type rmdrvsys`

---

## Files

- **Driver:** `bigDrivers/b24f0d3db0a24214c98260b89a039aa6af9eb4d1f90a412bbe4406ef5becf195.sys`
- **Analysis:** This document
- **Cascade backend:** Not yet implemented

---

## Novelty Assessment

| Criteria | Status |
|----------|--------|
| On loldrivers.io | **NO** |
| On MS Vulnerable Driver Blocklist | **UNKNOWN** |
| Publicly documented as vulnerable | **NO** |
| Has physical memory capability | **YES** (MmMapIoSpace) |
| Has PCI config access | **YES** (HalGetBusDataByOffset) |
| Signed by reputable vendor | **YES** (ADLINK/DigiCert) |
| Certificate still valid | **YES** (until 2026) |
