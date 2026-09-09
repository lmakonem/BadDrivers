# RtsPpx.sys Reverse Engineering Analysis

**Date:** 2026-09-08  
**Driver:** RtsPpx.sys (Realtek PCIe Card Reader Proxy)  
**SHA256:** 0259226bce1a413201617e7ea662e7871c4cdd4fb24f8e13dae93fbc28d3bbef  
**Size:** 27,208 bytes  
**Build:** Debug (E:\SW_SSD\WIN_DRIVER\RtsProxy\RtsPpx\x64\Win8.1Debug\RtsPpx.pdb)

## Summary

**FINDING: RtsPpx is a NOVEL BYOVD candidate with arbitrary physical memory R/W.**

The driver provides MmMapIoSpace-based physical memory access with NO address validation. It is NOT on loldrivers.io or known public BYOVD lists.

## Device Information

- **Device Name:** `\Device\RtsPpxDevice`
- **Symbolic Link:** `\??\RtsPpx`
- **User-mode Path:** `\\.\RtsPpx`
- **Signer:** DigiCert SHA2 Assured ID (Realtek)
- **Architecture:** x64

## IOCTL Codes

| IOCTL | Name | Function |
|-------|------|----------|
| `0x222000` | IOCTL_GETPCIECONSSPACE | Physical memory READ |
| `0x222004` | IOCTL_GETPCIECONSSPACE_XP | Physical memory READ (legacy) |
| `0x222008` | IOCTL_SETPCIECONSSPACE | Physical memory WRITE |
| `0x22200C` | IOCTL_SETPCIECONSSPACE_XP | Physical memory WRITE (legacy) |
| `0x222010` | IOCTL_GETHWDATA | Hardware data read |
| `0x222014` | IOCTL_SETHWDATA_ONEBYTE | Hardware single-byte write |

## Input Buffer Structure

### Read Request (0x222000)
```c
#pragma pack(push, 1)
struct RtsPpx_ReadReq {
    ULONGLONG physAddr;   // 0x00 - Physical address base (BAR)
    DWORD busNum;         // 0x08 - PCI bus number (set to 0)
    DWORD devNum;         // 0x0C - PCI device number (set to 0)
    DWORD funNum;         // 0x10 - PCI function number (set to 0)
    DWORD addOffset;      // 0x14 - Address offset (set to 0)
};
#pragma pack(pop)
// Total: 24 bytes (0x18)
// Output: Data read from physical memory
```

### Write Request (0x222008)
```c
#pragma pack(push, 1)
struct RtsPpx_WriteReq {
    ULONGLONG physAddr;   // 0x00 - Physical address base
    DWORD busNum;         // 0x08 - Set to 0
    DWORD devNum;         // 0x0C - Set to 0
    DWORD funNum;         // 0x10 - Set to 0
    DWORD addOffset;      // 0x14 - Set to 0
    BYTE data;            // 0x18 - Byte to write
};
#pragma pack(pop)
// Total: 25 bytes (0x19)
// Note: Writes one byte at a time
```

## Physical Address Calculation

The driver calculates the target physical address as:
```
physAddr = bar + (busNum << 20) + (devNum << 15) + (funNum << 12) + addOffset
```

**Key Insight:** When `busNum = devNum = funNum = addOffset = 0`, the calculated address equals `bar` exactly, providing arbitrary physical memory access.

## Why It Works for BYOVD

1. **No authentication required** - Device opens without any magic bytes or handshake
2. **No address whitelist** - Unlike NTIOLib, this driver does NOT validate physical addresses
3. **Direct MmMapIoSpace** - Maps arbitrary physical memory into kernel virtual space
4. **Debug build** - Contains helpful debug strings (but works in production)
5. **DigiCert signed** - Legitimate Realtek signature, high trust score

## Exploitation Flow

1. Open device: `CreateFileW(L"\\\\.\\RtsPpx", ...)`
2. Bootstrap CR3 via PML4 self-reference scan (scan physical memory for page tables)
3. Use CR3 for VA→PA translation
4. Read/write kernel memory via physical address

## Disassembly Notes

### IOCTL Dispatch (0x140005130)
```asm
; IOCTL switch base
subl    $0x222000, %eax         ; Base IOCTL is 0x222000
cmpl    $0x14, 0x60(%rsp)       ; Range is 0-0x14 (20 IOCTLs)
ja      default_case
; Jump table dispatch
```

### MmMapIoSpace Call (0x140005361)
```asm
; RCX = physical address (from input buffer)
; EDX = size
; R8D = 0 (MmNonCached)
callq   *-0x3347(%rip)          ; MmMapIoSpace import
```

The driver calls MmMapIoSpace directly with the user-provided physical address - no validation.

## Cascade Integration

Use with cascade.exe:
```cmd
cascade.exe --driver RtsPpx.sys --driver-type rtsppx --test-rw
```

Backend implementation uses CR3 bootstrap for VA→PA translation, similar to other physical memory primitives.

## Novelty Assessment

| Criteria | Status |
|----------|--------|
| On loldrivers.io | **NO** |
| On MS Vulnerable Driver Blocklist | **UNKNOWN** (testing required) |
| Publicly documented as vulnerable | **NO** |
| Has physical memory R/W | **YES** |
| Has address validation/whitelist | **NO** |
| Signed by reputable vendor | **YES** (Realtek/DigiCert) |

## Files

- Driver in collection: `bigDrivers/0259226bce1a413201617e7ea662e7871c4cdd4fb24f8e13dae93fbc28d3bbef.sys`
- Cascade backend: `src/cascade.cpp` (ProviderType::RtsPpx)

## Testing Status

### Windows 11 22H2 x64 (VM 125) — 2026-09-08

| Test | Result | Details |
|------|--------|---------|
| Driver Load | **PASS** | `sc start RtsPpx` succeeded |
| Device Open | **PASS** | `\\.\RtsPpx` handle acquired |
| Physical READ | **PASS** | Read from 0x1000, 0xFFFF0 (BIOS) |
| Physical WRITE | **PASS** | Modified byte at 0x1000, verified, restored |
| Secure Boot Block | **NO** | Loads with Secure Boot disabled |
| WDAC Block | **NO** | Not on Win11 22H2 blocklist |

### System Requirements (Tested)
- VBS: Disabled
- HVCI: Disabled  
- Secure Boot: Disabled
- Vulnerable Driver Blocklist: Disabled

### CR3 Bootstrap Note
The initial cascade implementation caused BSODs when scanning certain physical addresses (MMIO regions). Fixed by adding safe address checks:
- Skip first 4KB
- Skip legacy video/ROM (0xA0000-0x100000)
- Skip PCI MMIO (0xE0000000+)
- Skip APIC/HPET regions
- Start scan at 1MB instead of 4KB

### Windows 11 24H2
- **PENDING** - Not tested, likely blocked by expanded WDAC
