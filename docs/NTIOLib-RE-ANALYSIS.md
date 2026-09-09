# NTIOLib_MysticLight Reverse Engineering Analysis

**Date:** 2026-09-08  
**Driver:** NTIOLib.sys (MSI MysticLight)  
**Version:** 3.0.0.13  
**SHA256:** cdd6afd9b7146626ccb145e14d8d27c1929ff969962d6138be1d4b928f2ac83a

## Summary

**FINDING: NTIOLib is NOT suitable for BYOVD kernel memory access.**

The driver restricts physical memory access to specific hardware MMIO regions (RGB controller addresses). It cannot read arbitrary physical memory needed for EPROCESS traversal.

## Device Information

- **Device Name:** `\\.\NTIOLib_MysticLight`
- **Signer:** MSI (valid signature)
- **Architecture:** x64

## IOCTL Codes (Discovered via RE)

| IOCTL | Function | Description |
|-------|----------|-------------|
| `0xc350214c` | Auth | Input: 4-byte magic `0x2f405a34`, enables other IOCTLs |
| `0xc3502000` | Unknown | - |
| `0xc3502004` | Status read | Returns global status DWORD |
| `0xc3502084` | Port Read | I/O port read (whitelisted ports only) |
| `0xc3502088` | Port Write | I/O port write |
| `0xc350a108` | MMIO Read | **Whitelisted addresses only** |
| `0xc350a148` | MMIO Write | **Whitelisted addresses only** |

## Authentication Mechanism

Before using any IOCTLs, must call `0xc350214c` with:
- Input buffer: 4 bytes = `0x2f405a34`
- This sets a global flag checked by other handlers

## Physical Memory Access Restriction

The MMIO read/write IOCTLs (`0xc350a108`, `0xc350a148`) validate physical addresses against a whitelist:

```
Allowed address ranges (PhysAddr >> 16 must match):
- 0xe06d (MMIO base)
- 0xfd6e
- 0xfdae  
- 0xfdc3
- 0xfdd1
- 0xfdd5
- 0xfdd9 (final check)
```

These are specific PCI/MMIO regions for RGB LED controller hardware, NOT general physical memory.

## Buffer Structures

### IOCTL 0xc350a108 (MMIO Read)
```c
struct NTIOLib_ReadReq {
    QWORD PhysAddr;      // offset 0, must be in whitelist
    DWORD ElemSize;      // offset 8, must be 1-4
    DWORD Count;         // offset 12
};
// Output: Count * ElemSize bytes at offset 0x10 in same buffer
```

### IOCTL 0xc3502084 (Port Read)
```c
// Input: 4-byte port number (must be in whitelist)
// Output: Port value
// Whitelisted ports: 0x35, 0xce, 0x10a, 0x150, 0x194, 0x195, 0x196,
//                    0x1a0, 0x1a2, 0x1ad, 0x1ae, 0x1af, 0x1b1, 0x300,
//                    0x301, 0x383, 0x601
```

## Why It Won't Work for BYOVD

1. **No arbitrary physical memory access** - Whitelist restricts to specific MMIO regions
2. **Cannot read EPROCESS** - Kernel structures are not in allowed regions
3. **Cannot scan for CR3** - PML4 self-reference scan requires low physical memory access

## Recommendations

For BYOVD credential dumping, use drivers that provide:
- Arbitrary physical memory R/W (MmMapIoSpace without address validation)
- Or arbitrary kernel R/W (direct MDL mapping)

Working alternative: **BiosToolCommonDriver.sys** - confirmed to have arbitrary physical memory access.

## Disassembly Notes

Key code at `0x140001808` (MMIO Read handler):
```asm
; Check authentication magic
cmpl $0x2f405a34, 0x29fe(%rip)
jne  fail

; Check output buffer size >= 16
cmpl $0x10, %edx
jb   fail

; Get ElemSize from input+8, must be 1-4
movl 0x8(%rcx), %ecx
leal -0x1(%rcx), %eax
cmpl $0x3, %eax
ja   fail

; Validate physical address against whitelist at 0x140001867
; Only specific MMIO regions allowed
```

## Files

- Driver analyzed: `C:\Users\Public\byovd\NTIOLib.sys`
- Partial local copy: `/tmp/NTIOLib.sys` (29KB, truncated during transfer)
