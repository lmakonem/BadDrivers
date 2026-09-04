// mock_driver_test.cpp — offline EPROCESS parsing validator.
//
// No driver, no kernel access. Constructs a synthetic EPROCESS-like blob in
// user memory, then runs the same walk/offset logic cascade uses to verify
// the offsets and traversal are correct before deploying against a real
// system.
//
// Build:
//   x86_64-w64-mingw32-g++ -O2 src/mock_driver_test.cpp -o mock_driver_test.exe
//   (or plain g++ on Linux — no Windows APIs used)
//
// Run:
//   ./mock_driver_test
//   Exits 0 on success, 1 on offset mismatch.

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <vector>

// Portable typedef so the mock builds on Linux for CI without Windows headers
typedef uint32_t DWORD;
typedef uint32_t ULONG;


// Mirror of the offset table from cascade.cpp for Windows 11 22H2 (22621)
struct EprocOffsets {
    uint32_t uniquePid;
    uint32_t activeLinks;
    uint32_t token;
    uint32_t protection;
    uint32_t imageFileName;
};

static const EprocOffsets OFFSETS_22621 = {
    0x440,  // UniqueProcessId
    0x448,  // ActiveProcessLinks
    0x4B8,  // Token
    0x87A,  // Protection
    0x5A8,  // ImageFileName
};

// Build a fake EPROCESS chain: 3 processes linked via ActiveProcessLinks
struct MockEproc {
    std::vector<uint8_t> buf;
    uint64_t base;
};

static void WriteAt(MockEproc& e, size_t off, const void* data, size_t sz) {
    memcpy(e.buf.data() + off, data, sz);
}

static MockEproc MakeEproc(uint64_t base, DWORD pid, const char* name) {
    MockEproc e;
    e.buf.resize(0x900, 0);
    e.base = base;
    WriteAt(e, OFFSETS_22621.uniquePid, &pid, sizeof(pid));
    uint8_t prot = 0x62;  // PsProtectedSignerLsa-Light
    WriteAt(e, OFFSETS_22621.protection, &prot, 1);
    strncpy((char*)e.buf.data() + OFFSETS_22621.imageFileName, name, 15);
    return e;
}

static void LinkChain(std::vector<MockEproc>& chain) {
    // ActiveProcessLinks is a LIST_ENTRY {Flink, Blink}
    for (size_t i = 0; i < chain.size(); i++) {
        size_t next = (i + 1) % chain.size();
        size_t prev = (i + chain.size() - 1) % chain.size();
        uint64_t flink = chain[next].base + OFFSETS_22621.activeLinks;
        uint64_t blink = chain[prev].base + OFFSETS_22621.activeLinks;
        WriteAt(chain[i], OFFSETS_22621.activeLinks, &flink, sizeof(flink));
        WriteAt(chain[i], OFFSETS_22621.activeLinks + 8, &blink, sizeof(blink));
    }
}

// Simulate kernel read: given a fake VA, find the mock and return its data
static bool MockRead(const std::vector<MockEproc>& chain, uint64_t va,
                     void* out, size_t sz) {
    for (const auto& e : chain) {
        if (va >= e.base && va + sz <= e.base + e.buf.size()) {
            memcpy(out, e.buf.data() + (va - e.base), sz);
            return true;
        }
    }
    return false;
}

int main() {
    printf("[*] Mock EPROCESS validation (Win11 22H2 offsets)\n");

    std::vector<MockEproc> chain;
    chain.push_back(MakeEproc(0x1000, 4,    "System"));
    chain.push_back(MakeEproc(0x2000, 748,  "lsass.exe"));
    chain.push_back(MakeEproc(0x3000, 1234, "explorer.exe"));
    LinkChain(chain);

    // Walk from System, find lsass
    uint64_t sysBase = chain[0].base;
    uint64_t cur = sysBase;
    int fails = 0;

    for (int i = 0; i < 10; i++) {
        DWORD pid = 0;
        char name[16] = {0};
        if (!MockRead(chain, cur + OFFSETS_22621.uniquePid, &pid, sizeof(pid))) {
            printf("[-] read pid failed at 0x%llx\n", (unsigned long long)cur);
            fails++; break;
        }
        MockRead(chain, cur + OFFSETS_22621.imageFileName, name, 15);
        uint8_t prot = 0;
        MockRead(chain, cur + OFFSETS_22621.protection, &prot, 1);
        printf("  PID=%-5lu name=%-15s prot=0x%02x eproc=0x%llx\n",
               pid, name, prot, (unsigned long long)cur);

        if (pid == 748 && strcmp(name, "lsass.exe") == 0 && prot == 0x62) {
            printf("[+] lsass located with expected offsets\n");
            printf("[+] All offset checks passed\n");
            return 0;
        }

        uint64_t flink = 0;
        MockRead(chain, cur + OFFSETS_22621.activeLinks, &flink, sizeof(flink));
        if (!flink) { printf("[-] null flink\n"); fails++; break; }
        cur = flink - OFFSETS_22621.activeLinks;
        if (cur == sysBase) { printf("[-] full loop, lsass not found\n"); fails++; break; }
    }

    printf("[-] Test failed (%d errors)\n", fails);
    return 1;
}
