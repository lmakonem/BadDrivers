#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <vector>

typedef uint32_t DWORD;
typedef uint32_t ULONG;


struct EprocOffsets {
    uint32_t uniquePid;
    uint32_t activeLinks;
    uint32_t token;
    uint32_t protection;
    uint32_t imageFileName;
};

static const EprocOffsets OFFSETS_22621 = {
    0x440,
    0x448,
    0x4B8,
    0x87A,
    0x5A8,
};

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
    uint8_t prot = 0x62;
    WriteAt(e, OFFSETS_22621.protection, &prot, 1);
    strncpy((char*)e.buf.data() + OFFSETS_22621.imageFileName, name, 15);
    return e;
}

static void LinkChain(std::vector<MockEproc>& chain) {
    for (size_t i = 0; i < chain.size(); i++) {
        size_t next = (i + 1) % chain.size();
        size_t prev = (i + chain.size() - 1) % chain.size();
        uint64_t flink = chain[next].base + OFFSETS_22621.activeLinks;
        uint64_t blink = chain[prev].base + OFFSETS_22621.activeLinks;
        WriteAt(chain[i], OFFSETS_22621.activeLinks, &flink, sizeof(flink));
        WriteAt(chain[i], OFFSETS_22621.activeLinks + 8, &blink, sizeof(blink));
    }
}

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
