#!/usr/bin/env python3
"""
Convert DumpRpm custom format to MiniDump format parseable by pypykatz.
Custom format: each region = [base_addr:8LE][size:8LE][data:size]
Scans PE headers, uses cross-region VA lookup for export names.
"""
import struct, sys, time, os

def read_u16(data, off):
    if off + 2 > len(data): return 0
    return struct.unpack_from('<H', data, off)[0]

def read_u32(data, off):
    if off + 4 > len(data): return 0
    return struct.unpack_from('<I', data, off)[0]

def va_read(mem_map, va, size):
    """Read `size` bytes from virtual address va using mem_map sorted list."""
    for (base, end, data) in mem_map:
        if base <= va < end:
            off = va - base
            return data[off:off+size]
    return b''

def va_read_str(mem_map, va):
    """Read null-terminated ASCII string from virtual address."""
    result = []
    for i in range(256):
        b = va_read(mem_map, va + i, 1)
        if not b or b[0] == 0:
            break
        result.append(b[0])
    try:
        return bytes(result).decode('ascii', errors='replace')
    except Exception:
        return ''

def get_pe_info(mem_map, base):
    """Return (size_of_image, module_name) for PE at base, using cross-region reads."""
    hdr = va_read(mem_map, base, 0x40)
    if len(hdr) < 0x40 or hdr[:2] != b'MZ':
        return None
    e_lfanew = struct.unpack_from('<I', hdr, 0x3C)[0]
    pe_sig = va_read(mem_map, base + e_lfanew, 4)
    if pe_sig != b'PE\x00\x00':
        return None
    machine = struct.unpack_from('<H', va_read(mem_map, base + e_lfanew + 4, 2))[0]
    if machine not in (0x8664, 0x014C):
        return None

    opt_off = base + e_lfanew + 24
    opt_hdr = va_read(mem_map, opt_off, 8)
    if len(opt_hdr) < 2:
        return None
    magic = struct.unpack_from('<H', opt_hdr)[0]

    if magic == 0x020B:  # PE32+ x64
        fields = va_read(mem_map, opt_off, 120)
        if len(fields) < 120: return None
        size_of_image = struct.unpack_from('<I', fields, 56)[0]
        export_rva    = struct.unpack_from('<I', fields, 112)[0]
    elif magic == 0x010B:  # PE32
        fields = va_read(mem_map, opt_off, 104)
        if len(fields) < 104: return None
        size_of_image = struct.unpack_from('<I', fields, 56)[0]
        export_rva    = struct.unpack_from('<I', fields, 96)[0]
    else:
        return None

    if size_of_image == 0:
        return None

    module_name = None
    if export_rva:
        exp_dir = va_read(mem_map, base + export_rva, 16)
        if len(exp_dir) >= 16:
            name_rva = struct.unpack_from('<I', exp_dir, 12)[0]
            if name_rva:
                module_name = va_read_str(mem_map, base + name_rva)

    return (size_of_image, module_name)

def make_minidump_string(s):
    enc = s.encode('utf-16-le')
    return struct.pack('<I', len(enc)) + enc

def convert(in_path, out_path):
    regions = []
    with open(in_path, 'rb') as f:
        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            base, size = struct.unpack('<QQ', hdr)
            data = f.read(size)
            if len(data) < size:
                print(f"[!] Truncated at base=0x{base:X}", file=sys.stderr)
                break
            regions.append((base, data))

    print(f"[+] Parsed {len(regions)} memory regions", file=sys.stderr)

    # Build VA map for cross-region lookups
    mem_map = [(base, base + len(data), data) for base, data in regions]
    mem_map.sort(key=lambda x: x[0])

    # Scan for PE headers
    modules = []
    seen_bases = set()
    for base, data in regions:
        if base in seen_bases:
            continue
        # Check if this region starts with MZ (first 2 bytes)
        if len(data) < 2 or data[:2] != b'MZ':
            continue
        result = get_pe_info(mem_map, base)
        if result:
            seen_bases.add(base)
            size_img, name = result
            display_name = name or f'module_{base:X}.dll'
            modules.append((base, size_img, display_name))
            print(f"    PE @ 0x{base:016X}  size=0x{size_img:X}  name={name}", file=sys.stderr)

    print(f"[+] Found {len(modules)} PE modules", file=sys.stderr)

    # Layout: HEADER(32) + DIR(12*3) + SYSINFO(56) + MODLIST + STRING_POOL + MEM64LIST + DATA
    N_STREAMS = 3
    hdr_size  = 32
    dir_size  = 12 * N_STREAMS

    sysinfo_rva  = hdr_size + dir_size
    sysinfo_size = 56
    sysinfo_data = struct.pack('<HHHBBI', 0x0009, 0, 0, 1, 1, 10)
    sysinfo_data += struct.pack('<IIIIHH', 0, 22621, 2, 0, 0, 0)
    sysinfo_data = sysinfo_data.ljust(56, b'\x00')

    # MINIDUMP_MODULE = 108 bytes
    mod_list_rva   = sysinfo_rva + sysinfo_size
    mod_entry_size = 108
    mod_list_fixed = 4 + len(modules) * mod_entry_size
    string_pool_rva_base = mod_list_rva + mod_list_fixed

    string_pool = b''
    mod_name_rvas = []
    for base, size_img, name in modules:
        full = name if '\\' in name else f"C:\\Windows\\System32\\{name}"
        s_bytes = make_minidump_string(full)
        mod_name_rvas.append(string_pool_rva_base + len(string_pool))
        string_pool += s_bytes

    mod_list_size = mod_list_fixed + len(string_pool)
    mem64_rva  = mod_list_rva + mod_list_size
    mem64_size = 8 + 8 + len(regions) * 16
    data_start_rva = mem64_rva + mem64_size

    total = data_start_rva + sum(len(d) for _, d in regions)
    print(f"[+] Building MiniDump: {len(modules)} modules, {len(regions)} regions, {total:,} bytes", file=sys.stderr)

    with open(out_path, 'wb') as f:
        # MINIDUMP_HEADER (32 bytes): Sig(4)+Ver(4)+NumStreams(4)+DirRva(4)+Checksum(4)+Timestamp(4)+Flags(8)
        f.write(struct.pack('<IIIIII', 0x504D444D, 0x0000A793, N_STREAMS, hdr_size, 0, int(time.time())))
        f.write(struct.pack('<Q', 0))  # Flags

        # Directories
        f.write(struct.pack('<III', 7, sysinfo_size, sysinfo_rva))   # SystemInfo
        f.write(struct.pack('<III', 4, mod_list_size, mod_list_rva)) # ModuleList
        f.write(struct.pack('<III', 9, mem64_size, mem64_rva))       # Memory64List

        # SystemInfo
        f.write(sysinfo_data)

        # ModuleList: count + entries
        f.write(struct.pack('<I', len(modules)))
        for i, (base, size_img, name) in enumerate(modules):
            f.write(struct.pack('<Q', base))              # BaseOfImage
            f.write(struct.pack('<I', size_img))          # SizeOfImage
            f.write(struct.pack('<I', 0))                 # CheckSum
            f.write(struct.pack('<I', 0))                 # TimeDateStamp
            f.write(struct.pack('<I', mod_name_rvas[i]))  # ModuleNameRva
            f.write(b'\x00' * 52)                         # VS_FIXEDFILEINFO
            f.write(b'\x00' * 8)                          # CvRecord
            f.write(b'\x00' * 8)                          # MiscRecord
            f.write(b'\x00' * 16)                         # Reserved0+1

        # String pool
        f.write(string_pool)

        # Memory64List
        f.write(struct.pack('<Q', len(regions)))          # NumberOfMemoryRanges
        f.write(struct.pack('<Q', data_start_rva))        # BaseRva
        for base, data in regions:
            f.write(struct.pack('<Q', base))
            f.write(struct.pack('<Q', len(data)))

        # Memory data
        for _, data in regions:
            f.write(data)

    actual = os.path.getsize(out_path)
    print(f"[+] Written: {out_path} ({actual:,} bytes)", file=sys.stderr)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input_rpm_dump> <output.dmp>")
        sys.exit(1)
    convert(sys.argv[1], sys.argv[2])
