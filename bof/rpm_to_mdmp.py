#!/usr/bin/env python3
"""Convert cascade.exe RPM dump to MDMP (MiniDump) format for pypykatz.

RPM format (per region): [base:8LE][size:8LE][data:N]
"""
import struct, sys, os, io

STREAM_SYSTEM_INFO  = 7
STREAM_MODULE_LIST  = 4
STREAM_MEMORY64_LIST = 9


def parse_rpm(path):
    regions = []
    with open(path, 'rb') as f:
        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            base, size = struct.unpack('<QQ', hdr)
            if size == 0 or size > 512 * 1024 * 1024:
                print(f"[!] Bad region size {size} at base 0x{base:016x}", file=sys.stderr)
                break
            data = f.read(size)
            if len(data) < size:
                print(f"[!] Truncated at 0x{base:016x}", file=sys.stderr)
                break
            regions.append((base, data))
    return regions


def stitch_pe_data(regions, pe_base):
    """Combine all adjacent/overlapping regions that belong to the same PE image."""
    # Build a map of base -> data
    region_map = {b: d for b, d in regions}
    # Read enough of the PE header to find image size
    hdr_data = region_map.get(pe_base, b'')
    if len(hdr_data) < 0x40:
        return hdr_data
    pe_off = struct.unpack_from('<I', hdr_data, 0x3C)[0]
    if pe_off + 24 > len(hdr_data):
        return hdr_data
    if hdr_data[pe_off:pe_off+4] != b'PE\x00\x00':
        return hdr_data
    magic = struct.unpack_from('<H', hdr_data, pe_off + 24)[0]
    if magic not in (0x10B, 0x20B):
        return hdr_data
    opt_size_off = pe_off + 24 + 56  # SizeOfImage at same offset for PE32 and PE32+
    if opt_size_off + 4 > len(hdr_data):
        return hdr_data
    image_size = struct.unpack_from('<I', hdr_data, opt_size_off)[0]
    if image_size == 0 or image_size > 512 * 1024 * 1024:
        return hdr_data

    # Collect all region bases in range [pe_base, pe_base+image_size)
    full = bytearray(image_size)
    for rbase, rdata in regions:
        if rbase >= pe_base and rbase < pe_base + image_size:
            off = rbase - pe_base
            end = min(off + len(rdata), image_size)
            full[off:end] = rdata[:end - off]
    return bytes(full)


def get_export_name(data):
    """Extract module name from PE export directory. Returns name string or None."""
    if len(data) < 0x40:
        return None
    if data[0:2] != b'MZ':
        return None
    pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    if pe_off + 28 > len(data):
        return None
    if data[pe_off:pe_off+4] != b'PE\x00\x00':
        return None
    magic = struct.unpack_from('<H', data, pe_off + 24)[0]
    if magic == 0x20B:  # PE32+
        opt_off = pe_off + 24
        img_size = struct.unpack_from('<I', data, opt_off + 56)[0]
        export_rva = struct.unpack_from('<I', data, opt_off + 112)[0]
    elif magic == 0x10B:  # PE32
        opt_off = pe_off + 24
        img_size = struct.unpack_from('<I', data, opt_off + 56)[0]
        export_rva = struct.unpack_from('<I', data, opt_off + 96)[0]
    else:
        return None

    if export_rva == 0 or export_rva + 40 > len(data):
        return None

    name_rva = struct.unpack_from('<I', data, export_rva + 12)[0]
    if name_rva == 0 or name_rva >= len(data):
        return None
    end = data.find(b'\x00', name_rva)
    if end < 0 or end - name_rva > 260:
        return None
    name = data[name_rva:end].decode('ascii', errors='replace')
    return name if name else None


def find_modules(regions):
    """Return list of (base, image_size, name) for each PE in the dump."""
    modules = []
    seen = set()
    bases_with_mz = []
    for base, data in regions:
        if base in seen:
            continue
        if len(data) >= 2 and data[0:2] == b'MZ':
            bases_with_mz.append(base)

    print(f"  Found {len(bases_with_mz)} MZ regions, stitching PE images...")
    for pe_base in bases_with_mz:
        if pe_base in seen:
            continue
        full_data = stitch_pe_data(regions, pe_base)
        name = get_export_name(full_data)
        if name is None:
            # Fallback: scan first 4096 bytes for ASCII .dll/.exe strings
            sample = full_data[:4096]
            for i in range(len(sample) - 6):
                end = sample.find(b'\x00', i, i + 256)
                if end < 0 or end - i < 5:
                    continue
                s = sample[i:end]
                if s.lower().endswith((b'.dll', b'.exe')):
                    try:
                        name = s.decode('ascii')
                        break
                    except (UnicodeDecodeError, ValueError):
                        pass
            if name is None:
                name = f"mod_{pe_base:016x}.dll"

        img_size = len(full_data)
        if len(full_data) >= 0x40:
            pe_off = struct.unpack_from('<I', full_data, 0x3C)[0]
            if pe_off + 80 <= len(full_data):
                magic = struct.unpack_from('<H', full_data, pe_off + 24)[0]
                if magic in (0x10B, 0x20B):
                    sz = struct.unpack_from('<I', full_data, pe_off + 24 + 56)[0]
                    if sz > 0:
                        img_size = sz

        seen.add(pe_base)
        modules.append((pe_base, img_size, name))
        print(f"    0x{pe_base:016x}  {img_size//1024:6d}KB  {name}")

    return modules


def make_mdmp(regions, output_path):
    print(f"[*] Converting {len(regions)} regions to MDMP...")
    total_mem = sum(len(d) for _, d in regions)
    print(f"[*] Total memory: {total_mem // 1024 // 1024}MB")

    print("[*] Detecting PE modules...")
    modules = find_modules(regions)
    print(f"[*] {len(modules)} modules identified")

    # SystemInfoStream (56 bytes)
    sysinfo = struct.pack('<HHHBBIIIII HH',
        9, 0, 0,        # Arch=AMD64, Level, Revision
        4, 1,           # NumProcs=4, ProductType=Workstation
        10, 0, 22621, 2,  # Major, Minor, Build, Platform
        0, 0, 0          # CSDVersionRva, SuiteMask, Reserved2
    )
    sysinfo = (sysinfo + b'\x00' * 56)[:56]

    # Build ModuleListStream payload
    # Each MINIDUMP_MODULE = 108 bytes
    MDMP_MODULE_SIZE = 108
    VS_FIXEDFILEINFO_SIZE = 52
    modlist_out = io.BytesIO()
    modlist_out.write(struct.pack('<I', len(modules)))
    entry_base = modlist_out.tell()  # 4
    # Write placeholder entries
    for _ in modules:
        modlist_out.write(b'\x00' * MDMP_MODULE_SIZE)
    # Write module name strings and record offsets
    name_stream_offsets = []
    for base, img_size, name in modules:
        name_stream_offsets.append(modlist_out.tell())
        name_w = name.encode('utf-16-le')
        modlist_out.write(struct.pack('<I', len(name_w)))
        modlist_out.write(name_w)
        modlist_out.write(b'\x00\x00')

    modlist_bytes = bytearray(modlist_out.getvalue())

    # Fill in module entries (ModuleNameRva = stream-relative offset, fixed after layout)
    vs_info = b'\xbd\x04\xef\xfe' + b'\x00' * (VS_FIXEDFILEINFO_SIZE - 4)
    for i, (base, img_size, name) in enumerate(modules):
        off = entry_base + i * MDMP_MODULE_SIZE
        entry = struct.pack('<QIIII', base, img_size, 0, 0, name_stream_offsets[i])
        entry += vs_info
        entry += b'\x00' * 32  # CvRecord(8)+MiscRecord(8)+Res0(8)+Res1(8)
        assert len(entry) == MDMP_MODULE_SIZE
        modlist_bytes[off:off + MDMP_MODULE_SIZE] = entry

    modlist_data = bytes(modlist_bytes)

    # Layout
    HDR_SIZE = 32
    NUM_STREAMS = 3
    DIR_SIZE = NUM_STREAMS * 12
    streams_start = HDR_SIZE + DIR_SIZE

    sysinfo_rva   = streams_start
    modlist_rva   = sysinfo_rva + len(sysinfo)
    mem64_rva     = modlist_rva + len(modlist_data)
    mem64_hdr_sz  = 8 + 8 + len(regions) * 16
    mem_data_rva  = mem64_rva + mem64_hdr_sz

    # Fix ModuleNameRva: add modlist_rva to each stream-relative offset
    modlist_ba = bytearray(modlist_data)
    for i in range(len(modules)):
        name_rva_off = entry_base + i * MDMP_MODULE_SIZE + 20  # offset of ModuleNameRva
        raw = struct.unpack_from('<I', modlist_ba, name_rva_off)[0]
        struct.pack_into('<I', modlist_ba, name_rva_off, modlist_rva + raw)
    modlist_data = bytes(modlist_ba)

    # Memory64ListStream
    mem64_stream = struct.pack('<QQ', len(regions), mem_data_rva)
    for base, data in regions:
        mem64_stream += struct.pack('<QQ', base, len(data))

    # MINIDUMP_HEADER (32 bytes)
    header = (b'MDMP' +
              struct.pack('<I', 0x0000A793) +   # Version
              struct.pack('<I', NUM_STREAMS) +
              struct.pack('<I', HDR_SIZE) +      # StreamDirectoryRva
              struct.pack('<I', 0) +             # CheckSum
              struct.pack('<I', 0) +             # TimeDateStamp
              struct.pack('<Q', 0x00000021))     # Flags

    # Directory
    directory = (struct.pack('<III', STREAM_SYSTEM_INFO,   len(sysinfo),     sysinfo_rva) +
                 struct.pack('<III', STREAM_MODULE_LIST,   len(modlist_data), modlist_rva) +
                 struct.pack('<III', STREAM_MEMORY64_LIST, mem64_hdr_sz,     mem64_rva))

    print(f"[*] Writing {output_path}...")
    with open(output_path, 'wb') as f:
        f.write(header)
        f.write(directory)
        f.write(sysinfo)
        f.write(modlist_data)
        f.write(mem64_stream)
        for _, data in regions:
            f.write(data)

    sz = os.path.getsize(output_path)
    with open(output_path, 'rb') as f:
        sig = f.read(4)
    print(f"[+] {output_path} ({sz // 1024 // 1024}MB), sig={sig!r}")


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <rpm_dump> <output.dmp>")
        sys.exit(1)
    regions = parse_rpm(sys.argv[1])
    print(f"[+] Parsed {len(regions)} regions")
    make_mdmp(regions, sys.argv[2])
