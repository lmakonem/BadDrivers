#!/usr/bin/env bash
# build.sh - cross-compile the BadDrivers payloads with mingw-w64 for Windows x86-64.
#
# Output dir: build/Release/
#   - cascade.exe         (primary: all BYOVD modes - PPL/token/dump/callbacks)
#   - warp.exe            (legacy: PPL strip + in-memory dump + XOR)
#   - byovd_sample2.exe   (reference: PPL strip only)
#
# cascade.exe ships alongside libwinpthread-1.dll from the MinGW toolchain.
# Safe by default: no network calls, no driver touched.
# Requires: brew install mingw-w64

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/build/Release"
mkdir -p "$OUT"

CC=x86_64-w64-mingw32-g++
if ! command -v "$CC" &>/dev/null; then
    echo "[-] $CC not found. brew install mingw-w64" >&2; exit 3
fi

COMMON=(-O2 -s -fno-ident -static-libgcc -static-libstdc++)

echo "[+] building cascade.exe"
$CC "${COMMON[@]}" "$ROOT/src/cascade.cpp" \
    -lws2_32 -lntdll -ldbghelp -lpsapi -ladvapi32 \
    -o "$OUT/cascade.exe"
echo "    $OUT/cascade.exe ($(du -h "$OUT/cascade.exe" | cut -f1))"

# Copy runtime DLL required by libstdc++ on the Windows target
PTHREAD_DLL="$(dirname "$(which "$CC")")/../x86_64-w64-mingw32/bin/libwinpthread-1.dll"
if [ -f "$PTHREAD_DLL" ]; then
    cp "$PTHREAD_DLL" "$OUT/libwinpthread-1.dll"
    echo "    $OUT/libwinpthread-1.dll"
else
    echo "[!] libwinpthread-1.dll not found; locate manually and ship with cascade.exe"
fi

echo "[+] building warp.exe"
$CC "${COMMON[@]}" "$ROOT/src/warp.cpp" \
    -lntdll -ldbghelp -lpsapi -ladvapi32 \
    -o "$OUT/warp.exe"
echo "    $OUT/warp.exe"

echo "[+] building byovd_sample2.exe"
$CC "${COMMON[@]}" "$ROOT/samples/byovd_sample2.cpp" \
    -lntdll -lpsapi -ladvapi32 \
    -o "$OUT/byovd_sample2.exe"
echo "    $OUT/byovd_sample2.exe"

echo ""
echo "[+] artifacts ready under $OUT"
ls -lh "$OUT/"
