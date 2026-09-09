#!/usr/bin/env bash
# Creates autounattend.iso from autounattend.xml (place alongside the XML)
# Uses hdiutil (macOS built-in) or mkisofs if available

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
UNATTEND_XML="$SCRIPT_DIR/autounattend.xml"
OUT="$SCRIPT_DIR/autounattend"       # hdiutil appends .iso automatically

if [ ! -f "$UNATTEND_XML" ]; then
    echo "[-] $UNATTEND_XML not found"; exit 1
fi

TMPDIR_ISO="$(mktemp -d)"
cp "$UNATTEND_XML" "$TMPDIR_ISO/autounattend.xml"

echo "[*] Building autounattend.iso..."
if command -v mkisofs &>/dev/null; then
    mkisofs -J -R -o "${OUT}.iso" "$TMPDIR_ISO"
else
    hdiutil makehybrid -iso -joliet -o "$OUT" "$TMPDIR_ISO"
fi

rm -rf "$TMPDIR_ISO"
echo "[+] Created: ${OUT}.iso"
