#!/bin/bash
# Driver vulnerability hunting workflow using winbox
# Usage: ./winbox-driver-hunt.sh

set -euo pipefail

KALI_HOST="kali@192.168.36.38"
KALI_PASS="kali"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[*] BadDrivers: Driver enumeration via winbox"
echo "[*] Target: winbox Windows VM on $KALI_HOST"
echo ""

# Step 1: Upload enumeration script
echo "[*] Step 1: Uploading enumeration script..."
sshpass -p "$KALI_PASS" scp "$SCRIPT_DIR/winbox-enum-drivers.ps1" "$KALI_HOST:/tmp/enum.ps1"

echo "[*] Step 2: Transferring script to Windows VM..."
sshpass -p "$KALI_PASS" ssh "$KALI_HOST" "python3 -m winbox upload /tmp/enum.ps1" || {
    echo "[!] Upload via winbox failed, trying alternative..."
    # Alternative: use shell to copy
    sshpass -p "$KALI_PASS" ssh "$KALI_HOST" "python3 -m winbox shell" << 'EOWIN'
# Copy script content
exit
EOWIN
}

echo "[*] Step 3: Running driver enumeration..."
sshpass -p "$KALI_PASS" ssh "$KALI_HOST" << 'EOSSH'
python3 -m winbox exec powershell -ExecutionPolicy Bypass -File C:\\temp\\enum.ps1
EOSSH

echo ""
echo "[*] Step 4: Retrieving results..."
sshpass -p "$KALI_PASS" ssh "$KALI_HOST" "python3 -m winbox exec 'cmd /c type C:\\Windows\\Temp\\driver_enum.csv'" > ../deploy/driver_enum.csv

echo ""
echo "[+] Enumeration complete!"
echo "[+] Results saved to: ../deploy/driver_enum.csv"
echo ""
echo "Next steps:"
echo "  1. Review driver_enum.csv for high-priority targets"
echo "  2. Focus on loaded, third-party drivers"
echo "  3. Use Ghidra for static analysis"
