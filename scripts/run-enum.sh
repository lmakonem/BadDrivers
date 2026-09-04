#!/bin/bash
# Deploy and execute driver enumeration on VM 125 via QGA
set -euo pipefail

PROXMOX_HOST="root@192.168.36.225"
VMID=125
SCRIPT_PATH="/Users/lmakonem/repos/Research/BadDrivers/scripts/enum-drivers.ps1"

echo "[*] Reading enumeration script..."
SCRIPT_CONTENT=$(cat "$SCRIPT_PATH")

# Base64 encode for PowerShell -EncodedCommand
ENCODED=$(echo -n "$SCRIPT_CONTENT" | iconv -f UTF-8 -t UTF-16LE | base64)

echo "[*] Deploying via QGA to VM $VMID..."

# Execute via QGA
ssh "$PROXMOX_HOST" "qm guest exec $VMID --synchronous 1 -- powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand '$ENCODED'" 2>&1 | tee /tmp/enum-output.log

echo ""
echo "[*] Retrieving results..."

# Pull back the JSON manifest
MANIFEST_B64=$(ssh "$PROXMOX_HOST" "qm guest exec $VMID --synchronous 1 -- powershell -NoProfile -Command 'Get-Content C:\\bad\\driver-inventory.json -Raw | % { [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(\$_)) }'" 2>&1 | grep -v "^exitcode" | tail -1)

if [ -n "$MANIFEST_B64" ]; then
    echo "$MANIFEST_B64" | base64 -d > driver-inventory.json
    echo "[+] Results saved to driver-inventory.json"

    # Parse and show high-priority targets
    echo ""
    echo "=== HIGH-PRIORITY TARGETS ==="
    jq -r '.[] | select(.Priority >= 60) | "\(.Priority) | \(.Name) | \(.Vendor) | Loaded=\(.Loaded) | Exposed=\(.DeviceExposed) | \(.DevicePath // "N/A")"' driver-inventory.json | column -t -s '|'
else
    echo "[-] Failed to retrieve manifest"
    exit 1
fi

echo ""
echo "[*] Next: Run scripts/setup-analysis-env.sh to enable test signing + WinDbg"
