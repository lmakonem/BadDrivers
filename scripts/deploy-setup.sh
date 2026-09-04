#!/bin/bash
# Deploy and execute analysis environment setup on .210
set -euo pipefail

PROXMOX_HOST="root@192.168.36.225"
VMID=125
SETUP_SCRIPT="/Users/lmakonem/repos/Research/BadDrivers/scripts/setup-analysis-env.ps1"

echo "[*] Deploying analysis environment setup to VM $VMID..."

# Read and encode setup script
SCRIPT_CONTENT=$(cat "$SETUP_SCRIPT")
ENCODED=$(echo -n "$SCRIPT_CONTENT" | iconv -f UTF-8 -t UTF-16LE | base64)

echo "[*] Executing via QGA (requires Administrator)..."

# Execute setup script
ssh "$PROXMOX_HOST" "qm guest exec $VMID --synchronous 1 -- powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand '$ENCODED'" 2>&1 | tee /tmp/setup-output.log

echo ""
echo "[*] Setup complete. Check output above for reboot requirement."
echo ""
echo "If reboot is needed:"
echo "  1. Reboot VM manually: ssh $PROXMOX_HOST 'qm reboot $VMID'"
echo "  2. Wait ~60 seconds for boot"
echo "  3. Run scripts/run-enum.sh to enumerate drivers"
