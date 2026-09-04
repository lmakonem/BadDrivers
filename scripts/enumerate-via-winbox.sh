#!/bin/bash
# Complete driver enumeration workflow via winbox on Proxmox
set -euo pipefail

PROXMOX="root@192.168.36.225"
VMID=201
OUTPUT_DIR="../deploy"

echo "[*] BadDrivers: Driver Enumeration via winbox"
echo "[*] Target: VM $VMID on $PROXMOX"
echo ""

# Helper function to run winbox commands
run_winbox() {
    ssh "$PROXMOX" "qm guest exec $VMID -- su - kali -c 'python3 -m winbox $*'" 2>&1
}

# Step 1: Verify winbox is running
echo "[1/5] Checking winbox VM status..."
STATUS=$(run_winbox status | grep -o '"out-data" : ".*"' | sed 's/"out-data" : "//;s/"$//' | sed 's/\\n/\n/g')
echo "$STATUS"
echo ""

# Step 2: Create enumeration script on Windows
echo "[2/5] Creating enumeration script..."
ENUM_SCRIPT='
$results = @()
Get-ChildItem C:\Windows\System32\drivers\*.sys | ForEach-Object {
    $loaded = Get-WmiObject Win32_SystemDriver | Where-Object { $_.PathName -like "*$($_.Name)*" }
    $results += [PSCustomObject]@{
        Name = $_.Name
        SizeKB = [math]::Round($_.Length/1KB, 1)
        Loaded = ($null -ne $loaded)
        State = if ($loaded) { $loaded.State } else { "Not Loaded" }
    }
}
$results | Export-Csv C:\temp\drivers.csv -NoTypeInformation
Write-Host "[+] Found $($results.Count) drivers"
Write-Host "[+] Loaded: $(($results | Where-Object Loaded).Count)"
$results | Where-Object Loaded | Select-Object -First 20 | Format-Table
'

# Encode script for safe transmission
ENCODED=$(echo -n "$ENUM_SCRIPT" | iconv -f UTF-8 -t UTF-16LE | base64)

echo "[3/5] Running enumeration on Windows VM..."
run_winbox exec "powershell -NoProfile -EncodedCommand $ENCODED"

# Wait for completion
echo "[4/5] Waiting for enumeration to complete..."
sleep 10

# Step 3: Retrieve results
echo "[5/5] Retrieving results..."
mkdir -p "$OUTPUT_DIR"
run_winbox exec "cmd /c type C:\\temp\\drivers.csv" | \
    grep -o '"out-data" : ".*"' | \
    sed 's/"out-data" : "//;s/"$//' | \
    sed 's/\\r\\n/\n/g' | \
    sed 's/\\"/"/g' > "$OUTPUT_DIR/drivers.csv"

echo ""
echo "[+] Enumeration complete!"
echo "[+] Results: $OUTPUT_DIR/drivers.csv"
echo ""

# Show summary
if [ -f "$OUTPUT_DIR/drivers.csv" ]; then
    TOTAL=$(wc -l < "$OUTPUT_DIR/drivers.csv")
    LOADED=$(grep -c "True" "$OUTPUT_DIR/drivers.csv" || echo "0")
    echo "Summary:"
    echo "  Total drivers: $((TOTAL - 1))"
    echo "  Loaded drivers: $LOADED"
    echo ""
    echo "High-priority targets (loaded drivers):"
    grep "True" "$OUTPUT_DIR/drivers.csv" | head -10
fi
