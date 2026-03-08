#!/usr/bin/env bash
#
# Deploy Red Team Demo to Kali C2 Server
# ========================================
# Deploys the supply chain attack demo to the lab Kali C2.
#
# Usage:
#     ./deploy_to_kali.sh [KALI_IP]
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_ROOT="$(dirname "$SCRIPT_DIR")"

# Lab configuration
KALI_IP="${1:-192.168.36.172}"
KALI_USER="kali"
KALI_PASS="kali"
C2_PORT="8888"
GITEA_PORT="8080"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${RED}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           DEPLOY RED TEAM DEMO TO KALI C2                    ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Target: $KALI_IP                                        ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if sshpass is available
if ! command -v sshpass &> /dev/null; then
    echo -e "${YELLOW}[!] sshpass not found. Install with: brew install hudochenkov/sshpass/sshpass${NC}"
    echo "    Or use manual deployment (see below)"
    echo ""
fi

echo -e "${BLUE}[*] Creating deployment package...${NC}"

# Create temp directory for deployment
DEPLOY_DIR=$(mktemp -d)
trap "rm -rf $DEPLOY_DIR" EXIT

# Copy required files
mkdir -p "$DEPLOY_DIR/red_team_demo"
cp -r "$DEMO_ROOT/c2_server" "$DEPLOY_DIR/red_team_demo/"
cp -r "$DEMO_ROOT/gitea_server" "$DEPLOY_DIR/red_team_demo/"
cp -r "$DEMO_ROOT/git_hooks" "$DEPLOY_DIR/red_team_demo/"
cp -r "$DEMO_ROOT/payloads" "$DEPLOY_DIR/red_team_demo/"
cp -r "$DEMO_ROOT/xcode_implant" "$DEPLOY_DIR/red_team_demo/"
cp -r "$DEMO_ROOT/scripts" "$DEPLOY_DIR/red_team_demo/"
cp -r "$DEMO_ROOT/docs" "$DEPLOY_DIR/red_team_demo/"
cp "$DEMO_ROOT/README.md" "$DEPLOY_DIR/red_team_demo/"
cp "$DEMO_ROOT/LAB_CONFIG.md" "$DEPLOY_DIR/red_team_demo/" 2>/dev/null || true

# Also copy the demo project
if [ -d "$DEMO_ROOT/demo_project" ]; then
    cp -r "$DEMO_ROOT/demo_project" "$DEPLOY_DIR/red_team_demo/"
fi

# Create tarball
TARBALL="$DEPLOY_DIR/red_team_demo.tar.gz"
tar -czf "$TARBALL" -C "$DEPLOY_DIR" red_team_demo

echo -e "${GREEN}[+] Package created: $(du -h "$TARBALL" | cut -f1)${NC}"

echo ""
echo -e "${BLUE}[*] Deployment options:${NC}"
echo ""
echo "=== OPTION 1: SCP Transfer (if SSH key auth) ==="
echo -e "${YELLOW}scp $TARBALL $KALI_USER@$KALI_IP:~/${NC}"
echo ""

echo "=== OPTION 2: Manual Transfer ==="
echo "1. Copy tarball to Kali:"
echo -e "   ${YELLOW}scp red_team_demo.tar.gz kali@$KALI_IP:~/${NC}"
echo ""
echo "2. SSH into Kali and extract:"
echo -e "   ${YELLOW}ssh kali@$KALI_IP${NC}"
echo -e "   ${YELLOW}tar -xzf red_team_demo.tar.gz${NC}"
echo -e "   ${YELLOW}cd red_team_demo/scripts && ./setup.sh${NC}"
echo ""

echo "=== OPTION 3: HTTP Transfer ==="
echo "Start temp HTTP server on this machine:"
echo -e "${YELLOW}cd $DEPLOY_DIR && python3 -m http.server 9999${NC}"
echo ""
echo "On Kali:"
echo -e "${YELLOW}wget http://YOUR_IP:9999/red_team_demo.tar.gz${NC}"
echo ""

# Try to copy the tarball to current directory for easier access
cp "$TARBALL" "$DEMO_ROOT/red_team_demo.tar.gz" 2>/dev/null || true

echo -e "${GREEN}[+] Tarball also saved to: $DEMO_ROOT/red_team_demo.tar.gz${NC}"
echo ""

echo "=== After deploying to Kali, run: ==="
echo ""
echo "# On Kali C2 (192.168.36.172):"
echo -e "${YELLOW}cd ~/red_team_demo/scripts && ./setup.sh${NC}"
echo -e "${YELLOW}source ../.venv/bin/activate${NC}"
echo -e "${YELLOW}python3 ../c2_server/c2_server.py --host 0.0.0.0 --port $C2_PORT${NC}"
echo ""
echo "# In another terminal - Start Gitea simulator:"
echo -e "${YELLOW}python3 ../gitea_server/gitea_simulator.py --host 0.0.0.0 --port $GITEA_PORT --c2 http://$KALI_IP:$C2_PORT${NC}"
echo ""
echo "# C2 Dashboard: http://$KALI_IP:$C2_PORT/admin"
echo "# Gitea (malicious repos): http://$KALI_IP:$GITEA_PORT"
echo ""

# Keep tarball accessible
trap - EXIT
echo -e "${GREEN}[+] Deployment package ready!${NC}"
