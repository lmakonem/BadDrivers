#!/bin/bash
# PromptFoo Student Lab Status Check Script
# Verifies all lab components are ready

set -e

# Ensure HOME is set (needed when run via Proxmox guest agent)
export HOME="${HOME:-/home/kali}"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Read chatbot server from config if available
if [ -f ~/lab/promptfooconfig.yaml ]; then
    CHATBOT_URL=$(grep -oP 'url:\s*"\K[^"]+' ~/lab/promptfooconfig.yaml | head -1 | sed 's|/api/prompt||')
else
    CHATBOT_URL="http://10.2.20.50:5000"
fi

echo "=========================================="
echo "  PromptFoo AI Security Lab Status Check"
echo "=========================================="
echo ""
echo "Target: $CHATBOT_URL"
echo ""

ERRORS=0

# Check Node.js
echo -n "Checking Node.js... "
if command -v node &> /dev/null; then
    NODE_VERSION=$(node --version)
    echo -e "${GREEN}[OK]${NC} ($NODE_VERSION)"
else
    echo -e "${RED}[FAILED]${NC}"
    ((ERRORS++))
fi

# Check PromptFoo
echo -n "Checking PromptFoo CLI... "
if command -v promptfoo &> /dev/null; then
    PROMPTFOO_VERSION=$(promptfoo --version 2>/dev/null || echo "unknown")
    echo -e "${GREEN}[OK]${NC} ($PROMPTFOO_VERSION)"
else
    echo -e "${RED}[FAILED]${NC}"
    ((ERRORS++))
fi

# Check chatbot connectivity
echo -n "Checking chatbot server... "
if curl -s "${CHATBOT_URL}/health" > /dev/null 2>&1; then
    echo -e "${GREEN}[OK]${NC}"
else
    echo -e "${RED}[FAILED]${NC} - Cannot reach ${CHATBOT_URL}"
    ((ERRORS++))
fi

# Check lab files
echo -n "Checking lab files... "
if [ -f ~/lab/promptfooconfig.yaml ] && [ -f ~/lab/chat.sh ]; then
    echo -e "${GREEN}[OK]${NC}"
else
    echo -e "${RED}[MISSING]${NC}"
    ((ERRORS++))
fi

echo ""
echo "=========================================="

if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}All checks passed! Lab is ready.${NC}"
    echo ""
    echo "Quick start:"
    echo "  1. Open browser: $CHATBOT_URL"
    echo "  2. Chat with the bot: ./chat.sh \"Hello\""
    echo "  3. Run PromptFoo scan: cd ~/lab && promptfoo redteam run"
    echo ""
    exit 0
else
    echo -e "${RED}$ERRORS check(s) failed.${NC}"
    echo ""
    echo "Troubleshooting:"
    echo "  - Verify chatbot server is running"
    echo "  - Check network connectivity to $CHATBOT_URL"
    echo ""
    exit 1
fi
