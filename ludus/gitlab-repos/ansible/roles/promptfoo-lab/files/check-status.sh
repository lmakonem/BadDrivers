#!/bin/bash
# PromptFoo Lab Status Check Script
# Verifies all lab components are running correctly

set -e

# Ensure HOME is set (needed when run via Proxmox guest agent or cron)
export HOME="${HOME:-/home/kali}"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================="
echo "  PromptFoo AI Security Lab Status Check"
echo "=========================================="
echo ""

ERRORS=0

# Check Ollama service
echo -n "Checking Ollama service... "
if systemctl is-active --quiet ollama; then
    echo -e "${GREEN}[OK]${NC}"
else
    echo -e "${RED}[FAILED]${NC}"
    ((ERRORS++))
fi

# Check Ollama API
echo -n "Checking Ollama API (port 11434)... "
if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
    echo -e "${GREEN}[OK]${NC}"
else
    echo -e "${RED}[FAILED]${NC}"
    ((ERRORS++))
fi

# Check Ollama model
echo -n "Checking Ollama model (llama3.2:3b)... "
if ollama list 2>/dev/null | grep -q "llama3.2:3b"; then
    echo -e "${GREEN}[OK]${NC}"
else
    echo -e "${YELLOW}[MISSING]${NC} - Run: ollama pull llama3.2:3b"
    ((ERRORS++))
fi

# Check chatbot service
echo -n "Checking chatbot service... "
if systemctl is-active --quiet chatbot; then
    echo -e "${GREEN}[OK]${NC}"
else
    echo -e "${RED}[FAILED]${NC}"
    ((ERRORS++))
fi

# Check chatbot API
echo -n "Checking chatbot API (port 5000)... "
if curl -s http://localhost:5000/health > /dev/null 2>&1; then
    echo -e "${GREEN}[OK]${NC}"
else
    echo -e "${RED}[FAILED]${NC}"
    ((ERRORS++))
fi

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

echo ""
echo "=========================================="

if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}All checks passed! Lab is ready.${NC}"
    echo ""
    echo "Quick start:"
    echo "  1. Open browser: http://localhost:5000"
    echo "  2. Chat with the bot and try prompt injection"
    echo "  3. Run PromptFoo scan: cd ~/lab && promptfoo redteam run"
    echo ""
    exit 0
else
    echo -e "${RED}$ERRORS check(s) failed.${NC}"
    echo ""
    echo "Troubleshooting:"
    echo "  - Check Ollama logs: journalctl -u ollama -f"
    echo "  - Check chatbot logs: journalctl -u chatbot -f"
    echo "  - Restart services: sudo systemctl restart ollama chatbot"
    echo ""
    exit 1
fi
