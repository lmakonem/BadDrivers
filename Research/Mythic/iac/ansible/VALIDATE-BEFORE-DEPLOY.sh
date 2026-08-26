#!/bin/bash
# Pre-deployment validation script
# Run from lab network with SSH access to VMs

set -e

# Cleanup on exit
trap 'rm -f /tmp/test_inventory.ini /tmp/validate_$$.tmp 2>/dev/null' EXIT

echo "╔══════════════════════════════════════════════════════════╗"
echo "║     Mythic IaC Pre-Deployment Validation                 ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Configuration
MYTHIC_IP="${MYTHIC_IP:-10.23.20.10}"
REDIRECTOR_IP="${REDIRECTOR_IP:-192.168.36.117}"
SARDONIC_IP="${SARDONIC_IP:-192.168.36.122}"
SSH_USER="${SSH_USER:-localuser}"

echo "[1] Network Connectivity Checks"
echo "─────────────────────────────────"

# Check Mythic
echo -n "→ Mythic (${MYTHIC_IP}):22 ... "
if timeout 3 bash -c "echo > /dev/tcp/${MYTHIC_IP}/22" 2>/dev/null; then
  echo "✓ Reachable"
  MYTHIC_OK=1
else
  echo "✗ Unreachable"
  MYTHIC_OK=0
fi

# Check Redirector
echo -n "→ Redirector (${REDIRECTOR_IP}):22 ... "
if timeout 3 bash -c "echo > /dev/tcp/${REDIRECTOR_IP}/22" 2>/dev/null; then
  echo "✓ Reachable"
  REDIRECTOR_OK=1
else
  echo "✗ Unreachable"
  REDIRECTOR_OK=0
fi

# Check Sardonic (optional)
echo -n "→ Sardonic (${SARDONIC_IP}):22 ... "
if timeout 3 bash -c "echo > /dev/tcp/${SARDONIC_IP}/22" 2>/dev/null; then
  echo "✓ Reachable"
  SARDONIC_OK=1
else
  echo "⊘ Unreachable (optional)"
  SARDONIC_OK=0
fi

echo ""
echo "[2] SSH Authentication Checks"
echo "─────────────────────────────"

# Test Mythic SSH
echo -n "→ SSH to mythic-01 (${MYTHIC_IP}) ... "
if ssh -o ConnectTimeout=3 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=accept-new ${SSH_USER}@${MYTHIC_IP} "echo 'SSH OK'" 2>/dev/null | grep -q "SSH OK"; then
  echo "✓ Connected"
else
  echo "✗ Failed (check credentials/keys)"
  exit 1
fi

# Test Redirector SSH
echo -n "→ SSH to redirector-01 (${REDIRECTOR_IP}) ... "
if ssh -o ConnectTimeout=3 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=accept-new ${SSH_USER}@${REDIRECTOR_IP} "echo 'SSH OK'" 2>/dev/null | grep -q "SSH OK"; then
  echo "✓ Connected"
else
  echo "✗ Failed (check credentials/keys)"
  exit 1
fi

echo ""
echo "[3] System Requirements"
echo "──────────────────────"

# Check Ansible
echo -n "→ Ansible installed ... "
if command -v ansible >/dev/null 2>&1; then
  ANSIBLE_VERSION=$(ansible --version 2>/dev/null | head -1)
  echo "✓ ${ANSIBLE_VERSION}"
else
  echo "✗ Not found"
  echo "  Install: pip install ansible"
  exit 1
fi

# Check Python
echo -n "→ Python3 available ... "
if ssh -o ConnectTimeout=3 ${SSH_USER}@${MYTHIC_IP} "python3 --version" 2>/dev/null | grep -q "Python 3"; then
  echo "✓ Available on Mythic"
else
  echo "✗ Missing (install: apt install python3)"
  exit 1
fi

echo ""
echo "[4] Inventory Verification"
echo "──────────────────────────"

# Check if inventory file exists
if [ -f "inventory/lab.ini" ]; then
  echo "✓ inventory/lab.ini found"

  # Verify IPs
  echo ""
  echo "  Current inventory settings:"
  grep "ansible_host" inventory/lab.ini | sed 's/^/    /'

  echo ""
  echo "  ⚠️  If IPs don't match above, update inventory/lab.ini:"
  echo "     - mythic_servers: mythic-01 ansible_host=${MYTHIC_IP}"
  echo "     - redirectors: redirector-01 ansible_host=${REDIRECTOR_IP}"
else
  echo "✗ inventory/lab.ini not found"
  exit 1
fi

echo ""
echo "[5] Ansible Connectivity Test"
echo "─────────────────────────────"

# Create dynamic inventory with proper permissions
cat > /tmp/test_inventory.ini << INVEOF
[mythic_servers]
mythic-01 ansible_host=${MYTHIC_IP} ansible_user=${SSH_USER}

[redirectors]
redirector-01 ansible_host=${REDIRECTOR_IP} ansible_user=${SSH_USER}

[all:vars]
ansible_python_interpreter=/usr/bin/python3
INVEOF

chmod 600 /tmp/test_inventory.ini

echo -n "→ Testing Ansible connectivity ... "
if ansible all -i /tmp/test_inventory.ini -m ping 2>/dev/null | grep -q "SUCCESS"; then
  echo "✓ All hosts responding"
else
  echo "⚠️  Some hosts not responding"
  echo ""
  echo "Detailed test:"
  ansible all -i /tmp/test_inventory.ini -m ping -vvv
fi

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║                  DEPLOYMENT READY ✓                      ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "Next Steps:"
echo "  1. Verify inventory/lab.ini has correct IPs (shown above)"
echo "  2. Run deployment:"
echo "     ansible-playbook 0-site.yml -i inventory/lab.ini -v"
echo "  3. Watch for 'failed=0' in final report"
echo ""
echo "Deployment will take 10-15 minutes on first run"
echo ""
