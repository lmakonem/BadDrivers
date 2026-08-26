# Mythic C2 Deployment Log

**Date:** _______________  
**Deployer:** _______________  
**Lab Network:** _______________

---

## Pre-Deployment

**VM Accessibility Check:**
- [ ] SSH to 10.23.20.10 (Mythic): `ssh localuser@10.23.20.10 "echo OK"`
- [ ] SSH to 192.168.36.117 (Redirector): `ssh localuser@192.168.36.117 "echo OK"`
- [ ] Ansible installed: `ansible --version`
- [ ] Inventory updated: Check `iac/ansible/inventory/lab.ini`

**Validation Script:**
```bash
cd ~/repos/Research/Mythic/iac/ansible
./VALIDATE-BEFORE-DEPLOY.sh
```

Result: ✓ DEPLOYMENT READY or ✗ _________________

---

## Deployment Execution

**Command:**
```bash
cd ~/repos/Research/Mythic/iac/ansible
ansible-playbook 0-site.yml -i inventory/lab.ini -v
```

**Start Time:** _______________  
**Expected Duration:** 10-15 minutes

**Output Captured:**
```
[Paste final PLAY RECAP here]
```

**Final Status:**
```
PLAY RECAP
mythic-01 : ok=___ changed=___ unreachable=___ failed=___
redirector-01 : ok=___ changed=___ unreachable=___ failed=___
```

✓ Success (failed=0) or ✗ Failed (see logs below)

---

## Post-Deployment Verification

**Mythic Server (10.23.20.10):**
```bash
ssh localuser@10.23.20.10 << 'EOF'
echo "=== Docker Containers ==="
sudo docker ps --format "table {{.Names}}\t{{.Status}}"

echo ""
echo "=== API Health ==="
curl -sk https://localhost:7443/api 2>&1 | head -1
EOF
```

**Result:**
- [ ] Postgres running
- [ ] RabbitMQ running
- [ ] Mythic API running
- [ ] httpx running

**Redirector (192.168.36.117):**
```bash
ssh localuser@192.168.36.117 << 'EOF'
echo "=== Network Services ==="
sudo netstat -tlnp 2>/dev/null | grep -E ":(443|82|53)"

echo ""
echo "=== Service Status ==="
sudo systemctl status nginx | grep Active
sudo systemctl status socat-relay | grep Active || echo "socat: check"
sudo systemctl status dnsmasq | grep Active
EOF
```

**Result:**
- [ ] Port 443 listening (nginx)
- [ ] Port 82 listening (socat)
- [ ] Port 53 listening (dnsmasq)
- [ ] All services active

**Callback Path Test:**
```bash
ssh localuser@192.168.36.117 "curl -sk https://10.23.20.10:7443/api 2>&1 | head -1"
```

**Result:** {"status": "success"} or _______________

---

## Issues Encountered

**Issue 1:**
- Symptom: _______________
- Resolution: _______________
- Time to Fix: _______________

**Issue 2:**
- Symptom: _______________
- Resolution: _______________
- Time to Fix: _______________

---

## Deployment Summary

**Total Time:** _______________  
**Status:** ✓ Success or ✗ Partial (see issues)

**Services Online:**
- [ ] Mythic C2 API
- [ ] Redirector (nginx)
- [ ] Socat relay
- [ ] Dnsmasq
- [ ] Database
- [ ] Message broker

**Next Steps:**
- [ ] Deploy Apollo payload (see `track3-apollo-agent/DEPLOY-NOW.md`)
- [ ] Test C2 callback
- [ ] Integrate Track 2 (optional)
- [ ] Deploy monitoring (optional)

---

**Deployment Complete:** _______________

**Approver Signature:** _______________  
**Date:** _______________

