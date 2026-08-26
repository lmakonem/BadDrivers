# Mythic IaC Quick-Start Deployment (Hybrid Option 1)

**Timeline:** ~30 minutes end-to-end  
**Prerequisites:** SSH access to lab VMs, Ansible installed locally  
**Environment:** Lab mode (lab.ini inventory)

---

## Step 0: Pre-Flight Checks (5 min)

**From your lab network (e.g., Kali at 192.168.36.100):**

```bash
# Verify VM accessibility
echo "=== Checking Mythic VMs ==="
ping -c 1 10.23.20.10      # VMID 113: Mythic server (VLAN 20)
ping -c 1 192.168.36.117   # VMID 117: Redirector (VLAN 0)
ping -c 1 192.168.36.122   # VMID 121: Sardonic (VLAN 0)

# Verify SSH connectivity
ssh -o ConnectTimeout=3 localuser@10.23.20.10 "echo VMID 113 OK"
ssh -o ConnectTimeout=3 localuser@192.168.36.117 "echo VMID 117 OK"
ssh -o ConnectTimeout=3 localuser@192.168.36.122 "echo VMID 121 OK"
```

**Expected Output:**
```
VMID 113 OK
VMID 117 OK
VMID 121 OK
```

---

## Step 1: Clone Repo & Install Ansible (5 min)

```bash
# Navigate to Mythic IaC
cd ~/repos/Research/Mythic/iac/ansible

# Install Ansible (if not present)
pip install ansible -q

# Verify Ansible
ansible --version
```

---

## Step 2: Update Lab Inventory (2 min)

**File:** `inventory/lab.ini`

Verify these entries match your actual IPs:

```ini
[mythic_servers]
mythic-01 ansible_host=10.23.20.10 ansible_user=localuser

[redirectors]
redirector-01 ansible_host=192.168.36.117 ansible_user=localuser

[all:vars]
ansible_python_interpreter=/usr/bin/python3
ansible_become=yes
ansible_become_method=sudo
deployment_mode=lab
```

**If your IPs differ, update them now.** (e.g., redirector might be .100 instead of .117)

---

## Step 3: Test Ansible Connectivity (3 min)

```bash
# Test all hosts in inventory
ansible all -i inventory/lab.ini -m ping

# Expected output:
# mythic-01 | SUCCESS => {
#     "changed": false,
#     "ping": "pong"
# }
# redirector-01 | SUCCESS => {
#     "changed": false,
#     "ping": "pong"
# }
```

If any host fails, troubleshoot SSH:
```bash
ssh -v localuser@<IP>
# Check: Can you login with password or key?
# Note: Playbooks use 'ansible_become=yes' to run sudo commands
```

---

## Step 4: Dry-Run Playbook (5 min)

```bash
# Syntax check
ansible-playbook --syntax-check 0-site.yml -i inventory/lab.ini

# Dry run (shows what WOULD be changed, doesn't apply)
ansible-playbook 0-site.yml -i inventory/lab.ini -C

# Expected: Task names print, no actual changes
```

**Common dry-run output:**
```
PLAY [mythic_servers] ****
TASK [bootstrap : Create deployment user] *
CHANGED [mythic-01]

TASK [bootstrap : Configure SSH keys] *
CHANGED [mythic-01]

... (30+ more tasks)
```

---

## Step 5: Deploy! (10 min)

```bash
# Run the full playbook (applies all changes)
ansible-playbook 0-site.yml -i inventory/lab.ini -v

# Watch output for:
# - CHANGED: Something was modified
# - OK: Already correct
# - FAILED: Error occurred (see error message)
```

**Expected duration:** 10-15 minutes (depends on package downloads)

**Expected final output:**
```
PLAY RECAP ****
mythic-01 : ok=45 changed=12 unreachable=0 failed=0
redirector-01 : ok=38 changed=15 unreachable=0 failed=0
```

---

## Step 6: Verify Deployment (5 min)

### 6a. Mythic Server (VMID 113)

```bash
ssh localuser@10.23.20.10 << 'EOF'
echo "=== Mythic Docker Status ==="
sudo docker ps --format "table {{.Names}}\t{{.Status}}"

echo ""
echo "=== Mythic API Health ==="
curl -sk https://localhost:7443/api 2>&1 | head -3

echo ""
echo "=== Database Status ==="
sudo docker exec mythic_postgres pg_isready -U mythic_user -d mythic || echo "DB not ready yet"
EOF
```

**Expected Output:**
```
CONTAINER ID   IMAGE              STATUS
mythic_postgres    ... Up 2 minutes
mythic_server      ... Up 1 minute
mythic_httpx       ... Up 1 minute
mythic_rabbitmq    ... Up 2 minutes

=== Mythic API Health ===
{"status": "success"} ...

=== Database Status ===
accepting connections
```

### 6b. Redirector (VMID 117)

```bash
ssh localuser@192.168.36.117 << 'EOF'
echo "=== Nginx Status ==="
sudo systemctl status nginx | grep Active

echo ""
echo "=== Socat Status ==="
sudo systemctl status socat-relay | grep Active || echo "Service may not exist yet"

echo ""
echo "=== Network Listeners ==="
sudo netstat -tlnp | grep -E ":(443|82|53)" || sudo ss -tlnp | grep -E ":(443|82|53)"
EOF
```

**Expected Output:**
```
Active: active (running)
Active: active (running)

tcp  LISTEN  0  128  0.0.0.0:443  0.0.0.0:*  nginx
tcp  LISTEN  0  128  0.0.0.0:82   0.0.0.0:*  socat
udp  LISTEN  0  512  0.0.0.0:53   0.0.0.0:*  dnsmasq
```

### 6c. Test C2 Callback Path

```bash
echo "=== Testing redirector → Mythic path ==="

# From redirector: can reach Mythic backend?
ssh localuser@192.168.36.117 "curl -sk https://10.23.20.10:7443/api 2>&1 | head -1"

# Expected: {"status": "success"} or similar
```

---

## Troubleshooting

### Symptom: "Host not found" or SSH timeout

**Fix:**
```bash
# 1. Verify network routing
ssh localuser@192.168.36.100 "tracert 10.23.20.10"

# 2. Check if VM is running
# On Proxmox: qm list | grep 113
# Or: qm status 113

# 3. Check if SSH is enabled on VM
# SSH might not be installed on base template
```

### Symptom: "permission denied" on sudo tasks

**Fix:**
```bash
# Check sudoers:
ssh localuser@10.23.20.10 "sudo -l"

# If no NOPASSWD, edit ansible/inventory/lab.ini:
# Change: ansible_become_method=sudo
# Add: ansible_become_password=<password>

# OR disable become for testing:
ansible-playbook 0-site.yml -i inventory/lab.ini -b false
```

### Symptom: "Template not found" in Ansible

**Fix:**
```bash
# Verify template files exist:
find roles/*/templates -name "*.j2" | wc -l
# Should output: 11 (or more)

# If missing, re-clone:
cd ~/repos/Research/Mythic && git pull
```

### Symptom: Docker images not pulling

**Fix:**
```bash
# Check internet connectivity from VM
ssh localuser@10.23.20.10 "curl -I https://ghcr.io"

# If behind proxy, add to docker daemon.json:
sudo nano /etc/docker/daemon.json
# Add:
# {
#   "proxies": {
#     "https": "http://proxy:3128"
#   }
# }
```

---

## Success Criteria ✓

After deployment, you should be able to:

- [ ] SSH to each VM without password prompts
- [ ] See running Docker containers on Mythic (VMID 113)
- [ ] Curl Mythic API: `curl -sk https://10.23.20.10:7443/api`
- [ ] See nginx + socat + dnsmasq running on redirector (VMID 117)
- [ ] Verify redirector → Mythic connectivity (upstream proxy working)
- [ ] Ansible playbook completes with 0 failed tasks

---

## Next Steps (After Verification)

1. **Deploy Apollo Payload** (see `/Users/lmakonem/repos/Research/Mythic/track3-apollo-agent/DEPLOY-NOW.md`)
   - Build hardened beacon in Mythic UI
   - Deploy to Windows target
   - Monitor callbacks

2. **Integrate Track 2 (Sardonic)**
   - Modify `0-site.yml` to include VMID 121
   - Add sardonic group to inventory
   - Test Sardonic agent callback

3. **Deploy Monitoring Stack** (optional)
   - Uncomment monitoring playbook in 0-site.yml
   - Add monitoring VM to inventory
   - Access Grafana dashboards

4. **Track Changes in Git**
   - Commit any inventory changes
   - Document your environment specifics

---

## Reference Files

- **Playbook:** `0-site.yml` (orchestrator, calls sub-playbooks)
- **Roles:** `roles/{bootstrap,hardening,docker,mythic,redirector,monitoring}/`
- **Templates:** `roles/*/templates/*.j2` (11 Jinja2 templates)
- **Inventory:** `inventory/lab.ini` (lab environment)
- **Group Variables:** `group_vars/{mythic_servers,redirectors}.yml`
- **Host Variables:** `host_vars/{mythic-01,redirector-01}.yml`

---

## Performance Notes

- **First run:** 10-15 minutes (includes package installation)
- **Subsequent runs:** 2-3 minutes (only changed items)
- **Dry-run:** 1-2 minutes (no changes applied)

---

## Support

**If deployment fails:**

1. Re-run with verbose output:
   ```bash
   ansible-playbook 0-site.yml -i inventory/lab.ini -vvv
   ```

2. Check specific role:
   ```bash
   ansible-playbook 0-site.yml -i inventory/lab.ini -t hardening
   # -t = run only this tag
   ```

3. Skip problematic role:
   ```bash
   ansible-playbook 0-site.yml -i inventory/lab.ini --skip-tags monitoring
   ```

4. Check logs on VM:
   ```bash
   ssh localuser@10.23.20.10 "sudo journalctl -xe | head -50"
   ```

---

**Deployed By:** Claude (AI)  
**Date:** 2026-08-26  
**Status:** Ready for Deployment ✓
