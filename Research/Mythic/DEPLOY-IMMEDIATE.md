# 🚀 Deploy Mythic C2 - IMMEDIATE

**Run these commands from Kali (or any lab machine with SSH access)**

---

## Step 1: Pre-Deployment Check (2 min)

```bash
cd ~/repos/Research/Mythic/iac/ansible

# Run validation script (checks SSH, network, Ansible)
./VALIDATE-BEFORE-DEPLOY.sh

# Expected output: "DEPLOYMENT READY ✓"
```

---

## Step 2: Update Inventory (1 min)

```bash
# Edit if your redirector is NOT at 192.168.36.117
nano inventory/lab.ini
```

---

## Step 3: Dry-Run (3 min)

```bash
ansible-playbook 0-site.yml -i inventory/lab.ini -C
```

---

## Step 4: DEPLOY (10-15 min)

```bash
ansible-playbook 0-site.yml -i inventory/lab.ini -v
```

**Watch for:** `failed=0` in final output

---

## Step 5: Verify (5 min)

```bash
# Mythic status
ssh localuser@10.23.20.10 "sudo docker ps"

# Redirector status
ssh localuser@192.168.36.117 "sudo systemctl status nginx"
```

---

## ✅ If All Working

→ Go to `track3-apollo-agent/DEPLOY-NOW.md` for payload deployment

---

**PROCEED IMMEDIATELY ABOVE**
