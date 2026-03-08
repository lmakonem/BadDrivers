# LAB ENVIRONMENT SETUP

## Supply Chain Attack - Red Team vs Blue Team Exercise

**Last Updated:** March 8, 2026  
**Lab Network:** 192.168.36.0/24

---

## Infrastructure Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           LAB NETWORK (192.168.36.0/24)                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐     │
│  │   Proxmox 225    │     │   Proxmox 237    │     │                  │     │
│  │ 192.168.36.225   │     │ 192.168.36.237   │     │                  │     │
│  │                  │     │                  │     │                  │     │
│  │  ┌────────────┐  │     │  ┌────────────┐  │     │                  │     │
│  │  │ Adaptix C2 │  │     │  │   macOS    │  │     │                  │     │
│  │  │   VM 203   │  │     │  │   VM 200   │  │     │                  │     │
│  │  │ .226       │  │     │  │ .178       │  │     │                  │     │
│  │  └────────────┘  │     │  └────────────┘  │     │                  │     │
│  │                  │     │                  │     │                  │     │
│  │  ┌────────────┐  │     │                  │     │                  │     │
│  │  │Elastic SIEM│  │     │                  │     │                  │     │
│  │  │   VM 131   │  │     │                  │     │                  │     │
│  │  │ .131       │  │     │                  │     │                  │     │
│  │  └────────────┘  │     │                  │     │                  │     │
│  └──────────────────┘     └──────────────────┘     └──────────────────┘     │
│                                                                              │
│  Attack Flow:                                                                │
│  macOS (.178) ──[executes trojanized project]──> downloads agent            │
│       │                                              from .226:9999          │
│       └──────────[Gopher agent connects]─────────> Adaptix C2 .226:9090     │
│       │                                                                      │
│       └──────────[Elastic Agent reports]─────────> Elastic SIEM .131:9200   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## System Details

### Proxmox Hypervisors

| Hostname | IP Address | Role | Credentials |
|----------|------------|------|-------------|
| proxmox-225 | 192.168.36.225 | VM Host | root:lahilabs2018 |
| proxmox-237 | 192.168.36.237 | VM Host | root:lahilabs2018 |

### Virtual Machines

| VM ID | Name | IP Address | OS | Role | Credentials |
|-------|------|------------|-----|------|-------------|
| 203 | adaptix-c2-server | 192.168.36.226 | Ubuntu 22.04 | C2 Server | localuser:password |
| 131 | elastic-siem | 192.168.36.131 | Debian 12 | SIEM | debian:debian |
| 200 | macos-sonoma | 192.168.36.178 | macOS 15.7.4 | Target | user:password |

---

## Adaptix C2 Server (192.168.36.226)

### Service Configuration

| Service | Port | Protocol | Description |
|---------|------|----------|-------------|
| Teamserver | 4321 | HTTPS | Operator connection |
| GopherTCP Listener | 9090 | TCP | macOS/Linux agents |
| HTTP Beacon Listener | 8080 | HTTP | Windows agents |
| Payload Server | 9999 | HTTP | Agent binary hosting |

### Credentials

| Username | Password | Role |
|----------|----------|------|
| admin | AdminOp123! | Administrator |
| operator1 | Operator1Pass! | Operator |
| redteam | RedTeam2026! | Operator |

### File Locations

```
/opt/adaptix/                    # Installation directory
├── AdaptixServer/               # Server code
│   └── profile.yaml             # Server configuration
├── dist/                        # Compiled binaries
│   └── adaptixserver            # Server binary
└── database.db                  # Agent database

/tmp/agent.bin                   # macOS Gopher agent (6.2MB)
```

### Starting Services

```bash
# SSH to Adaptix server
ssh localuser@192.168.36.226

# Start Adaptix C2 (if not running)
cd /opt/adaptix
sudo ./dist/adaptixserver -profile AdaptixServer/profile.yaml &

# Start payload HTTP server
cd /tmp
python3 -m http.server 9999 &

# Verify services
netstat -tlnp | grep -E '4321|9090|9999'
```

### Listener Configuration

**GopherTCP Listener (mac-listener):**
```yaml
Name: mac-listener
Type: GopherTCP
Port: 9090
Host: 0.0.0.0
```

### Generating New Agent

```bash
# Via Adaptix Client GUI:
# 1. Connect to 192.168.36.226:4321
# 2. Go to Payloads tab
# 3. Select: Type=Gopher, OS=darwin, Arch=amd64
# 4. Select Listener: mac-listener
# 5. Generate and download

# Copy to server
scp agent.bin localuser@192.168.36.226:/tmp/
```

---

## Elastic SIEM (192.168.36.131)

### Service Configuration

| Service | Port | Protocol | Description |
|---------|------|----------|-------------|
| Kibana | 5601 | HTTPS | Web UI |
| Elasticsearch | 9200 | HTTPS | Data store |
| Fleet Server | 8220 | HTTPS | Agent management |

### Credentials

| Service | Username | Password |
|---------|----------|----------|
| Kibana/Elasticsearch | elastic | elasticpassword |
| SSH | debian | debian |

### Container Architecture

```
elastic-container/
├── docker-compose.yml
├── .env                         # Configuration
└── Containers:
    ├── ecp-elasticsearch        # Data store
    ├── ecp-kibana              # Web UI
    └── ecp-fleet-server        # Agent management
```

### Starting Services

```bash
# SSH to Elastic server
ssh debian@192.168.36.131

# Start containers
cd ~/elastic-container
docker compose up -d

# Check status
docker compose ps

# Expected output:
# ecp-elasticsearch   Up (healthy)
# ecp-kibana         Up (healthy)
# ecp-fleet-server   Up
```

### Fleet Configuration

**Agent Policy:** macOS Endpoint Policy
- Policy ID: 22659365-ef88-40d5-a510-4b14b5bd8dc0
- Integrations: Elastic Defend, System

**Enrollment Token:**
```
d1pkUHpKd0JWa2R1SWczTDAwLWI6QkdIZy1FeDdRVWVyNnRoYlhHNjRfUQ==
```

### Custom Detection Rules

| Rule Name | Severity | Risk Score | Status |
|-----------|----------|------------|--------|
| Suspicious Script Execution from Xcode Project | Critical | 85 | Enabled |
| Hex Payload Decoding via xxd - Supply Chain Attack | High | 73 | Enabled |
| Curl Download to Tmp with Execution | High | 70 | Enabled |

### Accessing Kibana

1. Open: https://192.168.36.131:5601
2. Accept self-signed certificate warning
3. Login: elastic / elasticpassword
4. Navigate to Security > Alerts

---

## macOS Target (192.168.36.178)

### System Information

| Property | Value |
|----------|-------|
| Hostname | users-iMac-Pro.local |
| OS | macOS 15.7.4 (Sonoma) |
| Architecture | x86_64 (Intel) |
| User | user |
| Password | password |

### Elastic Agent Installation

**Status Check:**
```bash
ssh user@192.168.36.178
echo 'password' | sudo -S /Library/Elastic/Agent/elastic-agent status
```

**Expected Output:**
```
┌─ fleet
│  └─ status: (HEALTHY) Connected
└─ elastic-agent
   └─ status: (HEALTHY) Running
```

**Installation Path:**
```
/Library/Elastic/
├── Agent/                       # Elastic Agent
│   ├── elastic-agent            # Agent binary
│   └── data/                    # Agent data
└── Endpoint/                    # Endpoint Security
    ├── elastic-endpoint         # Endpoint binary
    └── state/                   # Endpoint state/logs
```

**Important:** System Extension must be approved in:
`System Settings > Privacy & Security > Security`

### Trojanized Project Location

```
/tmp/MarkdownEditor.xcodeproj/
├── project.pbxproj              # Xcode project file
├── project.pbxproj.backup       # Original backup
├── project.xcworkspace/
└── xcuserdata/
    └── .xcassets/               # Hidden malicious directory
        └── xcassets.sh          # Malicious build script
```

### Malware Artifacts (Post-Exploitation)

```
/tmp/.a                          # Adaptix Gopher agent (running)
```

---

## Network Connectivity Matrix

| Source | Destination | Port | Protocol | Purpose |
|--------|-------------|------|----------|---------|
| macOS | Adaptix | 9999 | HTTP | Agent download |
| macOS | Adaptix | 9090 | TCP | C2 callback |
| macOS | Elastic | 8220 | HTTPS | Fleet enrollment |
| macOS | Elastic | 9200 | HTTPS | Telemetry data |
| Operator | Adaptix | 4321 | HTTPS | C2 management |
| Analyst | Elastic | 5601 | HTTPS | SIEM access |

---

## Quick Start Commands

### Red Team - Execute Attack

```bash
# 1. Verify C2 infrastructure
curl -I http://192.168.36.226:9999/agent.bin

# 2. Execute attack on macOS
ssh user@192.168.36.178 'bash /tmp/MarkdownEditor.xcodeproj/xcuserdata/.xcassets/xcassets.sh'

# 3. Verify agent running
ssh user@192.168.36.178 'ps aux | grep /tmp/.a'
```

### Blue Team - Monitor Attack

```bash
# 1. Check alerts in Elastic
curl -k -s -u elastic:elasticpassword \
  "https://192.168.36.131:5601/api/detection_engine/signals/search" \
  -H "kbn-xsrf: true" -d '{"query":{"match_all":{}}}'

# 2. Or open Kibana
open https://192.168.36.131:5601
# Login: elastic / elasticpassword
# Go to: Security > Alerts
```

### Cleanup

```bash
# Kill malware on macOS
ssh user@192.168.36.178 "echo 'password' | sudo -S pkill -9 -f '/tmp/.a'; rm -f /tmp/.a"

# Remove trojanized project
ssh user@192.168.36.178 "rm -rf /tmp/MarkdownEditor.xcodeproj"
```

---

## Troubleshooting

### Adaptix C2 Issues

| Problem | Solution |
|---------|----------|
| Can't connect to teamserver | Check `netstat -tlnp \| grep 4321` |
| Agent not connecting | Verify listener on 9090: `netstat -tlnp \| grep 9090` |
| Agent download fails | Start HTTP server: `cd /tmp && python3 -m http.server 9999` |

### Elastic SIEM Issues

| Problem | Solution |
|---------|----------|
| Kibana not loading | `docker compose restart kibana` |
| No data from agent | Check agent status on macOS |
| Fleet not ready | `docker compose restart fleet-server` |
| SSL errors | Verify output has `ssl.verification_mode: none` |

### macOS Agent Issues

| Problem | Solution |
|---------|----------|
| Agent degraded | Approve System Extension in Privacy & Security |
| No endpoint data | Restart agent: `sudo launchctl unload/load ...` |
| Can't SSH | Verify SSH enabled in System Settings > Sharing |

---

## Maintenance

### Restarting All Services

```bash
# Adaptix C2
ssh localuser@192.168.36.226 "cd /opt/adaptix && sudo pkill adaptixserver; sudo ./dist/adaptixserver -profile AdaptixServer/profile.yaml &"

# Elastic SIEM  
ssh debian@192.168.36.131 "cd ~/elastic-container && docker compose restart"

# macOS Agent
ssh user@192.168.36.178 "echo 'password' | sudo -S launchctl unload /Library/LaunchDaemons/co.elastic.elastic-agent.plist && sudo launchctl load /Library/LaunchDaemons/co.elastic.elastic-agent.plist"
```

### Checking Service Health

```bash
# All services at once
echo "=== Adaptix ===" && curl -sk https://192.168.36.226:4321 -o /dev/null -w "%{http_code}\n"
echo "=== Elastic ===" && curl -sk https://192.168.36.131:5601/api/status -u elastic:elasticpassword | python3 -c "import sys,json; print(json.load(sys.stdin)['status']['overall']['level'])"
echo "=== macOS Agent ===" && ssh user@192.168.36.178 "echo 'password' | sudo -S /Library/Elastic/Agent/elastic-agent status 2>&1 | grep -E 'HEALTHY|DEGRADED'"
```

---

## Security Notes

- All systems are on isolated lab network (192.168.36.0/24)
- Self-signed certificates used throughout
- Credentials are for lab use only
- Adaptix is a legitimate red team tool, not malware
- Clean up agents after exercises

**DO NOT** expose this lab to production networks or the internet.
