#!/usr/bin/env bash
# vm.sh — thin shell wrapper for common lab VM operations
# Usage: vm.sh <command> [args]
#
# Commands:
#   ssh <powershell cmd>         — run command on VM
#   upload <local> [remote]      — SCP local file to VM (default: C:\Users\Public\<file>)
#   download <remote> [local]    — SCP file from VM to current dir
#   snapshot [name]              — take snapshot (requires sudo)
#   revert [name]                — revert to snapshot + wait for SSH
#   reboot                       — reboot VM and wait for SSH
#   probe                        — run probe.ps1, print JSON
#   cascade <args...>            — run cascade.exe with args

set -euo pipefail

VM_IP="${VM_IP:-127.0.0.1}"
VM_PORT="${VM_PORT:-2222}"
VM_USER="${VM_USER:-user}"
VM_PASS="${VM_PASS:-password}"
VM_VMX="${VM_VMX:-}"
VM_SNAP="${VM_SNAP:-clean-baseline}"
REMOTE_DIR="${REMOTE_DIR:-C:\\Users\\Public}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"

SSH="sshpass -p ${VM_PASS} ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -p ${VM_PORT} ${VM_USER}@${VM_IP}"
SCP="sshpass -p ${VM_PASS} scp -o StrictHostKeyChecking=no -P ${VM_PORT}"

wait_ssh() {
    local deadline=$((SECONDS + ${1:-120}))
    echo "[*] Waiting for SSH..."
    while [ $SECONDS -lt $deadline ]; do
        nc -zw2 "$VM_IP" "$VM_PORT" 2>/dev/null && echo "[+] SSH ready" && return 0
        sleep 5
    done
    echo "[-] SSH timeout" >&2; return 1
}

cmd="${1:-help}"; shift || true

case "$cmd" in
    ssh)
        $SSH "powershell -NoProfile -NonInteractive -Command \"$*\""
        ;;

    upload)
        local_file="$1"; shift
        remote_dst="${1:-${REMOTE_DIR}\\$(basename "$local_file")}"
        echo "[*] Uploading $(basename "$local_file") → $remote_dst"
        $SCP "$local_file" "${VM_USER}@${VM_IP}:$(echo "$remote_dst" | tr '\\' '/')"
        echo "[+] Done"
        ;;

    download)
        remote_file="$1"; shift
        local_dst="${1:-.}"
        echo "[*] Downloading $remote_file → $local_dst"
        $SCP "${VM_USER}@${VM_IP}:$(echo "$remote_file" | tr '\\' '/')" "$local_dst"
        echo "[+] Done"
        ;;

    snapshot)
        snap="${1:-$VM_SNAP}"
        echo "[*] Taking snapshot: $snap"
        if sudo vmrun snapshot "$VM_VMX" "$snap" 2>&1 | grep -qi "password\|encrypted\|auth"; then
            echo "[-] VM disk is encrypted — vmrun can't authenticate."
            echo "    Use Fusion GUI: Virtual Machine → Snapshots → Take Snapshot → '$snap'"
            echo "    OR: remove encryption via Fusion → VM Settings → Encryption → Remove Encryption"
            exit 1
        fi
        echo "[+] Snapshot '$snap' taken"
        ;;

    revert)
        snap="${1:-$VM_SNAP}"
        echo "[*] Reverting to snapshot: $snap"
        if sudo vmrun revertToSnapshot "$VM_VMX" "$snap" 2>&1 | grep -qi "password\|encrypted\|auth"; then
            echo "[-] VM disk is encrypted — vmrun can't authenticate."
            echo "    Use Fusion GUI: Virtual Machine → Snapshots → Revert to '$snap'"
            exit 1
        fi
        sudo vmrun start "$VM_VMX" nogui
        wait_ssh 120
        ;;

    reboot)
        echo "[*] Rebooting VM..."
        $SSH "shutdown /r /t 5 /f" 2>/dev/null || true
        sleep 15
        wait_ssh 180
        ;;

    probe)
        probe_ps1="$REPO/deploy/probe.ps1"
        $SCP "$probe_ps1" "${VM_USER}@${VM_IP}:$(echo "${REMOTE_DIR}\\probe.ps1" | tr '\\' '/')"
        $SSH "powershell -ep bypass -File $(echo "${REMOTE_DIR}\\probe.ps1" | tr '\\' '/') -Json"
        ;;

    cascade)
        cascade_exe="$REPO/build/Release/cascade.exe"
        dll="$REPO/build/Release/libwinpthread-1.dll"
        echo "[*] Uploading cascade.exe..."
        $SCP "$cascade_exe" "${VM_USER}@${VM_IP}:$(echo "${REMOTE_DIR}\\cascade.exe" | tr '\\' '/')"
        [ -f "$dll" ] && $SCP "$dll" "${VM_USER}@${VM_IP}:$(echo "${REMOTE_DIR}\\libwinpthread-1.dll" | tr '\\' '/')"
        echo "[*] Running cascade.exe $*"
        $SSH "cd /C/Users/Public && .\\\\cascade.exe $*"
        ;;

    help|*)
        cat <<'EOF'
Usage: vm.sh <command> [args]

  vm.sh ssh "Get-Process"                          run PowerShell command
  vm.sh upload /path/to/driver.sys                 upload file to C:\Users\Public\
  vm.sh upload /path/to/file.sys "C:\dest\f.sys"  upload to specific path
  vm.sh download "C:\Users\Public\heap.bin"        download to current dir
  vm.sh snapshot clean-baseline                    take snapshot (needs sudo)
  vm.sh revert clean-baseline                      revert + wait for SSH
  vm.sh reboot                                     reboot + wait for SSH
  vm.sh probe                                      run probe.ps1, print JSON
  vm.sh cascade --driver-type iocdrv --test-rw     run cascade.exe

Environment overrides: VM_IP, VM_USER, VM_PASS, VM_VMX, VM_SNAP, REMOTE_DIR
EOF
        ;;
esac
