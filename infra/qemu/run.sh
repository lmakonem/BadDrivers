#!/usr/bin/env bash
# QEMU x86-64 Windows 11 lab VM
#
# Usage:
#   ./run.sh install   — boot from ISO for first-time Windows install
#   ./run.sh run       — boot from disk (normal operation, default)
#   ./run.sh bg        — boot in background (daemonized)
#
# VNC: open any VNC viewer → localhost:5901
# SSH: ssh -p 2222 user@localhost   (available after install)
# RDP: localhost:3389

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

DISK="${SCRIPT_DIR}/win11-x64.qcow2"
OVMF_CODE="/opt/homebrew/share/qemu/edk2-x86_64-code.fd"
OVMF_VARS="${SCRIPT_DIR}/OVMF_VARS.fd"
WIN_ISO="/Users/user/Downloads/26100.1742.240906-0331.ge_release_svc_refresh_CLIENT_LTSC_EVAL_x64FRE_en-us.iso"
UNATTEND_ISO="${SCRIPT_DIR}/autounattend.iso"
PIDFILE="${SCRIPT_DIR}/qemu.pid"

QEMU="$(command -v qemu-system-x86_64 2>/dev/null || true)"
if [ -z "$QEMU" ]; then
    echo "[-] qemu-system-x86_64 not found — run: brew install qemu"; exit 1
fi
if [ ! -f "$OVMF_CODE" ]; then
    echo "[-] OVMF not found at $OVMF_CODE — run: brew install qemu"; exit 1
fi
if [ ! -f "$DISK" ]; then
    echo "[-] Disk image not found: $DISK"
    echo "    Create: qemu-img create -f qcow2 $DISK 80G"; exit 1
fi

MODE="${1:-run}"

COMMON=(
    -machine q35
    -cpu Haswell
    -m 8192
    -smp 2
    -accel tcg,thread=multi

    # SeaBIOS + IDE — Windows has native IDE/AHCI drivers

    # NIC with SSH + RDP port forwarding
    -netdev "user,id=net0,hostfwd=tcp::2222-:22,hostfwd=tcp::3389-:3389"
    -device e1000,netdev=net0

    # VNC display (connect to localhost:5901)
    -vnc 127.0.0.1:1
    -display none

    # USB tablet for accurate mouse in VNC
    -usb
    -device usb-tablet
)

case "$MODE" in
    install)
        echo "[*] Mode: INSTALL"
        [ ! -f "$WIN_ISO" ]      && echo "[-] Windows ISO not found: $WIN_ISO" && exit 1
        [ ! -f "$UNATTEND_ISO" ] && echo "[!] autounattend.iso missing — run make-autounattend-iso.sh for unattended install"

        ISO_ARGS=(
            # IDE index 0 = primary master (hard disk)
            -drive "if=ide,index=0,format=qcow2,file=${DISK},cache=writeback"
            # IDE index 2 = secondary master (first CD = bootable Windows ISO)
            -drive "if=ide,index=2,media=cdrom,file=${WIN_ISO},readonly=on"
        )
        if [ -f "$UNATTEND_ISO" ]; then
            ISO_ARGS+=(
                # IDE index 3 = secondary slave (autounattend — found by Windows Setup)
                -drive "if=ide,index=3,media=cdrom,file=${UNATTEND_ISO},readonly=on"
            )
            echo "[*] Autounattend ISO: $UNATTEND_ISO"
        fi
        ISO_ARGS+=(-boot d)

        echo "[*] Windows ISO:      $WIN_ISO"
        echo "[*] VNC:              connect VNC viewer to localhost:5901"
        echo "[*] SSH after install: ssh -p 2222 user@localhost"
        echo "[*] Starting QEMU..."
        exec "$QEMU" "${COMMON[@]}" "${ISO_ARGS[@]}"
        ;;

    run)
        echo "[*] Mode: RUN (booting from disk)"
        echo "[*] VNC:  localhost:5901"
        echo "[*] SSH:  ssh -p 2222 user@localhost"
        echo "[*] RDP:  localhost:3389"
        echo "[*] Starting QEMU..."
        exec "$QEMU" "${COMMON[@]}" \
            -drive "if=ide,index=0,format=qcow2,file=${DISK},cache=writeback" \
            -boot c
        ;;

    bg)
        echo "[*] Mode: BACKGROUND (daemonized)"
        "$QEMU" "${COMMON[@]}" \
            -drive "if=ide,index=0,format=qcow2,file=${DISK},cache=writeback" \
            -boot c \
            -pidfile "$PIDFILE" -daemonize
        echo "[+] Started. PID in $PIDFILE"
        echo "[*] SSH:  ssh -p 2222 user@localhost"
        echo "[*] VNC:  localhost:5901"
        echo "[*] Stop: kill \$(cat $PIDFILE)"
        ;;

    stop)
        if [ -f "$PIDFILE" ]; then
            PID="$(cat "$PIDFILE")"
            echo "[*] Stopping QEMU (PID $PID)..."
            kill "$PID" 2>/dev/null || true
            rm -f "$PIDFILE"
            echo "[+] Done"
        else
            echo "[-] No pidfile found — VM may not be running"
        fi
        ;;

    *)
        echo "Usage: $0 [install|run|bg|stop]"; exit 1
        ;;
esac
