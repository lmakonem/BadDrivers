#!/usr/bin/env bash
# deploy.sh - push built payloads to VM 125 (.210) over the LAN via QGA exec.
#
# The Mac (or any host on the LAN) exposes the artifacts over a tiny HTTP server
# on 127.0.0.1 and QGA exec on the guest curl-fetches them, then verifies
# SHA256. No SSH needed, no RDP, no SMB.
#
# Usage:
#   ./deploy.sh                     # uses pve host 192.168.36.225, VM 125, .210
#   PVE=10.1.1.1 ./deploy.sh        # override pve host
#
# Requires: a local HTTP server on $PORT serving $STAGE (default: 18080).
# The script will start one if curl is available; otherwise it errors with
# instructions.

set -euo pipefail

PVE="${PVE:-192.168.36.225}"
VMID="${VMID:-125}"
GUEST_IP="${GUEST_IP:-192.168.36.210}"
PORT="${PORT:-18080}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STAGE="$ROOT/build/release-kali"

[ -f "$STAGE/warp.exe" ] || { echo "[-] missing $STAGE/warp.exe, run scripts/build.sh first" >&2; exit 3; }
[ -f "$STAGE/byovd_sample2.exe" ] || { echo "[-] missing $STAGE/byovd_sample2.exe" >&2; exit 3; }

sha_local() { (cd "$STAGE" && shasum -a 256 "$1" | awk '{print $1}'); }
WARP_SHA=$(sha_local warp.exe)
BYOV_SHA=$(sha_local byovd_sample2.exe)
echo "[*] warp.exe           sha256=$WARP_SHA"
echo "[*] byovd_sample2.exe  sha256=$BYOV_SHA"

# Start a tiny http server if not already up.
if ! curl -sSf -o /dev/null "http://127.0.0.1:$PORT/warp.exe" 2>/dev/null; then
    echo "[*] starting http server on 127.0.0.1:$PORT rooted at $STAGE"
    ( cd "$STAGE" && exec python3 -m http.server "$PORT" ) >/dev/null 2>&1 &
    SRV_PID=$!
    echo "$SRV_PID" > /tmp/badrivers_http.pid
    sleep 1
else
    SRV_PID=""
fi
trap 'if [ -n "${SRV_PID:-}" ]; then kill "$SRV_PID" 2>/dev/null || true; fi' EXIT

# Build the QGA command: the guest pulls from the Mac (over LAN) and verifies.
# We need the Mac's IP on the .0/24 segment. Find it heuristically.
MAC_IP=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null)
[ -n "${MAC_IP:-}" ] || { echo "[-] cannot determine Mac LAN IP" >&2; exit 3; }
echo "[*] pushing from $MAC_IP:$PORT to $GUEST_IP via $PVE ($VMID)"

# The guest command (powershell, base64-encoded UTF-16LE).
# Phase 1: fetch + verify both payloads into C:\bad (NOT C:\temp - Windows
# Update / KMS reboots wipe per-boot / temp state on this template).
# Phase 2: optionally run warp --dry-run on the guest, capture its output to
# C:\bad\dryrun.log. The whole thing is ONE PowerShell session so a reboot
# cannot land between the file-write and the dry-run.
PS='
$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "Stop"
$dir = "C:\bad"
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
$warp = "$dir\warp.exe"
$byov = "$dir\byovd_sample2.exe"
$warp_sha = "WARP_SHA_PLACEHOLDER"
$byov_sha = "BYOV_SHA_PLACEHOLDER"
$url_base = "http://MAC_IP_PLACEHOLDER:PORT_PLACEHOLDER/"

foreach ($name in @("warp.exe", "byovd_sample2.exe")) {
    $dest = "$dir\" + $name
    if (Test-Path $dest) { Remove-Item $dest }
    Invoke-WebRequest -Uri ($url_base + $name) -OutFile $dest -UseBasicParsing
    $got = (Get-FileHash -Algorithm SHA256 -Path $dest).Hash.ToLower()
    $exp = if ($name -eq "warp.exe") { $warp_sha } else { $byov_sha }
    if ($got -ne $exp) { throw ("sha256 mismatch for " + $name + " got=" + $got + " want=" + $exp) }
    Write-Host ("  ok " + $name + " sha256=" + $got)
}
Write-Host "DEPLOY_OK"

if ("DRYRUN_PLACEHOLDER".ToUpper() -eq "TRUE") {
    $log = "C:\bad\dryrun.log"
    & $warp --dry-run *> $log
    Write-Host "DRYRUN_LOG_WRITTEN:" $log
    Get-Content $log -ErrorAction SilentlyContinue
}
'
PS="${PS//WARP_SHA_PLACEHOLDER/$WARP_SHA}"
PS="${PS//BYOV_SHA_PLACEHOLDER/$BYOV_SHA}"
PS="${PS//MAC_IP_PLACEHOLDER/$MAC_IP}"
PS="${PS//PORT_PLACEHOLDER/$PORT}"
# The --dry-run sub-flag is opt-in (default off) so a stray deploy is safe.
if [ "${DRYRUN:-0}" = "1" ]; then
    PS="${PS//DRYRUN_PLACEHOLDER/True}"
else
    PS="${PS//DRYRUN_PLACEHOLDER/False}"
fi

PS_B64=$(printf '%s' "$PS" | iconv -f UTF-8 -t UTF-16LE | base64)

# Run via QGA on the pve host. Use cmd /c so sshd and powershell -Command don't double-wrap.
set +e
OUT=$(ssh -o BatchMode=yes -o ConnectTimeout=10 root@"$PVE" \
    "qm guest exec $VMID --synchronous 1 -- cmd /c \"powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $PS_B64\"" 2>&1)
RC=$?
set -e

echo "$OUT" | tr -d '\000' | sed -n '/[a-zA-Z0-9]/p' | head -80
if echo "$OUT" | grep -qE "DEPLOY_OK"; then
    echo "[+] artifacts deployed to C:\bad on $GUEST_IP"
    exit 0
else
    echo "[-] deploy did not report DEPLOY_OK (rc=$RC), inspect output above" >&2
    exit 1
fi
