#!/usr/bin/env bash
# pve.sh — Proxmox API helper for BYOVD lab
# Usage: pve.sh <command> [vmid] [args]
#
# Commands:
#   exec <vmid> <cmd> [args...]   run command on VM via guest agent
#   upload <vmid> <local> <remote> upload file to VM (base64 via guest agent)
#   download <vmid> <remote> [local] download file from VM
#   snap <vmid> <snapname>        take snapshot via API
#   revert <vmid> <snapname>      revert to snapshot
#   snaplist <vmid>               list snapshots
#   status <vmid>                 VM status + IPs

set -euo pipefail

PVE_HOST="${PVE_HOST:-127.0.0.1}"
PVE_PASS="${PVE_PASS:?Set PVE_PASS environment variable}"
PVE_NODE="${PVE_NODE:-pve}"
PVE="https://${PVE_HOST}:8006"

_auth() {
  AUTH=$(curl -sk -X POST "$PVE/api2/json/access/ticket" \
    -d "username=root@pam&password=${PVE_PASS}")
  TICKET=$(echo "$AUTH" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['ticket'])")
  CSRF=$(echo "$AUTH" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['CSRFPreventionToken'])")
}

_get()  { curl -sk -b "PVEAuthCookie=$TICKET" "$PVE/api2/json/$1"; }
_post() { curl -sk -b "PVEAuthCookie=$TICKET" -H "CSRFPreventionToken: $CSRF" \
            -H "Content-Type: application/json" -X POST "$PVE/api2/json/$1" -d "$2"; }

_agent_exec() {
  local vmid=$1; shift
  # Build JSON command array from args
  local json_args
  json_args=$(python3 -c "import sys,json; print(json.dumps(sys.argv[1:]))" "$@")
  local result
  result=$(_post "nodes/$PVE_NODE/qemu/$vmid/agent/exec" "{\"command\":$json_args}")
  local pid
  pid=$(echo "$result" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['pid'])" 2>/dev/null || echo "")
  if [ -z "$pid" ]; then
    echo "[-] exec failed: $result" >&2; return 1
  fi
  # Poll for completion
  local deadline=$((SECONDS + 120))
  while [ $SECONDS -lt $deadline ]; do
    sleep 2
    local status
    status=$(_get "nodes/$PVE_NODE/qemu/$vmid/agent/exec-status?pid=$pid")
    local exited
    exited=$(echo "$status" | python3 -c "import sys,json; print(json.load(sys.stdin)['data'].get('exited',0))" 2>/dev/null || echo 0)
    if [ "$exited" = "1" ]; then
      echo "$status" | python3 -c "
import sys,json
d=json.load(sys.stdin)['data']
if d.get('out-data'): print(d['out-data'], end='')
if d.get('err-data'): print(d['err-data'], end='', file=sys.stderr)
"
      return 0
    fi
  done
  echo "[-] Timeout waiting for command" >&2; return 1
}

_upload() {
  local vmid=$1 local_file=$2 remote_path=$3
  echo "[*] Uploading $(basename "$local_file") → $remote_path"
  # Base64 encode and write via PowerShell
  local b64
  b64=$(base64 < "$local_file" | tr -d '\n')
  local ps_cmd="[IO.File]::WriteAllBytes('${remote_path}', [Convert]::FromBase64String('${b64}'))"
  _agent_exec "$vmid" powershell.exe -NoProfile -NonInteractive -Command "$ps_cmd" > /dev/null
  echo "[+] Uploaded"
}

_download() {
  local vmid=$1 remote_path=$2 local_path="${3:-.}"
  echo "[*] Downloading $remote_path"
  local b64
  b64=$(_agent_exec "$vmid" powershell.exe -NoProfile -NonInteractive \
    -Command "[Convert]::ToBase64String([IO.File]::ReadAllBytes('${remote_path}'))")
  local fname
  fname=$(basename "$(echo "$remote_path" | tr '\\' '/')")
  echo "$b64" | base64 -d > "${local_path}/${fname}"
  echo "[+] Saved to ${local_path}/${fname}"
}

# ---- Main ----
_auth

cmd="${1:-help}"; shift || true

case "$cmd" in
  exec)
    vmid="$1"; shift
    _agent_exec "$vmid" "$@"
    ;;

  upload)
    _upload "$1" "$2" "$3"
    ;;

  download)
    _download "$1" "$2" "${3:-.}"
    ;;

  snap)
    vmid="$1"; snapname="${2:-byovd-clean}"
    echo "[*] Taking snapshot $snapname on VM $vmid..."
    task=$(_post "nodes/$PVE_NODE/qemu/$vmid/snapshot" \
      "{\"snapname\":\"$snapname\",\"description\":\"BYOVD lab snapshot\"}" \
      | python3 -c "import sys,json; print(json.load(sys.stdin)['data'])" 2>/dev/null)
    echo "[+] Task: $task"
    ;;

  revert)
    vmid="$1"; snapname="${2:-byovd-clean}"
    echo "[*] Reverting VM $vmid to $snapname..."
    task=$(_post "nodes/$PVE_NODE/qemu/$vmid/snapshot/$snapname/rollback" '{}' \
      | python3 -c "import sys,json; print(json.load(sys.stdin)['data'])" 2>/dev/null)
    echo "[+] Task: $task"
    ;;

  snaplist)
    vmid="$1"
    _get "nodes/$PVE_NODE/qemu/$vmid/snapshot" \
      | python3 -c "
import sys,json
snaps=json.load(sys.stdin)['data']
for s in snaps:
  print(s['name'], s.get('description',''))
"
    ;;

  status)
    vmid="$1"
    _get "nodes/$PVE_NODE/qemu/$vmid/status/current" | python3 -c "
import sys,json; d=json.load(sys.stdin)['data']
print('status:', d.get('status'))
print('mem:', d.get('mem',0)//1024//1024, 'MB')
"
    _get "nodes/$PVE_NODE/qemu/$vmid/agent/network-get-interfaces" | python3 -c "
import sys,json
for iface in json.load(sys.stdin).get('data',{}).get('result',[]):
  for ip in iface.get('ip-addresses',[]):
    if ip['ip-address-type']=='ipv4' and not ip['ip-address'].startswith('127'):
      print('ip:', ip['ip-address'])
" 2>/dev/null || true
    ;;

  help|*)
    cat <<'EOF'
Usage: pve.sh <command> [vmid] [args]

  pve.sh exec 125 cmd.exe /c whoami
  pve.sh exec 126 powershell.exe -NoProfile -Command "Get-Process"
  pve.sh upload 125 /local/file.exe "C:\Users\Public\file.exe"
  pve.sh download 125 "C:\Users\Public\out.txt" /local/dir
  pve.sh snap 126 byovd-clean
  pve.sh revert 126 byovd-files-ready
  pve.sh snaplist 126
  pve.sh status 125

Environment: PVE_HOST, PVE_PASS, PVE_NODE
EOF
    ;;
esac
