#!/usr/bin/env python3
"""
vm_mcp_server.py — MCP server for BadDrivers lab VM management.

Tools exposed to Claude:
  vm_ssh          — run a PowerShell command on the Windows VM
  vm_upload       — SCP a local file to the VM
  vm_download     — SCP a file from the VM to local
  vm_snapshot     — take a named snapshot (needs sudoers entry)
  vm_revert       — revert to a named snapshot + wait for SSH
  vm_reboot       — reboot the VM and wait for SSH to come back
  vm_probe        — run deploy/probe.ps1 and return parsed JSON
  vm_run_cascade  — run cascade.exe with given args, return stdout

Configuration via environment variables (or edit DEFAULTS below):
  VM_IP       172.16.157.129
  VM_USER     user
  VM_PASS     password
  VM_VMX      /Users/user/Virtual Machines.localized/baddrivers_vm.vmwarevm/baddrivers_vm.vmx
  VM_SNAP     clean-baseline
  REMOTE_DIR  C:\\Users\\Public
"""

import os, json, subprocess, time, socket
from pathlib import Path
import paramiko
from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
CFG = {
    "ip":       os.getenv("VM_IP",      "127.0.0.1"),
    "port":     int(os.getenv("VM_PORT", "2222")),
    "user":     os.getenv("VM_USER",    "user"),
    "password": os.getenv("VM_PASS",    "password"),
    "vmx":      os.getenv("VM_VMX",     ""),
    "snap":     os.getenv("VM_SNAP",    "clean-baseline"),
    "remote_dir": os.getenv("REMOTE_DIR", r"C:\Users\Public"),
    "repo":     str(Path(__file__).parent.parent),
}

# ---------------------------------------------------------------------------
# SSH helpers
# ---------------------------------------------------------------------------
def _client() -> paramiko.SSHClient:
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(CFG["ip"], port=CFG["port"], username=CFG["user"],
              password=CFG["password"], timeout=15, banner_timeout=30)
    return c


def _ssh(cmd: str, timeout: int = 60) -> dict:
    """Run cmd via SSH, return {stdout, stderr, exit_code}."""
    with _client() as c:
        _, out, err = c.exec_command(cmd, timeout=timeout)
        stdout = out.read().decode(errors="replace").strip()
        stderr = err.read().decode(errors="replace").strip()
        rc     = out.channel.recv_exit_status()
    return {"stdout": stdout, "stderr": stderr, "exit_code": rc}


def _wait_ssh(timeout: int = 120) -> bool:
    """Poll until SSH port is reachable, up to timeout seconds."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.create_connection((CFG["ip"], CFG["port"]), timeout=3)
            s.close()
            time.sleep(3)   # give sshd a moment to accept auth
            return True
        except OSError:
            time.sleep(5)
    return False


# ---------------------------------------------------------------------------
# MCP server
# ---------------------------------------------------------------------------
mcp = FastMCP("vm-tools")


@mcp.tool()
def vm_ssh(command: str, timeout: int = 60) -> str:
    """Run a PowerShell command on the Windows lab VM and return its output.

    Args:
        command: PowerShell command string (no quoting needed — sent as-is).
        timeout: seconds to wait for the command to finish (default 60).
    """
    result = _ssh(f"powershell -NoProfile -NonInteractive -Command \"{command}\"",
                  timeout=timeout)
    out = result["stdout"]
    if result["stderr"]:
        out += "\n[stderr] " + result["stderr"]
    if result["exit_code"] != 0:
        out += f"\n[exit {result['exit_code']}]"
    return out or "(no output)"


@mcp.tool()
def vm_upload(local_path: str, remote_path: str = "") -> str:
    """Upload a local file to the Windows lab VM via SCP.

    Args:
        local_path:  Absolute or repo-relative local path.
        remote_path: Destination on the VM (default: REMOTE_DIR\\<filename>).
    """
    src = Path(local_path)
    if not src.is_absolute():
        src = Path(CFG["repo"]) / local_path
    if not src.exists():
        return f"ERROR: {src} does not exist"

    dst = remote_path or f"{CFG['remote_dir']}\\{src.name}"
    with _client() as c:
        sftp = c.open_sftp()
        sftp.put(str(src), dst.replace("\\", "/"))
        sftp.close()
    return f"Uploaded {src.name} → {dst}"


@mcp.tool()
def vm_download(remote_path: str, local_path: str = "") -> str:
    """Download a file from the Windows lab VM via SCP.

    Args:
        remote_path: Path on the VM (e.g. C:\\Users\\Public\\heap.bin).
        local_path:  Local destination (default: current dir / filename).
    """
    fname = remote_path.replace("\\", "/").split("/")[-1]
    dst   = Path(local_path) if local_path else Path.cwd() / fname
    remote_unix = remote_path.replace("\\", "/")
    with _client() as c:
        sftp = c.open_sftp()
        sftp.get(remote_unix, str(dst))
        sftp.close()
    size = dst.stat().st_size
    return f"Downloaded {fname} → {dst} ({size:,} bytes)"


def _vmrun(args: list[str], vm_password: str = "") -> tuple[int, str]:
    """Run vmrun, optionally piping the VM encryption password."""
    cmd = ["sudo", "vmrun"] + args
    inp = (vm_password + "\n").encode() if vm_password else None
    r = subprocess.run(cmd, input=inp, capture_output=True, text=False)
    stderr = r.stderr.decode(errors="replace").strip()
    return r.returncode, stderr


@mcp.tool()
def vm_snapshot(name: str = "", vm_password: str = "") -> str:
    """Take a VM snapshot via vmrun.

    The VM disk may be encrypted — if so, pass the encryption password set
    when the VM was created (NOT the Windows user password).
    If vmrun keeps failing, take the snapshot via Fusion GUI:
    Virtual Machine menu → Snapshots → Take Snapshot → name it and click Take.

    Args:
        name:        Snapshot name (default: configured VM_SNAP).
        vm_password: VMware disk-encryption password (if the VM is encrypted).
    """
    snap = name or CFG["snap"]
    rc, err = _vmrun(["snapshot", CFG["vmx"], snap], vm_password)
    if rc == 0:
        return f"Snapshot '{snap}' taken."
    return (
        f"vmrun snapshot failed: {err}\n\n"
        "The VM disk is encrypted. Options:\n"
        "1. Pass the encryption password as vm_password argument.\n"
        "2. Remove encryption: Fusion → VM Settings → Encryption → Remove Encryption.\n"
        "3. Use Fusion GUI: Virtual Machine menu → Snapshots → Take Snapshot → 'clean-baseline'."
    )


@mcp.tool()
def vm_revert(name: str = "", vm_password: str = "", wait_ssh: bool = True) -> str:
    """Revert to a named snapshot, start the VM, and wait for SSH.

    Args:
        name:        Snapshot name (default: configured VM_SNAP).
        vm_password: VMware disk-encryption password (if the VM is encrypted).
        wait_ssh:    Poll until SSH is reachable after start (default True).
    """
    snap = name or CFG["snap"]
    rc, err = _vmrun(["revertToSnapshot", CFG["vmx"], snap], vm_password)
    if rc != 0:
        return (
            f"revertToSnapshot failed: {err}\n\n"
            "The VM disk is encrypted — pass the encryption password as vm_password,\n"
            "or remove encryption via Fusion → VM Settings → Encryption → Remove Encryption."
        )

    _vmrun(["start", CFG["vmx"], "nogui"], vm_password)

    if wait_ssh:
        ok = _wait_ssh(120)
        return f"Reverted to '{snap}'. SSH {'ready' if ok else 'TIMEOUT — VM may still be booting'}."
    return f"Reverted to '{snap}'. VM starting."


@mcp.tool()
def vm_reboot(wait_ssh: bool = True) -> str:
    """Reboot the Windows lab VM via SSH shutdown and wait for it to come back.

    Args:
        wait_ssh: Poll until SSH is reachable after reboot (default True).
    """
    try:
        _ssh("shutdown /r /t 5 /f", timeout=10)
    except Exception:
        pass
    time.sleep(15)
    if wait_ssh:
        ok = _wait_ssh(180)
        return f"Rebooted. SSH {'ready' if ok else 'TIMEOUT — VM may still be booting'}."
    return "Reboot command sent."


@mcp.tool()
def vm_probe() -> str:
    """Run deploy/probe.ps1 on the VM and return the JSON result.

    Uploads probe.ps1 if not already present, then runs it.
    Returns parsed JSON so Claude can make decisions based on HVCI/CG/etc state.
    """
    probe_local = str(Path(CFG["repo"]) / "BadDrivers" / "deploy" / "probe.ps1")
    remote_probe = CFG["remote_dir"] + "\\probe.ps1"

    # Upload probe.ps1
    vm_upload(probe_local, remote_probe)

    result = _ssh(
        f"powershell -NoProfile -NonInteractive -ep bypass "
        f"-File \"{remote_probe}\" -Json",
        timeout=30
    )
    raw = result["stdout"]
    try:
        data = json.loads(raw)
        return json.dumps(data, indent=2)
    except json.JSONDecodeError:
        return raw or result["stderr"] or "(no output)"


@mcp.tool()
def vm_run_cascade(args: str, driver_local: str = "", timeout: int = 120) -> str:
    """Run cascade.exe on the VM with the given arguments.

    Uploads cascade.exe + driver if local paths are provided, then runs.

    Args:
        args:         cascade.exe arguments (e.g. "--driver-type iocdrv --test-rw").
        driver_local: Local path to .sys driver to upload (optional).
        timeout:      Seconds to wait for cascade to finish (default 120).
    """
    cascade_local = str(Path(CFG["repo"]) / "BadDrivers" / "build" / "Release" / "cascade.exe")
    remote_cascade = CFG["remote_dir"] + "\\cascade.exe"
    remote_driver  = CFG["remote_dir"] + "\\driver.sys"

    vm_upload(cascade_local, remote_cascade)

    # Upload libwinpthread-1.dll if present
    dll = Path(CFG["repo"]) / "BadDrivers" / "build" / "Release" / "libwinpthread-1.dll"
    if dll.exists():
        vm_upload(str(dll), CFG["remote_dir"] + "\\libwinpthread-1.dll")

    if driver_local:
        vm_upload(driver_local, remote_driver)
        if "--driver " not in args:
            args = f"--driver {remote_driver} {args}"

    result = _ssh(
        f"cd {CFG['remote_dir']} && .\\cascade.exe {args}",
        timeout=timeout
    )
    out = result["stdout"]
    if result["stderr"]:
        out += "\n[stderr] " + result["stderr"]
    if result["exit_code"] not in (0, None):
        out += f"\n[exit {result['exit_code']}]"
    return out or "(no output)"


if __name__ == "__main__":
    mcp.run(transport="stdio")
