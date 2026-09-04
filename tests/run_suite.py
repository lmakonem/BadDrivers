#!/usr/bin/env python3
"""
Orchestrate N consecutive cascade_e2e runs with Proxmox snapshot revert between each.

Each run:
  1. Stops VM, rolls back to SNAP, starts VM.
  2. Waits for QEMU guest agent (up to ~10 min).
  3. Sleeps 45s for Windows services to settle.
  4. Runs cascade_e2e.py --run N.

Usage:
    python3 run_suite.py [--runs 5] [--snap cascade-test-base]
"""
import subprocess, time, sys, os, argparse

PVE  = os.environ.get("BADDRIVERS_PVE",  "root@PROXMOX_HOST")
VMID = os.environ.get("BADDRIVERS_VMID", "126")
HERE = os.path.dirname(os.path.abspath(__file__))

def pve(cmd, timeout=120):
    r = subprocess.run(
        ["ssh", "-o", "ConnectTimeout=20", "-o", "StrictHostKeyChecking=no",
         PVE, cmd],
        capture_output=True, timeout=timeout)
    return (r.stdout + r.stderr).decode("utf-8", errors="replace")

def wait_agent(run_num, max_attempts=50):
    for i in range(1, max_attempts + 1):
        out = pve(f"timeout 8 qm agent {VMID} ping 2>&1", timeout=30)
        if "200" in out or "{}" in out:
            print(f"  [agent] UP (ping) at attempt {i}"); return True
        out2 = pve(f'timeout 8 qm guest exec {VMID} --pass-stdin=false -- cmd /c "echo ok" 2>&1', timeout=30)
        if '"out-data"' in out2:
            print(f"  [agent] UP (exec) at attempt {i}"); return True
        print(f"  [agent] {i}/{max_attempts}...")
        time.sleep(15)
    print(f"  [agent] TIMEOUT for run {run_num}"); return False

def revert_and_boot(run_num, snap):
    print(f"\n{'='*60}\nPreparing VM for run {run_num} (snap={snap})")
    pve(f"qm unlock {VMID} 2>&1", timeout=30)
    pve(f"qm stop {VMID} --skiplock 2>&1", timeout=60)
    time.sleep(8)
    pve(f"qm unlock {VMID} 2>&1", timeout=30)
    print(f"  Rolling back to {snap}...")
    rb = pve(f"qm rollback {VMID} {snap} 2>&1", timeout=120)
    print(f"  {rb.strip()[-100:]}")
    time.sleep(5)
    pve(f"qm start {VMID} 2>&1", timeout=60)
    time.sleep(15)
    if not wait_agent(run_num):
        return False
    print("  [stabilize] 45s...")
    time.sleep(45)
    return True

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--snap", default="cascade-test-base")
    args = ap.parse_args()

    results = {}
    for run in range(1, args.runs + 1):
        if not revert_and_boot(run, args.snap):
            results[run] = "AGENT_TIMEOUT"; continue
        print(f"--- RUN {run} starting at {time.strftime('%H:%M:%S')} ---")
        r = subprocess.run(
            [sys.executable, os.path.join(HERE, "cascade_e2e.py"), "--run", str(run)],
            timeout=900)
        results[run] = "PASS" if r.returncode == 0 else "FAIL"
        print(f"=== RUN {run}: {results[run]} ===")

    print(f"\n{'='*60}")
    print("RESULTS:")
    for run in range(1, args.runs + 1):
        print(f"  Run {run}: {results.get(run, '?')}")
    fails = sum(1 for v in results.values() if v != "PASS")
    print(f"  {args.runs - fails}/{args.runs} PASS")
    sys.exit(0 if fails == 0 else 1)

if __name__ == "__main__":
    main()
