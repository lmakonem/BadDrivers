#!/usr/bin/env python3
"""Build a prioritized BYOVD candidate shortlist from the local driver catalog.

Joins catalog.csv + blocklist_status.csv with a curated table of known-vulnerable
driver families (CVE, primitive, gate/bypass source, tier). Tier 1 = primary,
known CVE + documented R/W + in collection + not blocklisted.

Output: drivers_23/candidates.csv  (ranked)
"""
import csv, os

BASE = "/Users/lmakonem/repos/Research/BadDrivers/drivers_23"
rows = list(csv.DictReader(open(os.path.join(BASE, "catalog.csv"))))
blk = {r["sha256"]: r for r in csv.DictReader(open(os.path.join(BASE, "blocklist_status.csv")))}

# origname-substring -> metadata
FAM = {
    "lnvmsrio":  ("LnvMSRIO", "CVE-2025-8061", "phys R/W + MSR R/W + LSTAR overwrite", "Notion bypass; kASLR bypass on 24H2", 1),
    "winring0":  ("WinRing0", "arbitrary phys/IO/mem R/W", "MmMapIoSpace / direct phys", "classic; many public PoCs", 1),
    "asio":      ("AsIO/ASIO3", "arbitrary phys R/W", "IOCTL phys R/W", "documented bypass", 1),
    "ntiolib":   ("NTIOLib", "arbitrary phys R/W", "IOCTL phys R/W", "MSI NTIOLib", 1),
    "iomap":     ("IOMap", "arbitrary phys R/W", "IOCTL phys R/W", "Asus IOMap", 1),
    "sptd":      ("sptd/sptd2", "kernel memory access", "filter/IOCTL", "Daemon Tools sptd", 1),
    "nvpciflt":  ("nvpciflt", "phys R/W via PCI BAR", "IOCTL BAR access", "NVIDIA PCI filter", 1),
    "semav6msr": ("semav6msr64", "MSR R/W", "IOCTL MSR", "Intel MSR", 2),
    "sepdal":    ("sepdal", "SEP/IA32 access", "IOCTL", "Intel SEP DAL", 2),
    "appcontrol":("AppControl", "hook/PEB + R/W", "version-specific", "Notion bypass (version-dep)", 2),
    "spyshelter":("SpyShelter", "hook driver", "hook", "Netmeetings", 2),
    "asuss":     ("AsusSAIO", "sound/IO", "IOCTL", "Asus", 2),
    "monprocess":("MonProcess", "PID kill only", "IOCTL kill", "Honor", 3),
    "hwsmbus":   ("HwSMBus", "SMBus R/W", "IOCTL SMBus", "Huawei", 3),
}

def match(r):
    blob = " ".join([r.get("origname", ""), r.get("product", ""), r.get("desc", "")]).lower()
    for key, meta in FAM.items():
        if key in blob:
            return meta
    return None

out = []
for r in rows:
    m = match(r)
    if not m:
        continue
    name, cve, prim, gate, tier = m
    b = blk.get(r["sha256"], {})
    label = r["origname"] or r.get("product") or r.get("desc") or "?"
    out.append({"tier": tier, "family": name, "sha256": r["sha256"], "name": label,
                "version": r["version"], "size": r["size"], "cve": cve, "primitive": prim,
                "gate": gate, "block_status": b.get("block_status", "?"),
                "machine": r["machine"], "signer": r["signer"]})

out.sort(key=lambda x: (x["tier"], x["family"], x["version"]))
with open(os.path.join(BASE, "candidates.csv"), "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(out[0].keys())); w.writeheader(); w.writerows(out)

from collections import Counter
tc = Counter(o["family"] for o in out)
print(f"[candidates] total matched rows: {len(out)}  distinct families: {len(tc)}")
for o in out:
    if o["tier"] == 1:
        print(f'  T1 {o["family"]:12} {o["sha256"][:16]}  v{o["version"]:12} {o["name"]:14} blk={o["block_status"]}')
