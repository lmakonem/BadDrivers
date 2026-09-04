#!/usr/bin/env python3
"""Cross-reference the local driver catalog against the MS vulnerable-driver
blocklist reconstructed from magicsword-io/LOLDrivers SiPolicy_Enforced.xml.

Blocklist source: https://raw.githubusercontent.com/magicsword-io/LOLDrivers/main/loldrivers.io/SiPolicy_Enforced.xml
  Version 10.0.27825.0. Each Deny rule carries a driver full-file SHA256 and/or
  SHA1, plus per-page hashes. A driver is BLOCKED if its full-file SHA256 OR its
  full-file SHA1 appears in the policy.

Outputs (next to this driver set):
  ms_blocklist.sha256   full-file SHA256 set
  ms_blocklist.sha1     full-file SHA1 set
  blocklist_status.csv  one row per local driver with its block status
"""
import csv, hashlib, os, re, sys

BASE = "/Users/lmakonem/repos/Research/BadDrivers/drivers_23"
POLICY = sys.argv[1] if len(sys.argv) > 1 else "/tmp/sipolicy_enforced.xml"
DRIVERS = os.path.join(BASE, "bigDrivers")
CATALOG = os.path.join(BASE, "catalog.csv")

DENY = re.compile(r'<Deny\s+[^>]*?ID="([^"]+)"[^>]*?FriendlyName="([^"]*)"[^>]*?Hash="([0-9A-Fa-f]+)"[^>]*/>', re.S)
DENY2 = re.compile(r'<Deny\s+[^>]*?Hash="([0-9A-Fa-f]+)"[^>]*?ID="([^"]+)"[^>]*/>', re.S)

def classify(fn, hlen):
    """Return (algo, is_page) using the FriendlyName, hash-length as fallback."""
    f = fn.lower()
    is_page = "page" in f or "PAGE" in fn
    if "sha256" in f:
        algo = "sha256"
    elif "sha1" in f:
        algo = "sha1"
    else:
        algo = "sha256" if hlen == 64 else "sha1"
    return algo, is_page

def ms_name(fn):
    """Strip the trailing 'Hash ...' type and any embedded \\<hex> to get the driver name."""
    stem = fn.split(" Hash")[0].strip()
    if "\\" in stem:
        pre, post = stem.rsplit("\\", 1)
        if re.fullmatch(r"[0-9a-fA-F_]+", post):
            return pre
        if re.fullmatch(r"[0-9a-fA-F_]+", pre):
            return post
        return pre or post
    return stem

sha256_full, sha1_full = set(), set()
page256, page16 = set(), set()
name_by_256, name_by_sha1 = {}, {}

raw = open(POLICY, encoding="utf-8", errors="replace").read()
n_rules = n_full256 = n_full16 = n_page = 0
for m in DENY.finditer(raw):
    idv, fn, h = m.group(1), m.group(2), m.group(3).upper()
    n_rules += 1
    algo, is_page = classify(fn, len(h))
    nm = ms_name(fn)
    if is_page:
        n_page += 1
        (page256 if algo == "sha256" else page16).add(h)
    else:
        if algo == "sha256":
            sha256_full.add(h); name_by_256.setdefault(h, nm); n_full256 += 1
        else:
            sha1_full.add(h); name_by_sha1.setdefault(h, nm); n_full16 += 1

print(f"[blocklist] policy={os.path.basename(POLICY)} rules={n_rules} (full256={n_full256} full16={n_full16} page={n_page})")
print(f"[blocklist] unique full-file SHA256={len(sha256_full)}  full-file SHA1={len(sha1_full)}  page-SHA256={len(page256)}  page-SHA1={len(page16)}")

with open(os.path.join(BASE, "ms_blocklist.sha256"), "w") as f:
    f.write("\n".join(sorted(sha256_full)))
with open(os.path.join(BASE, "ms_blocklist.sha1"), "w") as f:
    f.write("\n".join(sorted(sha1_full)))

def sha1_of(path):
    h = hashlib.sha1()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest().upper()

rows = list(csv.DictReader(open(CATALOG, newline="")))
out = []
blocked256 = blocked_sha1 = page_hit = loadable = 0
for r in rows:
    s256 = r["sha256"].upper()
    fpath = os.path.join(DRIVERS, r["sha256"] + ".sys")
    s1 = sha1_of(fpath) if os.path.exists(fpath) else ""
    if s256 in sha256_full:
        status, msname, how = "BLOCKED", name_by_256.get(s256, ""), "sha256"
        blocked256 += 1
    elif s1 and s1 in sha1_full:
        status, msname, how = "BLOCKED", name_by_sha1.get(s1, ""), "sha1"
        blocked_sha1 += 1
    elif s256 in page256:
        status, msname, how = "PAGE_HIT", "", "page_sha256"
        page_hit += 1
    else:
        status, msname, how = "LOADABLE", "", ""
        loadable += 1
    out.append({**r, "sha1": s1, "block_status": status, "block_via": how, "ms_name": msname})

with open(os.path.join(BASE, "blocklist_status.csv"), "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(out[0].keys()))
    w.writeheader(); w.writerows(out)

print(f"[result] total={len(rows)}  BLOCKED(sha256)={blocked256}  BLOCKED(sha1)={blocked_sha1}  PAGE_HIT={page_hit}  LOADABLE={loadable}")
print(f"[result] wrote blocklist_status.csv, ms_blocklist.sha256, ms_blocklist.sha1")
