#!/usr/bin/env python3
"""Cross-reference the local 2409-driver collection against loldrivers.io
KnownVulnerableSamples. A driver is CONFIRMED-VULNERABLE if its full-file SHA256
(or MD5 fallback) matches a hash loldrivers lists for a known-vulnerable sample.

Output: drivers_23/loldrivers_kvs_matches.csv
  local_sha256, local_origname, local_signer, lr_driver, lr_verified,
  lr_mitre, match_via, lr_sample_filename, lr_fileversion
"""
import csv, hashlib, json, os, sys

BASE = "/Users/lmakonem/repos/Research/BadDrivers/drivers_23"
DRIVERS = os.path.join(BASE, "bigDrivers")
CATALOG = os.path.join(BASE, "catalog.csv")
LOL = os.path.join(BASE, "loldrivers.json")

def md5_of(path):
    h = hashlib.md5()
    with open(path, "rb") as fh:
        for c in iter(lambda: fh.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()

lol = json.load(open(LOL))
sha256map, md5map = {}, {}
for e in lol:
    tag = (e.get("Tags") or ["?"])[0]
    for s in e.get("KnownVulnerableSamples", []) or []:
        ah = s.get("Authentihash", {})
        info = {"lr_driver": tag, "lr_verified": e.get("Verified"),
                "lr_mitre": e.get("MitreID"), "lr_fileversion": s.get("FileVersion"),
                "lr_sample_filename": s.get("Filename")}
        a256 = (ah.get("SHA256") or "").lower()
        a5 = (ah.get("MD5") or "").lower()
        if a256:
            sha256map.setdefault(a256, info)
        if a5:
            md5map.setdefault(a5, info)

print(f"[loldrivers] entries={len(lol)}  KVS sha256={len(sha256map)}  KVS md5={len(md5map)}")

rows = list(csv.DictReader(open(CATALOG, newline="")))
out = []
for r in rows:
    s256 = r["sha256"].lower()
    fpath = os.path.join(DRIVERS, r["sha256"] + ".sys")
    if s256 in sha256map:
        info, via = sha256map[s256], "sha256"
    else:
        m5 = md5_of(fpath) if os.path.exists(fpath) else ""
        info, via = (md5map[m5], "md5") if m5 in md5map else (None, "")
    if info:
        out.append({**r, "lr_driver": info["lr_driver"], "lr_verified": info["lr_verified"],
                    "lr_mitre": info["lr_mitre"], "match_via": via,
                    "lr_sample_filename": info["lr_sample_filename"],
                    "lr_fileversion": info["lr_fileversion"]})


with open(os.path.join(BASE, "loldrivers_kvs_matches.csv"), "w", newline="") as f:
    if out:
        w = csv.DictWriter(f, fieldnames=list(out[0].keys())); w.writeheader(); w.writerows(out)

print(f"[result] CONFIRMED-VULNERABLE drivers: {len(out)} / {len(rows)}")
for o in sorted(out, key=lambda x: x["lr_driver"]):
    print(f"  {o['lr_driver']:22} via={o['match_via']:6} ver={str(o['lr_fileversion']):10} mitre={str(o['lr_mitre']):7} local={o['origname']}")
