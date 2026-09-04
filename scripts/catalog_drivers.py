#!/usr/bin/env python3
"""Catalog all .sys files in the bigDrivers collection.

For each driver: PE machine, version-resource metadata, Authenticode signer
(leaf cert subject via openssl, deduped by cert-blob hash).

Usage: catalog_drivers.py <collection_dir>
Output: <collection_dir>/../catalog.csv
"""
import csv
import hashlib
import os
import subprocess
import sys
from concurrent.futures import ProcessPoolExecutor

import pefile

MACHINES = {0x8664: "x64", 0xAA64: "arm64", 0x14c: "x86", 0x1c0: "ia64"}


def parse_file(path):
    sha = os.path.basename(path)[:-4]
    out = {
        "sha256": sha,
        "size": os.path.getsize(path),
        "machine": "",
        "origname": "",
        "product": "",
        "desc": "",
        "company": "",
        "version": "",
        "cert_sha1": "",
        "cert_blob": b"",
    }
    try:
        data = open(path, "rb").read()
        pe = pefile.PE(data=data)
        out["machine"] = MACHINES.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine))

        try:
            for fl in pe.FileInfo:
                for sfi in fl:
                    for st in getattr(sfi, "StringTable", []):
                        for k, v in getattr(st, "entries", {}).items():
                            if isinstance(k, (bytes, bytearray)):
                                k = k.decode("utf-8", "ignore").rstrip("\x00")
                            if isinstance(v, (bytes, bytearray)):
                                v = v.decode("utf-8", "ignore").rstrip("\x00")
                            if not isinstance(k, str) or not isinstance(v, str):
                                continue
                            if k == "OriginalFilename":
                                out["origname"] = v
                            elif k == "ProductName":
                                out["product"] = v
                            elif k == "FileDescription":
                                out["desc"] = v
                            elif k == "CompanyName":
                                out["company"] = v
                            elif k == "FileVersion":
                                out["version"] = v
        except Exception as e:
            out["desc"] = out["desc"] or "ERR:%s" % e.__class__.__name__

        try:
            sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
            ]
            if sec.VirtualAddress and sec.Size:
                blob = data[sec.VirtualAddress : sec.VirtualAddress + sec.Size]
                if len(blob) >= 16:
                    out["cert_sha1"] = hashlib.sha1(blob).hexdigest()
                    out["cert_blob"] = blob[8:]
        except Exception:
            pass
        pe.close()
    except Exception as e:
        out["desc"] = (out["desc"] or "") + " PARSE_ERR:%s" % e.__class__.__name__
    return out


def resolve_subject(blob):
    try:
        r = subprocess.run(
            ["openssl", "pkcs7", "-inform", "DER", "-print_certs", "-noout"],
            input=blob, capture_output=True, timeout=20,
        )
        if r.returncode == 0 and r.stdout:
            subjects = [l.split("=", 1)[1].strip() for l in r.stdout.decode().splitlines() if l.startswith("subject=")]
            if subjects:
                return "LEAF[%s]" % subjects[-1]
        r = subprocess.run(
            ["openssl", "x509", "-inform", "DER", "-noout", "-subject"],
            input=blob, capture_output=True, timeout=20,
        )
        if r.returncode == 0:
            s = r.stdout.decode().strip()
            if s:
                return "X509[" + s.replace("subject=", "", 1).strip() + "]"
    except Exception:
        pass
    return "UNREADABLE"


def main():
    coll = sys.argv[1]
    files = sorted(f for f in os.listdir(coll) if f.endswith(".sys"))
    paths = [os.path.join(coll, f) for f in files]
    rows = []
    with ProcessPoolExecutor(max_workers=8) as ex:
        for r in ex.map(parse_file, paths, chunksize=16):
            rows.append(r)
            if len(rows) % 500 == 0:
                print("...%d" % len(rows), file=sys.stderr)

    uniq = {}
    for r in rows:
        if r["cert_sha1"]:
            uniq.setdefault(r["cert_sha1"], r["cert_blob"])
    subjects = {}
    for h, blob in uniq.items():
        subjects[h] = resolve_subject(blob)
        print("cert %s -> %s" % (h[:12], subjects[h][:90]), file=sys.stderr)

    out_csv = os.path.join(os.path.dirname(os.path.abspath(coll)), "catalog.csv")
    with open(out_csv, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["sha256", "size", "machine", "origname", "product", "desc", "company", "version", "signer"])
        for r in rows:
            signer = subjects.get(r["cert_sha1"], "UNSIGNED") if r["cert_sha1"] else "UNSIGNED"
            w.writerow([r["sha256"], r["size"], r["machine"], r["origname"], r["product"], r["desc"], r["company"], r["version"], signer])
    print("wrote %s (%d drivers, %d unique certs)" % (out_csv, len(rows), len(uniq)))


if __name__ == "__main__":
    main()
