"""Download CSE-CIC-IDS2018 "Processed Traffic Data for ML Algorithms" (CICFlowMeter-V3 CSVs).

Source of truth: Communications Security Establishment & Canadian Institute for Cybersecurity,
public AWS bucket ``s3://cse-cic-ids2018`` (https://www.unb.ca/cic/datasets/ids-2018.html),
fetched over plain HTTPS (no AWS account needed). 10 day files, ~6.9 GB, 16.2 M flows.
SHA-256 values of the three default days are pinned from a single-process, size-verified
download in GitHub Actions (bench run 36996988970, size == S3 Content-Length). The other seven
days are not pinned; ``--all`` therefore also needs ``--allow-unpinned``, in which mode an
unpinned file is accepted only if its size equals the S3 Content-Length. Only the three default
days are used by FEINT's studies.

``--print-pins`` prints, for every fetched file, its size, SHA-256 and MD5 and checks the MD5
against the S3 ETag (single-part uploads; for multipart uploads the per-part ETag is recomputed
for every part size consistent with the part count). That is how new days get pinned: run
``bench.yml`` with study ``data-2018-pin`` and copy the SHA-256 values whose ETag check passed.

By default only three days are fetched (1.09 GB): Wednesday-14-02 (FTP/SSH brute force),
Thursday-15-02 (DoS GoldenEye / Slowloris) and Friday-02-03 (Bot) -- the families that also
exist in CIC-IDS2017, for the cross-dataset study. ``--all`` fetches all ten days.

Usage:  python scripts/download_cicids2018.py [--dest D:/cyber-portfolio/datasets/feint/cicids2018]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import urllib.parse
import urllib.request
from pathlib import Path

from _fetch import UA, fetch

BASE = ("https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/"
        + urllib.parse.quote("Processed Traffic Data for ML Algorithms") + "/")
FILES = {
    "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv":
        "acff8bc61376ee031d80878ee6099e0b1a87a1bd711d8068298421418c9f8147",
    "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv":
        "fa2947a8256d81ee9103ae16139d62d0e17aa23e696ee80d9e76fb51c01c9c4b",
    "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv": None,
    "Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv": None,
    "Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv": None,
    "Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv": None,
    "Friday-23-02-2018_TrafficForML_CICFlowMeter.csv": None,
    "Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv": None,
    "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv": None,
    "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv":
        "d96f38e7496aba83475031e6fb8c6fdf1abf6aa1b71325a917798f3c7de93de1",
}
DEFAULT_DAYS = ["Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv",
                "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv",
                "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv"]
DEFAULT = Path(os.environ.get("FEINT_DATA") or Path.cwd() / "data") / "cicids2018"
MIB = 1 << 20


def multipart_etag(path: Path, part_size: int) -> str:
    """The ETag S3 assigns to a multipart upload of ``path`` with parts of ``part_size`` bytes."""
    digests = []
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(part_size), b""):
            digests.append(hashlib.md5(chunk, usedforsecurity=False).digest())
    return hashlib.md5(b"".join(digests), usedforsecurity=False).hexdigest() + f"-{len(digests)}"


def pin_record(url: str, path: Path) -> dict:
    """Size, SHA-256 and MD5 of a downloaded file, checked against the S3 ETag and Content-Length."""
    with urllib.request.urlopen(urllib.request.Request(url, method="HEAD", headers=UA), timeout=60) as r:
        etag = (r.headers.get("ETag") or "").strip('"')
        length = int(r.headers.get("Content-Length", 0) or 0)
    sha, md5 = hashlib.sha256(), hashlib.md5(usedforsecurity=False)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(MIB), b""):
            sha.update(chunk)
            md5.update(chunk)
    size = path.stat().st_size
    rec = {"file": path.name, "size": size, "content_length": length, "sha256": sha.hexdigest(),
           "md5": md5.hexdigest(), "etag": etag}
    if "-" not in etag:
        rec["etag_check"] = "md5 == etag" if md5.hexdigest() == etag else "MISMATCH"
        return rec
    parts = int(etag.rsplit("-", 1)[1])
    lo = math.ceil(size / parts / MIB)  # whole-MiB part sizes that split `size` into `parts` parts
    hi = math.floor((size - 1) / max(parts - 1, 1) / MIB) if parts > 1 else lo
    sizes = range(lo, hi + 1) if hi - lo <= 16 else [m for m in (5, 8, 15, 16, 25, 32, 50, 64, 100, 128, 256,
                                                                  512, 1024) if lo <= m <= hi]
    for mib in sizes:
        if multipart_etag(path, mib * MIB) == etag:
            rec["etag_check"] = f"multipart etag matches with {mib} MiB parts"
            return rec
    rec["etag_check"] = "MISMATCH (no whole-MiB part size reproduces the multipart ETag)"
    return rec


def main() -> None:
    ap = argparse.ArgumentParser(description="Download (and verify) CSE-CIC-IDS2018 day files.")
    ap.add_argument("--dest", type=Path, default=DEFAULT)
    ap.add_argument("--all", action="store_true", help="all ten days (~6.9 GB)")
    ap.add_argument("--allow-unpinned", action="store_true",
                    help="accept files with no pinned SHA-256 if their size matches Content-Length")
    ap.add_argument("--print-pins", action="store_true",
                    help="print size / SHA-256 / MD5 of each file and check the MD5 against the S3 ETag")
    a = ap.parse_args()
    for name, sha in FILES.items():
        if not a.all and name not in DEFAULT_DAYS:
            continue
        path = fetch(BASE + name, a.dest / name, sha, allow_unpinned=a.allow_unpinned)
        if a.print_pins:
            print(json.dumps(pin_record(BASE + name, path)), flush=True)


if __name__ == "__main__":
    main()
