"""Download CSE-CIC-IDS2018 "Processed Traffic Data for ML Algorithms" (CICFlowMeter-V3 CSVs).

Source of truth: Communications Security Establishment & Canadian Institute for Cybersecurity,
public AWS bucket ``s3://cse-cic-ids2018`` (https://www.unb.ca/cic/datasets/ids-2018.html),
fetched over plain HTTPS (no AWS account needed). 10 day files, ~6.9 GB, 16.2 M flows.
All ten SHA-256 values are pinned from a single-process GitHub Actions download in which every
file's size equalled the S3 Content-Length and its 16 MiB part MD5s reproduced the S3 multipart
ETag (bench run 37052097044, study ``data-2018-pin``); that run also re-confirmed the three
default-day pins first taken in run 36996988970. Only the three default days are used by
FEINT's studies.

``--print-pins`` prints, for every fetched file, its size, SHA-256 and MD5 and checks the MD5
against the S3 ETag (single-part uploads; for multipart uploads the per-part ETag is recomputed
for every part size consistent with the part count). Use it (with ``--allow-unpinned``) to pin a
file that has no pin yet.

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
    "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv":
        "1a4919faa0c49c7af97230b0c2d076eba23ee6dd81103a3801d51ac316355d8b",
    "Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv":
        "7287a4d7740a1dddbf330ceb2beb6a4889d33ba63674558a68b5eb50d16711df",
    "Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv":
        "a5f4a1c2689e0aa6566c03a58466de9c407c0be0cbd3cc69306544026611be04",
    "Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv":
        "da33c927018274f9d49b145baa00e4ce0526c25b3b890b34c489e247b5e24544",
    "Friday-23-02-2018_TrafficForML_CICFlowMeter.csv":
        "d0a7f5059d9823b6e9b392b759e306481a3502d190dea7a1b5502ae079ea069b",
    "Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv":
        "f15e2a12304446058a0186c8ad67de2bd15735a9ba5c70c9a1f4c4242ab06771",
    "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv":
        "b0534c5d7d8b41e03df71c6966c995d116a8ed28e61f377c8b14cdf5d28f4edf",
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
