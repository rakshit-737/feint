"""Download CSE-CIC-IDS2018 "Processed Traffic Data for ML Algorithms" (CICFlowMeter-V3 CSVs).

Source of truth: Communications Security Establishment & Canadian Institute for Cybersecurity,
public AWS bucket ``s3://cse-cic-ids2018`` (https://www.unb.ca/cic/datasets/ids-2018.html),
fetched over plain HTTPS (no AWS account needed). 10 day files, ~6.9 GB, 16.2 M flows.
SHA-256 values are NOT pinned yet: no size-verified copy exists (an earlier local copy was
corrupted by two concurrent downloaders and deleted). The script therefore refuses to run
unless ``--allow-unpinned`` is given; in that mode a file is accepted only if its size equals
the S3 Content-Length. Pin the printed hashes from a clean CI run before using any result.

By default only three days are fetched (1.09 GB): Wednesday-14-02 (FTP/SSH brute force),
Thursday-15-02 (DoS GoldenEye / Slowloris) and Friday-02-03 (Bot) -- the families that also
exist in CIC-IDS2017, for the cross-dataset study. ``--all`` fetches all ten days.

Usage:  python scripts/download_cicids2018.py [--dest D:/cyber-portfolio/datasets/feint/cicids2018]
"""
from __future__ import annotations

import argparse
import os
import urllib.parse
from pathlib import Path

from _fetch import fetch

BASE = ("https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/"
        + urllib.parse.quote("Processed Traffic Data for ML Algorithms") + "/")
FILES = {
    "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv": None,
    "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv": None,
    "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv": None,
    "Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv": None,
    "Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv": None,
    "Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv": None,
    "Friday-23-02-2018_TrafficForML_CICFlowMeter.csv": None,
    "Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv": None,
    "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv": None,
    "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv": None,
}
DEFAULT_DAYS = ["Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv",
                "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv",
                "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv"]
DEFAULT = Path(os.environ.get("FEINT_DATA") or Path.cwd() / "data") / "cicids2018"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dest", type=Path, default=DEFAULT)
    ap.add_argument("--all", action="store_true", help="all ten days (~6.9 GB)")
    ap.add_argument("--allow-unpinned", action="store_true",
                    help="accept files with no pinned SHA-256 if their size matches Content-Length")
    a = ap.parse_args()
    for name, sha in FILES.items():
        if not a.all and name not in DEFAULT_DAYS:
            continue
        fetch(BASE + name, a.dest / name, sha, allow_unpinned=a.allow_unpinned)


if __name__ == "__main__":
    main()
