"""Download CIC-IDS2017 MachineLearningCSV (the official CICFlowMeter feature CSVs).

Source of truth: Canadian Institute for Cybersecurity, University of New Brunswick
(https://www.unb.ca/cic/datasets/ids-2017.html). UNB now gates direct downloads behind a
form, so by default we fetch a ``MachineLearningCSV.zip`` mirror on the
Hugging Face Hub and verify its SHA-256. ~235 MB zipped, 885 MB extracted, 2,830,743 flows.

Usage:  python scripts/download_cicids2017.py [--dest D:/cyber-portfolio/datasets/feint/cicids2017]
"""
from __future__ import annotations

import argparse
import os
import zipfile
from pathlib import Path

from _fetch import fetch

URL = "https://huggingface.co/datasets/bencorn/CICIDS2017/resolve/main/csvs/MachineLearningCSV.zip"
SHA256 = "c3f26274b36c837ccf28ffd2dbf4582941c30b3ee70a635c6e5b2f87c4727928"
DEFAULT = Path(os.environ.get("FEINT_DATA") or Path.cwd() / "data") / "cicids2017"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dest", type=Path, default=DEFAULT)
    a = ap.parse_args()
    z = fetch(URL, a.dest / "MachineLearningCSV.zip", SHA256)
    out = a.dest / "MachineLearningCVE"
    if not out.exists() or len(list(out.glob("*.csv"))) < 8:
        with zipfile.ZipFile(z) as zf:
            zf.extractall(a.dest)
    print(f"[ok] {len(list(out.glob('*.csv')))} CSV files in {out}")


if __name__ == "__main__":
    main()
