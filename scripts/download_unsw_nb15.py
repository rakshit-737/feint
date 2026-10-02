"""Download the official UNSW-NB15 train/test partition (Moustafa & Slay, 2015).

Source of truth: UNSW Canberra Cyber (https://research.unsw.edu.au/projects/unsw-nb15-dataset),
distributed via SharePoint which cannot be scripted, so we fetch CSV mirrors
hosted on the Hugging Face Hub and verify SHA-256.

Note: the mirror follows a well-known naming swap; we restore the official names by row
count (training set = 175,341 flows, testing set = 82,332 flows). ~48 MB total.

Usage:  python scripts/download_unsw_nb15.py [--dest D:/cyber-portfolio/datasets/feint/unsw-nb15]
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path

from _fetch import fetch

BASE = "https://huggingface.co/datasets/Mireu-Lab/UNSW-NB15/resolve/main/"
FILES = {
    # official name                 (mirror name, sha256)
    "UNSW_NB15_training-set.csv": ("test.csv", "bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa"),
    "UNSW_NB15_testing-set.csv": ("train.csv", "734fe6642edf758f7c94d7d9149426b49d202fe8e7bf0bef47392489c3c0a559"),
}
DEFAULT = Path(os.environ.get("FEINT_DATA") or Path.cwd() / "data") / "unsw-nb15"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dest", type=Path, default=DEFAULT)
    a = ap.parse_args()
    for official, (mirror, sha) in FILES.items():
        fetch(BASE + mirror, a.dest / official, sha)


if __name__ == "__main__":
    main()
