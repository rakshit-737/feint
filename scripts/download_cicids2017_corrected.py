"""Download the *corrected* CIC-IDS2017 (Engelen, Rimmer & Joosen, SPW 2021; re-released by
Liu, Engelen, Lynar, Essam & Joosen, IEEE CNS 2022, doi:10.1109/CNS56114.2022.9947235).

They fixed CICFlowMeter's TCP-termination and timeout bugs, regenerated the flows from the
original PCAPs and relabelled them (adding "- Attempted" classes for attack flows that carry
no attack payload). Source of truth: https://intrusion-detection.distrinet-research.be/CNS2022/Datasets/
(CICIDS2017_improved.zip; the WTMC2021 page points there). We fetch the Hugging Face mirror
``bvk/CICIDS-2017``, a Kaggle re-export of that CNS 2022 release (its Timestamp column is
mangled; we do not use it) (5 day CSVs, ~810 MB; the mirror only adds decimal-encoded IP columns and
drops a few rows with inf values) and verify SHA-256.

Usage:  python scripts/download_cicids2017_corrected.py [--dest .../cicids2017-corrected]
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path

from _fetch import fetch

BASE = "https://huggingface.co/datasets/bvk/CICIDS-2017/resolve/main/"
FILES = {
    "monday.csv": "c493314d7f2cd5614193d3fd8de6d0731edfe1383ccf24df0323c8c6899ba7ab",
    "tuesday.csv": "664b615572fdbd88ae24d01f33a538983277359151e9fd5172d40da092362f71",
    "wednesday.csv": "87c6ab27cef32df2dcac315ecd992f918484e71856f32b0d2a55eb171a774d60",
    "thursday.csv": "e3cac669f495df33da7ae1e8fcc06ed511d3161b97a7ba9263f2d476cf467a0e",
    "friday.csv": "e16fa2655766ed685fe3e43455d7e4024a81f8a1965c1eabf56e53dc9f07fb6b",
}
DEFAULT = Path(os.environ.get("FEINT_DATA", Path(__file__).resolve().parents[1] / "data")) / "cicids2017-corrected"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dest", type=Path, default=DEFAULT)
    a = ap.parse_args()
    for name, sha in FILES.items():
        fetch(BASE + name, a.dest / name, sha)


if __name__ == "__main__":
    main()
