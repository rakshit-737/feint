"""Merge per-seed ``seeds.json`` files from CI matrix jobs into one seeds.json / seeds.md.

Usage:  python scripts/merge_seeds.py OUT_DIR seed0/seeds.json seed1/seeds.json ...
        (or per-seed ablation.json files)
"""
import sys

from feint import ablation as AB
from feint import seeds as S

if __name__ == "__main__":
    paths = sys.argv[2:]
    if paths and paths[0].endswith("ablation.json"):
        out = AB.save(AB.merge(paths), sys.argv[1])
        print((out / "ablation.md").read_text(encoding="utf-8"))
    else:
        out = S.save(S.merge(paths), sys.argv[1])
        print((out / "seeds.md").read_text(encoding="utf-8"))
