"""Merge per-seed ``seeds.json`` files from CI matrix jobs into one seeds.json / seeds.md.

Usage:  python scripts/merge_seeds.py OUT_DIR seed0/seeds.json seed1/seeds.json ...
"""
import sys

from feint import seeds as S

if __name__ == "__main__":
    out = S.save(S.merge(sys.argv[2:]), sys.argv[1])
    print((out / "seeds.md").read_text(encoding="utf-8"))
