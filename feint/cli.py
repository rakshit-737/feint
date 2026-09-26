"""feint CLI: `python -m feint.cli run|generate`."""
from __future__ import annotations

import argparse
import csv
import sys

from .data import load_cicids_csv, synthetic_flows
from .pipeline import DEFAULT_EPS, run_study, save, to_markdown


def main(argv=None):
    ap = argparse.ArgumentParser(prog="feint", description="Adversarially-robust NIDS study")
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="train, attack, harden, report")
    r.add_argument("--data", default="synthetic", help="'synthetic' or path to CIC-IDS2017 CSV")
    r.add_argument("--n", type=int, default=4000, help="synthetic flow count")
    r.add_argument("--max-rows", type=int, default=200000)
    r.add_argument("--seed", type=int, default=0)
    r.add_argument("--eps", type=float, nargs="+", default=DEFAULT_EPS)
    r.add_argument("--adv-eps", type=float, default=2.0)
    r.add_argument("--adv-rounds", type=int, default=3)
    r.add_argument("--steps", type=int, default=20)
    r.add_argument("--out", default="results")

    g = sub.add_parser("generate", help="write synthetic flows to CSV")
    g.add_argument("--n", type=int, default=4000)
    g.add_argument("--seed", type=int, default=0)
    g.add_argument("--out", default="flows.csv")

    a = ap.parse_args(argv)
    if a.cmd == "generate":
        ds = synthetic_flows(a.n, seed=a.seed)
        with open(a.out, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(ds.feature_names + ["label"])
            for x, y in zip(ds.X, ds.y):
                w.writerow(list(map(float, x)) + [int(y)])
        print(f"wrote {len(ds.y)} flows to {a.out}")
        return 0

    ds = synthetic_flows(a.n, seed=a.seed) if a.data == "synthetic" else load_cicids_csv(a.data, a.max_rows)
    rep = run_study(ds, eps_list=a.eps, seed=a.seed, adv_eps=a.adv_eps, adv_rounds=a.adv_rounds, steps=a.steps)
    out = save(rep, a.out)
    print(to_markdown(rep))
    print(f"\nsaved {out / 'report.json'} and {out / 'report.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
