"""feint CLI.

    python -m feint run --data synthetic|cicids2017|unsw_nb15|<csv> [--quick] [--out DIR]
    python -m feint generate --n 4000 --out flows.csv
    python -m feint serve --model results/cicids2017/model.joblib   (needs the [api] extra)

`run --save-model` writes the bundle that `serve` loads.
"""
from __future__ import annotations

import argparse
import csv
import sys
import warnings
from pathlib import Path

from .data import load_cicids2017, load_cicids_csv, load_unsw_nb15, synthetic_flows
from .pipeline import DEFAULT_EPS, StudyConfig, run_study, save


def load(name: str, a) -> object:
    if name == "synthetic":
        return synthetic_flows(a.n, seed=a.seed)
    if name == "cicids2017":
        return load_cicids2017(a.data_dir, frac=a.frac, seed=a.seed)
    if name == "unsw_nb15":
        return load_unsw_nb15(a.data_dir)
    return load_cicids_csv(name, a.max_rows)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="feint", description="Adversarially-robust NIDS study")
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="train, attack, harden, explain, poison, report")
    r.add_argument("--data", default="synthetic",
                   help="'synthetic', 'cicids2017', 'unsw_nb15' or a path to a CICFlowMeter CSV")
    r.add_argument("--data-dir", default=None, help="dataset directory (default: $FEINT_DATA/<name>)")
    r.add_argument("--frac", type=float, default=0.1, help="CIC-IDS2017 per-class sampling fraction")
    r.add_argument("--n", type=int, default=4000, help="synthetic flow count")
    r.add_argument("--max-rows", type=int, default=200000)
    r.add_argument("--seed", type=int, default=0)
    r.add_argument("--eps", type=float, nargs="+", default=DEFAULT_EPS)
    r.add_argument("--adv-eps", type=float, default=2.0)
    r.add_argument("--adv-rounds", type=int, default=3)
    r.add_argument("--steps", type=int, default=20)
    r.add_argument("--iters", type=int, default=100)
    r.add_argument("--max-eval", type=int, default=1000)
    r.add_argument("--quick", action="store_true", help="tiny models / budgets (CI smoke test)")
    r.add_argument("--no-figures", action="store_true")
    r.add_argument("--save-model", action="store_true", help="also write model.joblib for `serve`")
    r.add_argument("--out", default="results")

    g = sub.add_parser("generate", help="write synthetic flows to CSV")
    g.add_argument("--n", type=int, default=4000)
    g.add_argument("--seed", type=int, default=0)
    g.add_argument("--out", default="flows.csv")

    s = sub.add_parser("serve", help="HTTP scoring + explanation API (FastAPI)")
    s.add_argument("--model", required=True)
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)

    a = ap.parse_args(argv)
    # scikit-learn >= 1.6 on Python 3.14 warns on every parallel predict; keep logs readable
    warnings.filterwarnings("ignore", category=UserWarning, module=r"sklearn\.")
    if a.cmd == "generate":
        ds = synthetic_flows(a.n, seed=a.seed)
        with open(a.out, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(ds.feature_names + ["label"])
            for x, y in zip(ds.X, ds.y):
                w.writerow(list(map(float, x)) + [int(y)])
        print(f"wrote {len(ds.y)} flows to {a.out}")
        return 0

    if a.cmd == "serve":
        import uvicorn

        from .api import create_app

        uvicorn.run(create_app(a.model), host=a.host, port=a.port)
        return 0

    ds = load(a.data, a)
    kw = dict(eps=a.eps, seed=a.seed, adv_eps=a.adv_eps, adv_rounds=a.adv_rounds, steps=a.steps,
              iters=a.iters, max_eval=a.max_eval)
    cfg = StudyConfig.quick(**{k: v for k, v in kw.items() if k in ("eps", "seed", "adv_eps")}) \
        if a.quick else StudyConfig(**kw)
    rep, models = run_study(ds, cfg, return_models=True)
    out = save(rep, a.out, figures=not a.no_figures)
    if a.save_model:
        from .api import save_bundle

        save_bundle(models, ds.schema, Path(out) / "model.joblib")
    print((Path(out) / "report.md").read_text(encoding="utf-8"))
    print(f"\nsaved {out / 'report.json'} and {out / 'report.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
