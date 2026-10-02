"""feint CLI.

    python -m feint run --data synthetic|cicids2017|unsw_nb15|<csv> [--quick] [--out DIR]
    python -m feint seeds --data unsw_nb15 --seeds 0 1 2 --out results/unsw_nb15
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

from .data import (
    load_cicids2017,
    load_cicids2017_corrected,
    load_cicids2018,
    load_cicids_csv,
    load_ciciot2023,
    load_unsw_nb15,
    synthetic_flows,
)
from .pipeline import DEFAULT_EPS, StudyConfig, run_study, save

DATASETS = ("synthetic", "cicids2017", "cicids2017_corrected", "cicids2018", "ciciot2023", "unsw_nb15")


def load(name: str, a) -> object:
    if name == "synthetic":
        return synthetic_flows(a.n, seed=a.seed)
    if name == "cicids2017":
        return load_cicids2017(a.data_dir, frac=a.frac, seed=a.seed)
    if name == "unsw_nb15":
        return load_unsw_nb15(a.data_dir)
    per_class = getattr(a, "per_class", 20_000)
    if name == "ciciot2023":
        return load_ciciot2023(a.data_dir, per_class=min(per_class, 5_000), seed=a.seed)
    if name == "cicids2018":
        return load_cicids2018(a.data_dir, per_class=per_class, seed=a.seed)
    if name == "cicids2017_corrected":
        return load_cicids2017_corrected(a.data_dir, per_class=per_class, seed=a.seed,
                                         attempted=getattr(a, "attempted", "benign"))
    if not Path(name).is_file():
        raise SystemExit(f"--data: unknown dataset {name!r}; use one of {', '.join(DATASETS)} "
                         "or a path to a CICFlowMeter CSV")
    return load_cicids_csv(name, a.max_rows)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="feint", description="Adversarially-robust NIDS study")
    from . import __version__
    ap.add_argument("--version", action="version", version=f"feint {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="train, attack, harden, explain, poison, report")
    r.add_argument("--data", default="synthetic",
                   help=f"one of {', '.join(DATASETS)} or a path to a CICFlowMeter CSV")
    r.add_argument("--per-class", type=int, default=20_000,
                   help="flows kept per label for cicids2018 / cicids2017_corrected")
    r.add_argument("--attempted", choices=["benign", "attack"], default="benign",
                   help="corrected CIC-IDS2017: how to label '- Attempted' flows")
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

    sd = sub.add_parser("seeds", help="multi-seed robustness study with 95%% confidence intervals")
    sd.add_argument("--data", default="synthetic")
    sd.add_argument("--data-dir", default=None)
    sd.add_argument("--frac", type=float, default=0.1)
    sd.add_argument("--n", type=int, default=4000)
    sd.add_argument("--max-rows", type=int, default=200000)
    sd.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2])
    sd.add_argument("--eps", type=float, nargs="+", default=DEFAULT_EPS,
                    help="budget grid (default = headline grid; detection is a union over it)")
    sd.add_argument("--max-eval", type=int, default=1000)
    sd.add_argument("--adv", action="store_true",
                    help="also adversarially train MLP, XGBoost and ensemble per seed (slow)")
    sd.add_argument("--poison", action="store_true", help="also run the backdoor-poisoning study per seed")
    sd.add_argument("--quick", action="store_true")
    sd.add_argument("--out", default="results")

    xd = sub.add_parser("xdata", help="cross-dataset study: train on one CIC dataset, test on another",
                        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    xd.add_argument("--train", default="cicids2017", help="training dataset name or CSV path")
    xd.add_argument("--test", default="cicids2018", help="test dataset name or CSV path")
    xd.add_argument("--train-dir", default=None, help="training dataset directory")
    xd.add_argument("--test-dir", default=None, help="test dataset directory")
    xd.add_argument("--frac", type=float, default=0.1, help="CIC-IDS2017 per-class sampling fraction")
    xd.add_argument("--per-class", type=int, default=20_000, help="flows kept per label (2018 / corrected)")
    xd.add_argument("--attempted", choices=["benign", "attack"], default="benign",
                    help="corrected CIC-IDS2017: how to label '- Attempted' flows")
    xd.add_argument("--max-rows", type=int, default=200000, help="rows read from a CSV path")
    xd.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2], help="model / attack seeds")
    xd.add_argument("--eps", type=float, nargs="+", default=DEFAULT_EPS, help="attack budget grid")
    xd.add_argument("--quick", action="store_true", help="tiny models and budgets (smoke test)")
    xd.add_argument("--out", default="results/xdata", help="output directory")

    rp = sub.add_parser("repro", help="reproduce a published result under the paper's own setup",
                        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    rp.add_argument("--paper", choices=["sharafaldin2018", "moustafa2016"], required=True)
    rp.add_argument("--data-dir", default=None, help="dataset directory")
    rp.add_argument("--seed", type=int, default=0, help="split / model seed")
    rp.add_argument("--models", nargs="*", default=None, help="subset of classifiers (default: all)")
    rp.add_argument("--out", default="results/repro", help="output directory")

    st = sub.add_parser("steal", help="model-stealing study (label-only queries -> transfer attack)")
    st.add_argument("--data", default="synthetic")
    st.add_argument("--data-dir", default=None)
    st.add_argument("--frac", type=float, default=0.1)
    st.add_argument("--n", type=int, default=4000)
    st.add_argument("--max-rows", type=int, default=200000)
    st.add_argument("--seed", type=int, default=0)
    st.add_argument("--budgets", type=int, nargs="+", default=[500, 2000, 10000])
    st.add_argument("--eps", type=float, nargs="+", default=[0.5, 1.0, 2.0])
    st.add_argument("--quick", action="store_true")
    st.add_argument("--out", default="results")

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
        try:
            import uvicorn
        except ImportError:
            print("feint serve needs the API extra: pip install 'feint[api]'", file=sys.stderr)
            return 2

        from .api import create_app

        uvicorn.run(create_app(a.model), host=a.host, port=a.port)
        return 0

    if a.cmd == "steal":
        import json as _json

        from . import steal as ST

        ds = load(a.data, a)
        cfg = StudyConfig.quick(seed=a.seed) if a.quick else StudyConfig(seed=a.seed)
        r = ST.steal_study(ds, a.budgets, a.eps, cfg)
        out = Path(a.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "steal.json").write_text(_json.dumps(r, indent=2))
        (out / "steal.md").write_text(ST.to_markdown(r), encoding="utf-8")
        print(ST.to_markdown(r))
        return 0

    if a.cmd == "repro":
        from . import repro as RP

        if a.paper == "sharafaldin2018":
            r = RP.sharafaldin2018(a.data_dir, seed=a.seed, models=a.models)
        else:
            r = RP.moustafa_slay2016(a.data_dir, seed=a.seed)
        RP.save(r, a.out, a.paper)
        print(RP.to_markdown(r))
        return 0

    if a.cmd == "xdata":
        from . import xdata as XD

        a.seed, a.n = 0, 4000
        a.data_dir = a.train_dir
        train = load(a.train, a)
        a.data_dir = a.test_dir
        test = load(a.test, a)
        cfg = StudyConfig.quick(eps=a.eps) if a.quick else StudyConfig(eps=a.eps)
        r = XD.xdata_study(train, test, a.seeds, cfg)
        out = XD.save(r, a.out)
        print(XD.to_markdown(r))
        print(f"saved {out / 'xdata.json'}")
        return 0

    if a.cmd == "seeds":
        from . import seeds as S

        a.seed = 0  # the data sample is fixed; model / split / attack seeds vary
        ds = load(a.data, a)
        cfg = StudyConfig.quick(eps=a.eps) if a.quick else StudyConfig(eps=a.eps, max_eval=a.max_eval)
        r = S.seed_study(ds, a.seeds, cfg, adv=a.adv, poison=a.poison)
        out = S.save(r, a.out)
        print(S.to_markdown(r))
        print(f"saved {out / 'seeds.json'}")
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
