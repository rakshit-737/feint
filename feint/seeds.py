"""Multi-seed robustness study with confidence intervals.

The full study (``run_study``) takes about an hour per dataset on a laptop CPU, so seed variance
is measured with a focused, like-for-like re-run: for every seed the train/test split (random
split datasets only), all model initialisations, the evaluated attack sample and the attack's
random search change; the model configuration, attack budget and eps grid default to those of the
headline study (detection at eps is a union over the grid points up to eps, so the grid matters).
Adversarial training (``adv=True``: MLP, XGBoost and ensemble, attacked through both the undefended
and the hardened MLP) and the backdoor-poisoning study (``poison=True``) are optional because they
dominate the runtime. The CIC-IDS2017 per-class subsample itself is fixed at seed 0.
"""
from __future__ import annotations

import json
import math
from collections.abc import Iterable, Sequence
from pathlib import Path

import numpy as np

from .attack import adaptive
from .data import Dataset
from .harden import adversarial_training, robust_feature_indices
from .metrics import detection_metrics, robustness_curve
from .model import BaseDetector, EnsembleDetector, Preprocessor, SklearnDetector, XGBDetector
from .pipeline import HARDENED, StudyConfig, _log, environment, split, train_members
from .poison import backdoor_study

# two-sided 97.5 % Student-t quantiles for small n (df = n - 1)
_T975 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262}


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion k/n."""
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def mean_ci(values: Iterable[float] | np.ndarray) -> dict:
    """Mean, sample std and 95 % Student-t confidence interval across seeds."""
    v = np.asarray(values, dtype=float)
    n = len(v)
    m = float(v.mean())
    if n < 2:
        return {"mean": m, "std": 0.0, "ci95": [m, m], "n": n}
    s = float(v.std(ddof=1))
    t = _T975.get(n - 1, 1.96)
    h = t * s / math.sqrt(n)
    # detection rates, F1 and FPR are proportions: clip the interval to [0, 1]
    return {"mean": m, "std": s, "ci95": [max(0.0, m - h), min(1.0, m + h)], "n": n}


def seed_study(ds: Dataset, seeds: Sequence[int] = (0, 1, 2), cfg: StudyConfig | None = None,
               adv: bool = False, poison: bool = False) -> dict:
    """Re-run training and the constrained attack for every seed; aggregate mean and 95 % CI."""
    cfg = cfg or StudyConfig()
    per_seed: dict[str, dict] = {}
    for seed in seeds:
        c = StudyConfig(**{**cfg.__dict__, "seed": int(seed)})
        _log(f"seed {seed}")
        tr, te, split_desc = split(ds, c.seed)
        pre = Preprocessor().fit(tr.X)
        mlp, xgb, ae = train_members(tr.X, tr.y, c, pre)
        rf = SklearnDetector("rf", c.seed)
        rf.pre = pre
        rf.fit_z(pre.transform(tr.X), tr.y)
        xgb_rob = XGBDetector(seed=c.seed, n_estimators=c.xgb_trees, max_depth=4 if c.fast else 8,
                              cols=robust_feature_indices(ds.schema))
        xgb_rob.pre = pre
        xgb_rob.fit_z(pre.transform(tr.X), tr.y)
        models = {"mlp": mlp, "random_forest": rf, "xgboost": xgb,
                  "ensemble": EnsembleDetector([xgb, mlp], ae), "xgboost_robust_features": xgb_rob}
        mlp_adv = None
        if adv:
            mlp_adv = adversarial_training(mlp, tr.X, tr.y, lambda d, X, e, c=c: adaptive(
                d, X, ds.schema, eps=e, steps=c.steps, iters=max(c.iters // 2, 5), seed=c.seed),
                eps=c.adv_eps, rounds=c.adv_rounds, n_adv=c.adv_n, seed=c.seed)
            xgb_adv = adversarial_training(xgb, tr.X, tr.y, lambda d, X, e, c=c, s=mlp_adv: adaptive(
                d, X, ds.schema, eps=e, surrogate=s, steps=c.steps, iters=max(c.iters // 2, 5),
                seed=c.seed), eps=c.adv_eps, rounds=c.adv_rounds, n_adv=c.adv_n, seed=c.seed)
            models.update({"mlp_adv_trained": mlp_adv, "xgboost_adv_trained": xgb_adv,
                           "ensemble_adv_trained": EnsembleDetector([xgb_adv, mlp_adv], ae)})
        rng = np.random.default_rng(c.seed)
        mal = np.flatnonzero(te.y == 1)
        X_mal = te.X[rng.choice(mal, size=min(c.max_eval, len(mal)), replace=False)]

        def atk(d: BaseDetector, X: np.ndarray, e: float, c: StudyConfig = c,
                mlp: BaseDetector = mlp) -> np.ndarray:
            return adaptive(d, X, ds.schema, eps=e, surrogate=mlp, steps=c.steps, iters=c.iters,
                            seed=c.seed)

        def atk_hard(d: BaseDetector, X: np.ndarray, e: float, c: StudyConfig = c, mlp: BaseDetector = mlp,
                     mlp_adv: BaseDetector | None = mlp_adv) -> np.ndarray:
            return adaptive(d, X, ds.schema, eps=e, surrogate=[mlp, mlp_adv], steps=c.steps,
                            iters=c.iters, seed=c.seed)

        rows = {}
        for name, m in models.items():
            clean = detection_metrics(m, te.X, te.y)
            curve = robustness_curve(m, X_mal, c.eps, ds.schema, atk_hard if name in HARDENED else atk)
            rows[name] = {"f1": clean["f1"], "fpr": clean["fpr"],
                          "detection": {str(p["eps"]): p["detection_rate"] for p in curve},
                          "n_eval": int(len(X_mal))}
            _log(f"  {name}: det@{c.eps[-1]} = {curve[-1]['detection_rate']:.3f}")
        per_seed[str(seed)] = {"split": split_desc, "models": rows}
        if poison:
            ntr = min(c.poison_max_train, len(tr.y))
            pi = rng.choice(len(tr.y), size=ntr, replace=False)

            def factory(X: np.ndarray, y: np.ndarray, c: StudyConfig = c, pre: Preprocessor = pre) -> BaseDetector:
                return XGBDetector(seed=c.seed, n_estimators=c.xgb_trees,
                                   max_depth=4 if c.fast else 8).fit(X, y, pre=pre)

            per_seed[str(seed)]["poisoning"] = backdoor_study(
                factory, tr.X[pi], tr.y[pi], te.X, te.y, ds.schema, rate=c.poison_rate, seed=c.seed,
                robust_cols=robust_feature_indices(ds.schema))

    return aggregate({"dataset": ds.info.get("name"), "seeds": list(map(int, seeds)), "eps": list(cfg.eps),
                      "adv": adv, "poison": poison, "environment": environment(), "per_seed": per_seed})


def aggregate(r: dict) -> dict:
    """(Re)compute mean / 95 % CI aggregates from ``r['per_seed']`` (used to merge CI jobs)."""
    per_seed = r["per_seed"]
    names = list(next(iter(per_seed.values()))["models"])
    agg = {}
    for name in names:
        runs = [per_seed[s]["models"][name] for s in per_seed]
        agg[name] = {"f1": mean_ci([r["f1"] for r in runs]), "fpr": mean_ci([r["fpr"] for r in runs]),
                     "detection": {e: mean_ci([r["detection"][e] for r in runs]) for e in runs[0]["detection"]}}
    out = {**r, "seeds": sorted(int(s) for s in per_seed),
           "ci_note": "Student-t 95 % CI across seeds (t quantile for n-1 df), clipped to [0, 1]",
           "aggregate": agg}
    P = [per_seed[s]["poisoning"] for s in per_seed if "poisoning" in per_seed[s]]
    if P and len(P) == len(per_seed):
        pa = {}
        for tag in ("clean_model", "poisoned_model", "sanitized_model"):
            if all(tag in p for p in P):
                pa[tag] = {k: mean_ci([p[tag][k] for p in P]) for k in P[0][tag]}
        if all("sanitizer" in p for p in P):
            pa["sanitizer"] = {k: mean_ci([p["sanitizer"][k] for p in P])
                               for k in ("poison_recall", "precision", "clean_benign_removed_frac")}
        out["poisoning_aggregate"] = pa
    return out


def merge(paths: Iterable[str | Path]) -> dict:
    """Merge several single-seed ``seeds.json`` files (e.g. one per CI job) into one study."""
    rs = [json.loads(Path(p).read_text()) for p in paths]
    per_seed = {k: v for r in rs for k, v in r["per_seed"].items()}
    return aggregate({**rs[0], "per_seed": per_seed})


def to_markdown(r: dict) -> str:
    """Markdown tables (mean [95 % CI]) of a seed study, including the poisoning aggregate."""
    eps = [str(float(e)) for e in r["eps"]]
    L = [f"# Multi-seed robustness: {r['dataset']}", "",
         f"Seeds {r['seeds']} (n={len(r['seeds'])}); mean with 95 % Student-t CI across seeds. "
         "Constrained adaptive attack, detection rate on held-out attack flows (higher is better).", "",
         "| model | clean F1 | FPR | " + " | ".join(f"eps={e}" for e in eps) + " |",
         "|---|---|---|" + "---|" * len(eps)]

    def f(ci: dict) -> str:
        return f"{ci['mean']:.3f} [{ci['ci95'][0]:.3f}, {ci['ci95'][1]:.3f}]"

    for name, a in r["aggregate"].items():
        L.append(f"| {name} | {f(a['f1'])} | {f(a['fpr'])} | "
                 + " | ".join(f(a["detection"][e]) for e in eps) + " |")
    if "poisoning_aggregate" in r:
        L += ["", "## Backdoor poisoning (2 % of a training subsample), mean [95 % CI]", "",
              "| model | clean accuracy | backdoor success |", "|---|---|---|"]
        for tag, v in r["poisoning_aggregate"].items():
            if tag == "sanitizer":
                continue
            L.append(f"| {tag} | {f(v['clean_accuracy'])} | {f(v['backdoor_success'])} |")
        if "sanitizer" in r["poisoning_aggregate"]:
            z = r["poisoning_aggregate"]["sanitizer"]
            L += ["", f"Sanitiser: poison recall {f(z['poison_recall'])}, precision {f(z['precision'])}, "
                  f"clean benign removed {f(z['clean_benign_removed_frac'])}."]
    L += ["", "Per-seed binomial (Wilson) 95 % interval half-width at n="
          f"{next(iter(r['per_seed'].values()))['models']['xgboost']['n_eval']} evaluated flows is at most "
          f"{max_wilson_halfwidth(next(iter(r['per_seed'].values()))['models']['xgboost']['n_eval']):.3f}.", ""]
    return "\n".join(L)


def max_wilson_halfwidth(n: int) -> float:
    """Largest Wilson 95 % half-width at ``n`` trials (attained at p = 0.5)."""
    lo, hi = wilson(n // 2, n)
    return (hi - lo) / 2


def save(r: dict, out_dir: str | Path) -> Path:
    """Write ``seeds.json`` and ``seeds.md`` into ``out_dir``."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "seeds.json").write_text(json.dumps(r, indent=2))
    (out / "seeds.md").write_text(to_markdown(r), encoding="utf-8")
    return out
