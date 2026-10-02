"""Cross-dataset evaluation: train on one CICFlowMeter dataset, test on another.

Both datasets are projected onto the same 11-feature CIC schema (``feint.data.CIC_ALIASES``
harmonises the header spellings) and restricted to the attack families that exist in both
(``feint.data.SHARED_FAMILIES``) plus benign. For each seed we report clean recall per family,
FPR and PR-AUC on the *other* dataset, and the constrained robustness curve after the shift for
the undefended XGBoost, the adversarially trained XGBoost and the robust-feature XGBoost, so the
study shows whether a defence's gain survives a change of network and capture year.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from .attack import adaptive
from .data import SHARED_FAMILIES, Dataset
from .harden import adversarial_training, robust_feature_indices
from .metrics import detection_metrics, robustness_curve
from .model import Preprocessor, XGBDetector
from .pipeline import StudyConfig, _log, environment, train_members
from .seeds import mean_ci


def harmonise(ds: Dataset) -> Dataset:
    """Keep benign and shared families only; relabel families to their common names."""
    fam = np.array([SHARED_FAMILIES.get(a, "") for a in ds.attack])
    out = ds.subset(fam != "")
    out.attack = fam[fam != ""]
    return out


def xdata_study(train: Dataset, test: Dataset, seeds=(0, 1, 2), cfg: StudyConfig | None = None,
                max_test: int = 50_000) -> dict:
    """Train on ``train``, evaluate on ``test`` (both harmonised) for every seed."""
    cfg = cfg or StudyConfig()
    tr, te = harmonise(train), harmonise(test)
    per_seed = {}
    for seed in seeds:
        c = StudyConfig(**{**cfg.__dict__, "seed": int(seed)})
        rng = np.random.default_rng(c.seed)
        _log(f"xdata seed {seed}: train {train.info.get('name')} ({len(tr)}) -> test "
             f"{test.info.get('name')} ({len(te)})")
        ti = rng.choice(len(te), size=min(max_test, len(te)), replace=False)
        tes = te.subset(np.isin(np.arange(len(te)), ti))
        pre = Preprocessor().fit(tr.X)
        mlp, xgb, _ = train_members(tr.X, tr.y, c, pre)
        rob = XGBDetector(seed=c.seed, n_estimators=c.xgb_trees, max_depth=4 if c.fast else 8,
                          cols=robust_feature_indices(tr.schema))
        rob.pre = pre
        rob.fit_z(pre.transform(tr.X), tr.y)
        xgb_adv = adversarial_training(xgb, tr.X, tr.y, lambda d, X, e, c=c, s=mlp: adaptive(
            d, X, tr.schema, eps=e, surrogate=s, steps=c.steps, iters=max(c.iters // 2, 5), seed=c.seed),
            eps=c.adv_eps, rounds=c.adv_rounds, n_adv=c.adv_n, seed=c.seed)
        models = {"xgboost": xgb, "xgboost_adv_trained": xgb_adv, "xgboost_robust_features": rob}
        mal = np.flatnonzero(tes.y == 1)
        X_mal = tes.X[rng.choice(mal, size=min(c.max_eval, len(mal)), replace=False)]
        rows = {}
        for name, m in models.items():
            met = detection_metrics(m, tes.X, tes.y)
            pred = m.predict(tes.X)
            fam = {f: float((pred[tes.attack == f] == 1).mean()) for f in sorted(set(tes.attack)) if f != "BENIGN"}
            nfam = {f: int((tes.attack == f).sum()) for f in fam}
            curve = robustness_curve(m, X_mal, c.eps, tes.schema, lambda d, X, e, c=c, t=tes, s=mlp: adaptive(
                d, X, t.schema, eps=e, surrogate=s, steps=c.steps, iters=c.iters, seed=c.seed))
            rows[name] = {"f1": met["f1"], "fpr": met["fpr"], "recall": met.get("recall"),
                          "pr_auc": met.get("pr_auc"), "family_recall": fam, "family_n": nfam,
                          "detection": {str(p["eps"]): p["detection_rate"] for p in curve}}
            _log(f"  {name}: F1 {met['f1']:.3f} FPR {met['fpr']:.4f}")
        per_seed[str(seed)] = rows
    names = list(next(iter(per_seed.values())))
    agg = {}
    for n in names:
        runs = [per_seed[s][n] for s in per_seed]
        agg[n] = {"f1": mean_ci([r["f1"] for r in runs]), "fpr": mean_ci([r["fpr"] for r in runs]),
                  "family_recall": {f: mean_ci([r["family_recall"][f] for r in runs])
                                    for f in runs[0]["family_recall"]},
                  "detection": {e: mean_ci([r["detection"][e] for r in runs]) for e in runs[0]["detection"]}}
    return {"train": train.info.get("name"), "test": test.info.get("name"), "seeds": list(map(int, seeds)),
            "eps": list(cfg.eps), "n_train": int(len(tr)), "n_test": int(min(max_test, len(te))),
            "train_classes": {str(k): int(v) for k, v in zip(*np.unique(tr.attack, return_counts=True))},
            "test_classes": {str(k): int(v) for k, v in zip(*np.unique(te.attack, return_counts=True))},
            "environment": environment(), "per_seed": per_seed, "aggregate": agg}


def to_markdown(r: dict) -> str:
    def f(ci):
        return f"{ci['mean']:.3f} [{ci['ci95'][0]:.3f}, {ci['ci95'][1]:.3f}]"

    eps = [str(float(e)) for e in r["eps"]]
    L = [f"# Cross-dataset: train {r['train']} -> test {r['test']}", "",
         f"Seeds {r['seeds']}; mean [95 % Student-t CI]. Shared families only, harmonised 11-feature "
         f"CIC schema. Train n={r['n_train']}, test n={r['n_test']}.", "",
         "| model | F1 | FPR | " + " | ".join(f"det eps={e}" for e in eps) + " |",
         "|---|---|---|" + "---|" * len(eps)]
    for n, a in r["aggregate"].items():
        L.append(f"| {n} | {f(a['f1'])} | {f(a['fpr'])} | " + " | ".join(f(a["detection"][e]) for e in eps) + " |")
    fams = sorted(next(iter(r["aggregate"].values()))["family_recall"])
    L += ["", "Per-family recall on the test dataset:", "",
          "| family | n | " + " | ".join(r["aggregate"]) + " |", "|---|---|" + "---|" * len(r["aggregate"])]
    n0 = next(iter(r["per_seed"].values()))
    for fam in fams:
        L.append(f"| {fam} | {next(iter(n0.values()))['family_n'][fam]} | "
                 + " | ".join(f(a["family_recall"][fam]) for a in r["aggregate"].values()) + " |")
    return "\n".join(L) + "\n"


def save(r: dict, out_dir) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "xdata.json").write_text(json.dumps(r, indent=2))
    (out / "xdata.md").write_text(to_markdown(r), encoding="utf-8")
    return out
