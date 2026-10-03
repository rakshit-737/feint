"""End-to-end study: train -> red-team -> harden -> explain -> poison -> drift -> report."""
from __future__ import annotations

import dataclasses
import json
import time
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.model_selection import train_test_split

from .attack import adaptive
from .data import CIC_DAYS, Dataset, synthetic_flows
from .explain import counterfactual, describe_counterfactual, global_importance
from .harden import AdversarialInputDetector, adversarial_training, robust_feature_indices
from .metrics import area_under_curve, detection_metrics, robustness_curve
from .model import (
    AutoencoderDetector,
    BaseDetector,
    EnsembleDetector,
    IForestDetector,
    MLPDetector,
    Preprocessor,
    SklearnDetector,
    XGBDetector,
)
from .poison import backdoor_study
from .schema import Schema

HARDENED = ("xgboost_adv_trained", "ensemble_adv_trained")
DEFAULT_EPS = [0.0, 0.25, 0.5, 1.0, 1.5, 2.0]


@dataclass
class StudyConfig:
    """Settings of one study; :meth:`quick` gives tiny models and budgets for CI and smoke tests."""

    eps: list = field(default_factory=lambda: list(DEFAULT_EPS))
    seed: int = 0
    adv_eps: float = 2.0
    adv_rounds: int = 3
    adv_n: int = 5000  # malicious training flows perturbed per adversarial-training round
    steps: int = 20  # PGD steps
    iters: int = 100  # black-box search queries
    max_eval: int = 1000  # malicious test flows attacked per curve point
    n_cf: int = 200  # counterfactuals
    poison_rate: float = 0.02
    poison_max_train: int = 100_000
    mlp_hidden: tuple = (64, 32)
    xgb_trees: int = 300
    fast: bool = False  # tiny models for CI / smoke tests
    drift: bool = True
    baselines: bool = True

    @classmethod
    def quick(cls, **kw: Any) -> StudyConfig:
        """Small, fast configuration (overridable with keyword arguments)."""
        base = dict(adv_rounds=1, adv_n=300, steps=5, iters=15, max_eval=150, n_cf=20,
                    poison_max_train=3000, mlp_hidden=(16,), xgb_trees=40, fast=True)
        base.update(kw)
        return cls(**base)


def restrict(schema: Schema, feats: list[str]) -> Schema:
    """Same schema, but the attacker controls only ``feats``."""
    return dataclasses.replace(schema, up=[f for f in schema.up if f in feats],
                               free={f: r for f, r in schema.free.items() if f in feats},
                               integer=list(schema.integer))


def split(ds: Dataset, seed: int = 0) -> tuple[Dataset, Dataset, str]:
    """(train, test, description): UNSW-NB15's official partition, else a stratified 70/30 split."""
    if ds.info.get("name") == "unsw_nb15" and ds.group is not None and len(set(ds.group)) == 2:
        tr, te = ds.group == 0, ds.group == 1  # official partition
        return ds.subset(tr), ds.subset(te), "official train/test partition"
    idx = np.arange(len(ds))
    a, b = train_test_split(idx, test_size=0.3, random_state=seed, stratify=ds.y)
    ma, mb = np.zeros(len(ds), bool), np.zeros(len(ds), bool)
    ma[a], mb[b] = True, True
    return ds.subset(ma), ds.subset(mb), "stratified random 70/30"


class Timer:
    """Wall-clock seconds of named blocks: ``with timer("name"): ...`` records ``timer.t["name"]``."""

    def __init__(self) -> None:
        self.t = {}

    def __call__(self, name: str) -> AbstractContextManager[None]:
        """Context manager that times its block under ``name``."""
        tm = self

        class _C:
            def __enter__(self_) -> None:
                self_.s = time.time()

            def __exit__(self_, *a: object) -> None:
                tm.t[name] = round(time.time() - self_.s, 2)
        return _C()


def _log(msg: str) -> None:
    print(f"[feint {time.strftime('%H:%M:%S')}] {msg}", flush=True)


def train_members(Xtr: np.ndarray, ytr: np.ndarray, cfg: StudyConfig,
                  pre: Preprocessor) -> tuple[MLPDetector, XGBDetector, AutoencoderDetector]:
    """Train the ensemble members (MLP, XGBoost, benign autoencoder) on a shared preprocessor."""
    Ztr = pre.transform(Xtr)
    mlp = MLPDetector(hidden=cfg.mlp_hidden, seed=cfg.seed, max_iter=60 if cfg.fast else 200)
    xgb = XGBDetector(seed=cfg.seed, n_estimators=cfg.xgb_trees, max_depth=4 if cfg.fast else 8)
    ae = AutoencoderDetector(hidden=(8, 4, 8) if cfg.fast else (32, 8, 32), seed=cfg.seed,
                             max_iter=60 if cfg.fast else 200)
    for m in (mlp, xgb, ae):
        m.pre = pre
    mlp.fit_z(Ztr, ytr)
    xgb.fit_z(Ztr, ytr)
    ae.fit_z(Ztr, ytr)
    return mlp, xgb, ae


def run_study(ds: Dataset | None = None, cfg: StudyConfig | None = None, return_models: bool = False,
              **kw: Any) -> dict | tuple[dict, dict]:
    """Full study on ``ds`` (synthetic flows by default); returns the report, and the models if asked.

    Steps: train detectors and baselines, adversarially train and fit the robust-feature model,
    clean metrics, constrained and textbook robustness curves, SHAP and counterfactuals, the
    adversarial-input alarm, poisoning and (CIC-IDS2017) temporal drift. ``kw`` builds a
    :class:`StudyConfig` when ``cfg`` is None.
    """
    cfg = cfg or StudyConfig(**kw)
    ds = ds or synthetic_flows(seed=cfg.seed)
    schema = ds.schema
    rng = np.random.default_rng(cfg.seed)
    T = Timer()
    tr, te, split_desc = split(ds, cfg.seed)
    Xtr, ytr, Xte, yte = tr.X, tr.y, te.X, te.y
    report = {
        "dataset": ds.info, "schema": schema.name, "split": split_desc,
        "n_train": int(len(ytr)), "n_test": int(len(yte)),
        "attack_prevalence_test": float(yte.mean()),
        "features": ds.feature_names, "controllable": schema.controllable,
        "robust_features": schema.robust_features(), "config": dataclasses.asdict(cfg),
        "models": {}, "robustness": {}, "timings_s": T.t,
    }
    pre = Preprocessor().fit(Xtr)

    # ------------------------------------------------------------------ 1. detectors
    _log(f"training detectors on {len(ytr):,} flows")
    with T("train_members"):
        mlp, xgb, ae = train_members(Xtr, ytr, cfg, pre)
        ens = EnsembleDetector([xgb, mlp], ae)
    models = {"mlp": mlp, "xgboost": xgb, "autoencoder": ae, "ensemble": ens}
    if cfg.baselines:
        with T("train_baselines"):
            lr = SklearnDetector("logreg", cfg.seed)
            rf = SklearnDetector("rf", cfg.seed)
            iso = IForestDetector(cfg.seed)
            for m in (lr, rf, iso):
                m.pre = pre
                m.fit_z(pre.transform(Xtr), ytr)
        models = {"logreg": lr, "random_forest": rf, "iforest": iso, **models}

    # ------------------------------------------------------------------ 2. hardening
    def atk(det: BaseDetector, X: np.ndarray, eps: float, constrained: bool = True,
            sch: Schema = schema) -> np.ndarray:
        return adaptive(det, X, sch, eps=eps, constrained=constrained, surrogate=mlp,
                        steps=cfg.steps, iters=cfg.iters, seed=cfg.seed)

    _log("adversarial training (MLP, XGBoost)")
    with T("adv_training"):
        mlp_adv = adversarial_training(mlp, Xtr, ytr, lambda d, X, e: adaptive(
            d, X, schema, eps=e, steps=cfg.steps, iters=max(cfg.iters // 2, 5), seed=cfg.seed),
            eps=cfg.adv_eps, rounds=cfg.adv_rounds, n_adv=cfg.adv_n, seed=cfg.seed)
        xgb_adv = adversarial_training(xgb, Xtr, ytr, lambda d, X, e: adaptive(
            d, X, schema, eps=e, surrogate=mlp_adv, steps=cfg.steps, iters=max(cfg.iters // 2, 5),
            seed=cfg.seed), eps=cfg.adv_eps, rounds=cfg.adv_rounds, n_adv=cfg.adv_n, seed=cfg.seed)
        ens_adv = EnsembleDetector([xgb_adv, mlp_adv], ae)
    with T("robust_features"):
        rcols = robust_feature_indices(schema)
        xgb_rob = XGBDetector(seed=cfg.seed, n_estimators=cfg.xgb_trees,
                              max_depth=4 if cfg.fast else 8, cols=rcols)
        xgb_rob.pre = pre
        xgb_rob.fit_z(pre.transform(Xtr), ytr)
    models.update({"mlp_adv_trained": mlp_adv, "xgboost_adv_trained": xgb_adv,
                   "ensemble_adv_trained": ens_adv, "xgboost_robust_features": xgb_rob})

    def atk_hard(det: BaseDetector, X: np.ndarray, eps: float, constrained: bool = True) -> np.ndarray:
        return adaptive(det, X, schema, eps=eps, constrained=constrained, surrogate=[mlp, mlp_adv],
                        steps=cfg.steps, iters=cfg.iters, seed=cfg.seed)

    # ------------------------------------------------------------------ 3. clean metrics
    for name, m in models.items():
        report["models"][name] = detection_metrics(m, Xte, yte)

    # ------------------------------------------------------------------ 4. robustness curves
    mal_idx = np.flatnonzero(yte == 1)
    ev = rng.choice(mal_idx, size=min(cfg.max_eval, len(mal_idx)), replace=False)
    X_mal, fam_mal = Xte[ev], (te.attack[ev] if te.attack is not None else None)
    report["n_eval_attacks"] = int(len(ev))
    curve_models = ["mlp", "xgboost", "ensemble", "mlp_adv_trained", "xgboost_adv_trained",
                    "ensemble_adv_trained", "xgboost_robust_features"]
    if cfg.baselines:
        curve_models.insert(2, "random_forest")
    _log("robustness curves")
    with T("robustness_curves"):
        for name in curve_models:
            m = models[name]
            if name in HARDENED:
                # adaptive: gradients from the undefended AND the hardened MLP (per-flow best);
                # the transfer-from-undefended-MLP curve is kept as an ablation
                r = {"constrained": robustness_curve(m, X_mal, cfg.eps, schema,
                                                     lambda d, X, e: atk_hard(d, X, e)),
                     "constrained_transfer_only": robustness_curve(
                         m, X_mal, cfg.eps, schema, lambda d, X, e: atk(d, X, e, True))}
            else:
                r = {"constrained": robustness_curve(m, X_mal, cfg.eps, schema,
                                                     lambda d, X, e: atk(d, X, e, True))}
            if name in ("mlp", "xgboost", "ensemble"):
                r["unconstrained"] = robustness_curve(m, X_mal, cfg.eps, schema,
                                                      lambda d, X, e: atk(d, X, e, False))
            for k in list(r):
                r[f"{k}_auc"] = area_under_curve(r[k])
            report["robustness"][name] = r
            _log(f"  {name}: constrained detection @eps={cfg.eps[-1]} = "
                 f"{r['constrained'][-1]['detection_rate']:.3f}")

    # per-family breakdown at the largest budget for the baseline XGBoost
    if fam_mal is not None:
        Xa = atk(xgb, X_mal, cfg.eps[-1])
        clean_hit, adv_hit = xgb.predict(X_mal) == 1, xgb.predict(Xa) == 1
        report["per_family"] = {
            str(f): {"n": int((fam_mal == f).sum()),
                     "clean_detection": float(clean_hit[fam_mal == f].mean()),
                     "adv_detection": float(adv_hit[fam_mal == f].mean())}
            for f in np.unique(fam_mal)}

    # which controllable features are inherently (non-)robust? single-feature attacks
    with T("feature_robustness"):
        feat_rob = {}
        for f in schema.controllable:
            sub = restrict(schema, [f])
            Xa = adaptive(xgb, X_mal, sub, eps=cfg.eps[-1], surrogate=mlp, steps=cfg.steps,
                          iters=cfg.iters, seed=cfg.seed)
            feat_rob[f] = float((xgb.predict(Xa) == 1).mean())
        report["single_feature_attack_detection"] = feat_rob

    # ------------------------------------------------------------------ 5. explanations
    _log("SHAP + counterfactuals")
    with T("explain"):
        samp = Xte[rng.choice(len(Xte), size=min(5000, len(Xte)), replace=False)]
        report["shap_global_xgboost"] = global_importance(xgb, samp, ds.feature_names)
        flagged = X_mal[xgb.predict(X_mal) == 1][: cfg.n_cf]
        cfs, _ = counterfactual(xgb, flagged, schema, surrogate=mlp, eps_max=max(cfg.eps),
                                iters=max(cfg.iters // 2, 10), seed=cfg.seed)
        found = [c for c in cfs if c["found"]]
        from collections import Counter

        cnt = Counter(ch["feature"] for c in found for ch in c["changes"])
        report["counterfactuals"] = {
            "model": "xgboost", "n": len(cfs),
            "found_rate": len(found) / max(len(cfs), 1),
            "valid_rate": float(np.mean([c["valid"] for c in cfs])) if cfs else float("nan"),
            "mean_features_changed": float(np.mean([len(c["changes"]) for c in found])) if found else 0.0,
            "median_eps": float(np.median([c["eps"] for c in found])) if found else None,
            "feature_frequency": dict(cnt.most_common()),
            "examples": [describe_counterfactual(c) for c in cfs[:5]],
        }
        cfs_h, _ = counterfactual(ens_adv, X_mal[ens_adv.predict(X_mal) == 1][: cfg.n_cf], schema,
                                  surrogate=mlp_adv, eps_max=max(cfg.eps), iters=max(cfg.iters // 2, 10),
                                  seed=cfg.seed)
        report["counterfactuals_hardened_ensemble"] = {
            "n": len(cfs_h), "found_rate": float(np.mean([c["found"] for c in cfs_h])) if cfs_h else 0.0}

    # ------------------------------------------------------------------ 6. adversarial-input detector
    _log("adversarial-input detector")
    with T("adv_input_detector"):
        tr_mal = Xtr[ytr == 1]
        pick = rng.choice(len(tr_mal), size=min(cfg.adv_n, len(tr_mal)), replace=False)
        Xs = tr_mal[pick]
        parts = np.array_split(np.arange(len(Xs)), 3)
        X_adv_tr = np.vstack([atk(xgb, Xs[p], e) for p, e in zip(parts, [0.5, 1.0, 2.0])])
        evaded = xgb.predict(X_adv_tr) == 0
        nb = int((ytr == 0).sum())
        ben_tr = Xtr[ytr == 0][rng.choice(nb, size=min(len(Xs), nb), replace=False)]
        aid = AdversarialInputDetector(xgb, cfg.seed).fit(np.vstack([ben_tr, Xs]), X_adv_tr[evaded])
        ben_te = Xte[yte == 0][rng.choice(int((yte == 0).sum()), size=min(len(X_mal), int((yte == 0).sum())),
                                          replace=False)]
        res = {"train_adv": int(evaded.sum())}
        for e in (1.0, 1.5):
            Xa = atk(xgb, X_mal, e)
            ev_ = xgb.predict(Xa) == 0
            if ev_.any():
                res[f"eps_{e}"] = aid.evaluate(np.vstack([ben_te, X_mal]), Xa[ev_])
                res[f"eps_{e}"]["n_evasions"] = int(ev_.sum())
        # adaptive attacker who knows about the adversarial-input detector too
        g = aid.guarded()
        Xg = adaptive(g, X_mal, schema, eps=cfg.eps[-1], surrogate=mlp, steps=cfg.steps,
                      iters=cfg.iters, seed=cfg.seed)
        res["adaptive_vs_guarded"] = {
            "eps": float(cfg.eps[-1]),
            "detection_rate": float((g.predict(Xg) == 1).mean()),
            "evade_target_only": float((xgb.predict(Xg) == 0).mean()),
            "guarded_fpr_benign": float((g.predict(ben_te) == 1).mean()),
        }
        report["adversarial_input_detector"] = res

    # ------------------------------------------------------------------ 7. poisoning
    _log("poisoning / backdoor study")
    with T("poisoning"):
        ntr = min(cfg.poison_max_train, len(ytr))
        pi = rng.choice(len(ytr), size=ntr, replace=False)

        def factory(X: np.ndarray, y: np.ndarray) -> BaseDetector:
            d = XGBDetector(seed=cfg.seed, n_estimators=cfg.xgb_trees, max_depth=4 if cfg.fast else 8)
            return d.fit(X, y, pre=pre)

        report["poisoning"] = backdoor_study(factory, Xtr[pi], ytr[pi], Xte, yte, schema,
                                             rate=cfg.poison_rate, seed=cfg.seed, robust_cols=rcols)

    # ------------------------------------------------------------------ 8. drift / zero-day
    if cfg.drift and ds.info.get("name") == "cicids2017" and ds.group is not None:
        _log("temporal drift study (train Mon-Wed, test Thu-Fri)")
        with T("drift"):
            report["drift"] = drift_study(ds, cfg)

    if return_models:
        return report, models
    return report


def drift_study(ds: Dataset, cfg: StudyConfig) -> dict:
    """Train on Monday-Wednesday captures, test on Thursday-Friday (unseen attack families)."""
    tr, te = ds.subset(ds.group <= 2), ds.subset(ds.group >= 3)
    pre = Preprocessor().fit(tr.X)
    mlp, xgb, ae = train_members(tr.X, tr.y, cfg, pre)
    ens = EnsembleDetector([xgb, mlp], ae)
    out = {"train_days": CIC_DAYS[:3], "test_days": CIC_DAYS[3:],
           "train_families": sorted(set(tr.attack[tr.y == 1].tolist())), "families": {}}
    preds = {n: m.predict(te.X) for n, m in [("xgboost", xgb), ("autoencoder", ae), ("ensemble", ens)]}
    ben = te.y == 0
    out["benign_fpr"] = {n: float(p[ben].mean()) for n, p in preds.items()}
    for fam in sorted(set(te.attack[te.y == 1].tolist())):
        m = te.attack == fam
        out["families"][fam] = {"n": int(m.sum()), **{n: float(p[m].mean()) for n, p in preds.items()}}
    out["overall"] = {n: detection_metrics_from_pred(p, te.y) for n, p in preds.items()}
    return out


def detection_metrics_from_pred(p: np.ndarray, y: np.ndarray) -> dict:
    """Recall, precision and FPR from hard predictions ``p`` and labels ``y``."""
    tp = int(((p == 1) & (y == 1)).sum())
    fp = int(((p == 1) & (y == 0)).sum())
    fn = int(((p == 0) & (y == 1)).sum())
    return {"recall": tp / max(tp + fn, 1), "precision": tp / max(tp + fp, 1),
            "fpr": fp / max(int((y == 0).sum()), 1)}


# ---------------------------------------------------------------------------- persistence
def environment() -> dict:
    """Versions and commit that produced a result file (written into every JSON)."""
    import platform
    import subprocess

    import pandas
    import sklearn
    import xgboost

    from . import __version__
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                                timeout=5).stdout.strip() or None
    except Exception:  # noqa: BLE001 - not a git checkout
        commit = None
    return {"feint": __version__, "python": platform.python_version(), "platform": platform.platform(),
            "numpy": np.__version__, "pandas": pandas.__version__, "scikit-learn": sklearn.__version__,
            "xgboost": xgboost.__version__, "git_commit": commit}


def save(report: dict, out_dir: str | Path, figures: bool = True) -> Path:
    """Write ``report.json``, ``report.md`` and (optionally) the figures into ``out_dir``."""
    from .report import to_markdown, write_figures

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    report.setdefault("environment", environment())
    (out / "report.json").write_text(json.dumps(report, indent=2, default=float))
    (out / "report.md").write_text(to_markdown(report), encoding="utf-8")
    if figures:
        write_figures(report, out)
    return out
