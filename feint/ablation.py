"""Ablations that isolate what the attacker-capability schema contributes to two defences.

For every seed, each comparison is paired: the two arms share the split, the preprocessor, the
undefended model, the poison set and the evaluation attack, and differ only in whether the
schema is used.

* **Sanitiser**: kNN label-consistency computed in robust-feature space (FEINT) vs in the full
  feature space (the schema-agnostic kNN defence of Paudice et al. 2018). Both are applied to the
  same poisoned training set; the outcome is backdoor success after retraining on the kept data.
* **Adversarial training**: the MLP hardened with constrained (schema-projected, realisable)
  evasions vs with textbook unconstrained evasions at the same L-inf budget, both evaluated by the
  *constrained* adaptive attack, which is the threat model FEINT claims to defend against.

The report gives each arm's mean and 95 % CI over seeds and the paired difference (schema minus
schema-agnostic) with a Student-t CI over the per-seed differences.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from .attack import adaptive
from .data import Dataset
from .harden import adversarial_training, robust_feature_indices
from .metrics import detection_metrics, robustness_curve
from .model import Preprocessor, XGBDetector
from .pipeline import StudyConfig, _log, environment, split, train_members
from .poison import backdoor_study
from .seeds import mean_ci


def _one_seed(ds: Dataset, c: StudyConfig) -> dict:
    tr, te, split_desc = split(ds, c.seed)
    pre = Preprocessor().fit(tr.X)
    mlp, _, _ = train_members(tr.X, tr.y, c, pre)
    schema = ds.schema
    out: dict = {"split": split_desc}

    def at(constrained: bool):
        return adversarial_training(
            mlp, tr.X, tr.y,
            lambda d, X, e: adaptive(d, X, schema, eps=e, constrained=constrained, steps=c.steps,
                                     iters=max(c.iters // 2, 5), seed=c.seed),
            eps=c.adv_eps, rounds=c.adv_rounds, n_adv=c.adv_n, seed=c.seed)

    rng = np.random.default_rng(c.seed)
    mal = np.flatnonzero(te.y == 1)
    X_mal = te.X[rng.choice(mal, size=min(c.max_eval, len(mal)), replace=False)]

    def atk(d, X, e):
        return adaptive(d, X, schema, eps=e, steps=c.steps, iters=c.iters, seed=c.seed)

    out["adversarial_training"] = {}
    for tag, constrained in (("constrained_at", True), ("unconstrained_at", False)):
        m = at(constrained)
        clean = detection_metrics(m, te.X, te.y)
        curve = robustness_curve(m, X_mal, c.eps, schema, atk)
        out["adversarial_training"][tag] = {
            "f1": clean["f1"], "fpr": clean["fpr"],
            "detection": {str(p["eps"]): p["detection_rate"] for p in curve}}
        _log(f"  {tag}: det@{c.eps[-1]} = {curve[-1]['detection_rate']:.3f}")

    ntr = min(c.poison_max_train, len(tr.y))
    pi = rng.choice(len(tr.y), size=ntr, replace=False)

    def factory(X, y):
        return XGBDetector(seed=c.seed, n_estimators=c.xgb_trees,
                           max_depth=4 if c.fast else 8).fit(X, y, pre=pre)

    out["sanitiser"] = {}
    for tag, cols in (("robust_features", robust_feature_indices(schema)),
                      ("all_features", np.arange(tr.X.shape[1]))):
        r = backdoor_study(factory, tr.X[pi], tr.y[pi], te.X, te.y, schema, rate=c.poison_rate,
                           seed=c.seed, robust_cols=cols)
        out["sanitiser"][tag] = {
            "backdoor_success": r["sanitized_model"]["backdoor_success"],
            "clean_accuracy": r["sanitized_model"]["clean_accuracy"],
            "poisoned_backdoor_success": r["poisoned_model"]["backdoor_success"],
            **{k: r["sanitizer"][k] for k in ("poison_recall", "precision", "clean_benign_removed_frac")}}
        _log(f"  sanitiser {tag}: backdoor success {out['sanitiser'][tag]['backdoor_success']:.3f}")
    return out


def ablation_study(ds: Dataset, seeds=(0, 1, 2), cfg: StudyConfig | None = None) -> dict:
    """Run both paired ablations for every seed and aggregate arms and paired differences."""
    cfg = cfg or StudyConfig()
    per_seed = {}
    for s in seeds:
        _log(f"ablation seed {s}")
        per_seed[str(s)] = _one_seed(ds, StudyConfig(**{**cfg.__dict__, "seed": int(s)}))
    return aggregate({"dataset": ds.info.get("name"), "seeds": [int(s) for s in seeds],
                      "eps": list(cfg.eps), "environment": environment(), "per_seed": per_seed})


def aggregate(r: dict) -> dict:
    """Mean / CI per arm and for the paired difference (schema arm minus schema-agnostic arm)."""
    P = list(r["per_seed"].values())
    eps = [str(float(e)) for e in r["eps"]]
    at = {}
    for tag in ("constrained_at", "unconstrained_at"):
        at[tag] = {"f1": mean_ci([p["adversarial_training"][tag]["f1"] for p in P]),
                   "fpr": mean_ci([p["adversarial_training"][tag]["fpr"] for p in P]),
                   "detection": {e: mean_ci([p["adversarial_training"][tag]["detection"][e] for p in P])
                                 for e in eps}}

    at["paired_difference"] = {
        "detection": {e: mean_ci([p["adversarial_training"]["constrained_at"]["detection"][e]
                                  - p["adversarial_training"]["unconstrained_at"]["detection"][e] for p in P])
                      for e in eps},
        "fpr": mean_ci([p["adversarial_training"]["constrained_at"]["fpr"]
                        - p["adversarial_training"]["unconstrained_at"]["fpr"] for p in P])}
    keys = ("backdoor_success", "clean_accuracy", "poison_recall", "precision", "clean_benign_removed_frac")
    san = {tag: {k: mean_ci([p["sanitiser"][tag][k] for p in P]) for k in keys}
           for tag in ("robust_features", "all_features")}
    san["paired_difference"] = {k: mean_ci([p["sanitiser"]["robust_features"][k]
                                            - p["sanitiser"]["all_features"][k] for p in P]) for k in keys}
    san["poisoned_backdoor_success"] = mean_ci([p["sanitiser"]["robust_features"]["poisoned_backdoor_success"]
                                                for p in P])
    return {**r, "seeds": sorted(int(s) for s in r["per_seed"]),
            "ci_note": "Student-t 95 % CI across seeds; differences are paired per seed",
            "aggregate": {"adversarial_training": at, "sanitiser": san}}


def merge(paths) -> dict:
    """Merge single-seed ``ablation.json`` files (one per CI job)."""
    rs = [json.loads(Path(p).read_text()) for p in paths]
    return aggregate({**rs[0], "per_seed": {k: v for r in rs for k, v in r["per_seed"].items()}})


def _f(ci: dict, signed: bool = False) -> str:
    fmt = "{:+.3f}" if signed else "{:.3f}"
    return f"{fmt.format(ci['mean'])} [{fmt.format(ci['ci95'][0])}, {fmt.format(ci['ci95'][1])}]"


def _fd(ci: dict) -> str:
    # paired differences can be negative: report the unclipped Student-t interval
    m, s, n = ci["mean"], ci["std"], ci["n"]
    from .seeds import _T975
    h = _T975.get(n - 1, 1.96) * s / np.sqrt(n) if n > 1 else 0.0
    return f"{m:+.3f} [{m - h:+.3f}, {m + h:+.3f}]"


def to_markdown(r: dict) -> str:
    """Render the ablation as Markdown tables."""
    a = r["aggregate"]
    eps = [str(float(e)) for e in r["eps"]]
    L = [f"# Schema ablation: {r['dataset']}", "",
         f"Seeds {r['seeds']} (n={len(r['seeds'])}); mean [95 % Student-t CI]. Differences are paired "
         "per seed (schema arm minus schema-agnostic arm).", "",
         "## Adversarial training of the MLP: constrained vs unconstrained examples", "",
         "Both arms are evaluated by the constrained adaptive attack (white-box PGD + black-box search).", "",
         "| arm | clean F1 | FPR | " + " | ".join(f"det eps={e}" for e in eps) + " |",
         "|---|---|---|" + "---|" * len(eps)]
    for tag in ("constrained_at", "unconstrained_at"):
        v = a["adversarial_training"][tag]
        L.append(f"| {tag} | {_f(v['f1'])} | {_f(v['fpr'])} | "
                 + " | ".join(_f(v["detection"][e]) for e in eps) + " |")
    d = a["adversarial_training"]["paired_difference"]
    L.append(f"| difference | | {_fd(d['fpr'])} | " + " | ".join(_fd(d["detection"][e]) for e in eps) + " |")
    s = a["sanitiser"]
    L += ["", "## kNN poison sanitiser: robust-feature space vs all features", "",
          f"Backdoor success of the poisoned, unsanitised model: {_f(s['poisoned_backdoor_success'])}.", "",
          "| arm | backdoor success after sanitising | clean accuracy | poison recall | precision | "
          "clean benign removed |", "|---|---|---|---|---|---|"]
    keys = ("backdoor_success", "clean_accuracy", "poison_recall", "precision", "clean_benign_removed_frac")
    for tag in ("robust_features", "all_features"):
        L.append(f"| {tag} | " + " | ".join(_f(s[tag][k]) for k in keys) + " |")
    L.append("| difference | " + " | ".join(_fd(s["paired_difference"][k]) for k in keys) + " |")
    return "\n".join(L) + "\n"


def save(r: dict, out_dir) -> Path:
    """Write ``ablation.json`` and ``ablation.md`` into ``out_dir``."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "ablation.json").write_text(json.dumps(r, indent=2))
    (out / "ablation.md").write_text(to_markdown(r), encoding="utf-8")
    return out
