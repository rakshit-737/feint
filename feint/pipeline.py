"""End-to-end study: train -> red-team -> harden -> re-evaluate -> report."""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
from sklearn.model_selection import train_test_split

from .attack import pgd
from .data import Dataset, synthetic_flows
from .harden import adversarial_training
from .metrics import detection_metrics, precision_at_base_rate, robustness_curve
from .model import AnomalyMember, Detector

DEFAULT_EPS = [0.0, 0.25, 0.5, 1.0, 1.5, 2.0]


def run_study(ds: Dataset | None = None, eps_list=None, seed=0, adv_eps=2.0,
              adv_rounds=3, steps=20, max_eval=600):
    ds = ds or synthetic_flows(seed=seed)
    eps_list = eps_list or DEFAULT_EPS
    Xtr, Xte, ytr, yte = train_test_split(ds.X, ds.y, test_size=0.3, random_state=seed, stratify=ds.y)

    base = Detector(seed=seed).fit(Xtr, ytr)
    hard = adversarial_training(base, Xtr, ytr, eps=adv_eps, rounds=adv_rounds, seed=seed)
    iso = AnomalyMember(seed=seed).fit(base.pre.transform(Xtr[ytr == 0]))

    X_mal = Xte[yte == 1][:max_eval]
    report = {"n_train": int(len(ytr)), "n_test": int(len(yte)), "features": ds.feature_names,
              "models": {}}
    for name, det in [("baseline", base), ("adv_trained", hard)]:
        m = detection_metrics(det, Xte, yte)
        m["precision_at_0.1pct_prevalence"] = precision_at_base_rate(m["recall"], m["fpr"], 0.001)
        report["models"][name] = {
            "clean": m,
            "constrained": robustness_curve(det, X_mal, eps_list, constrained=True, steps=steps),
            "unconstrained": robustness_curve(det, X_mal, eps_list, constrained=False, steps=steps),
        }

    # Does the unsupervised member catch constrained evasions the baseline missed?
    Xa = pgd(base, X_mal, np.ones(len(X_mal)), eps=max(eps_list), steps=steps, constrained=True)
    evaded = base.predict(Xa) == 0
    caught = iso.is_anomalous(base.pre.transform(Xa[evaded])) if evaded.any() else np.array([])
    report["ensemble_backstop"] = {
        "eps": float(max(eps_list)),
        "evaded_baseline": int(evaded.sum()),
        "caught_by_isolation_forest": int(caught.sum()),
        "iforest_fpr_on_benign_test": float(iso.is_anomalous(base.pre.transform(Xte[yte == 0])).mean()),
    }
    return report


def to_markdown(report) -> str:
    lines = ["# FEINT robustness report", ""]
    lines += ["## Clean detection (held-out test set)", "",
              "| model | acc | prec | recall | F1 | AUC | FPR | precision @0.1% prevalence |",
              "|---|---|---|---|---|---|---|---|"]
    for name, r in report["models"].items():
        c = r["clean"]
        lines.append(f"| {name} | {c['accuracy']:.3f} | {c['precision']:.3f} | {c['recall']:.3f} | "
                     f"{c['f1']:.3f} | {c['auc']:.3f} | {c['fpr']:.4f} | {c['precision_at_0.1pct_prevalence']:.3f} |")
    for kind in ["constrained", "unconstrained"]:
        lines += ["", f"## Robustness curve: {kind} PGD (detection rate on attack flows)", "",
                  "| eps | baseline detect | baseline ASR | hardened detect | hardened ASR | valid flows (baseline atk) |",
                  "|---|---|---|---|---|---|"]
        b, h = report["models"]["baseline"][kind], report["models"]["adv_trained"][kind]
        for rb, rh in zip(b, h):
            lines.append(f"| {rb['eps']:.2f} | {rb['detection_rate']:.3f} | {rb['attack_success_rate']:.3f} | "
                         f"{rh['detection_rate']:.3f} | {rh['attack_success_rate']:.3f} | {rb['valid_rate']:.3f} |")
    e = report["ensemble_backstop"]
    lines += ["", "## Ensemble backstop", "",
              f"At eps={e['eps']}, {e['evaded_baseline']} constrained evasions beat the baseline MLP; "
              f"IsolationForest flagged {e['caught_by_isolation_forest']} of them "
              f"(IForest FPR on benign test = {e['iforest_fpr_on_benign_test']:.3f}).", ""]
    return "\n".join(lines)


def save(report, out_dir: str | Path):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(json.dumps(report, indent=2))
    (out / "report.md").write_text(to_markdown(report))
    return out
