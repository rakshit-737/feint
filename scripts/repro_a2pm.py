"""Reproduce Vitorino, Oliveira & Praca 2022 (A2PM, Future Internet 14(4):108), Enterprise scenario.

Setup taken from the paper (Sections 4.1-4.4):

* CIC-IDS2017 Tuesday + Wednesday captures, 8 classes, stratified 70/30 holdout split;
* A2PM base configuration: Interval pattern on the numerical features (integer perturbations on
  discrete ones, ratio in [0.1, 0.3], probability 0.6); Combination pattern on the categorical
  features with port and protocol locked (probability 0.4); no perturbation of the Benign class;
* RF: 100 trees, gini, max depth 32, min samples per leaf 2, sqrt features, balanced class weights;
* MLP: hidden layers 64 and 32 (ReLU), Adam, learning rate 1e-3, batch 512, at most 50 epochs with
  early stopping on a 20 % validation split;
* adversarial training: one A2PM example per malicious training flow, A2PM fitted on training data;
* attacks: A2PM fitted on the evaluation set, at most 50 iterations with early stopping, targeted
  (towards Benign) and untargeted;
* metrics: accuracy on the malicious evaluation flows only, macro-F1 over all evaluation flows.

Deviations we cannot avoid (recorded in the output):

* we use the MachineLearningCVE CSVs (78 numerical features, destination port only), not the 83-
  feature version with one-hot categorical features the authors built; the Combination pattern
  therefore runs on the binary TCP-flag features with the destination port locked;
* scikit-learn's MLPClassifier replaces the Keras MLP: no dropout, no class weights, no Bayesian
  tuning (the paper reports the tuned architecture, which we copy);
* rows with NaN / inf are dropped.

Usage:  python scripts/repro_a2pm.py [--data-dir DIR] [--out results/repro] [--iterations 50]
Needs Python <= 3.12 and numpy < 2 (a2pm 1.2.0 pins numpy < 2).
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import time
from pathlib import Path

import numpy as np
import pandas as pd

# Read from the figures and text of Section 4.5 (values from figures are approximate).
PAPER = {
    "clean_accuracy_malicious": "> 0.99 for both MLP and RF (regular training)",
    "targeted_after_1_iteration": "accuracy drops by about 15 points (MLP) and 33 points (RF)",
    "targeted_after_50_iterations": "very low for regular training; RF with adversarial training keeps 0.9991",
    "untargeted_regular": "accuracy declines by about 99 % and macro-F1 by about 79 % (MLP and RF)",
    "untargeted_adv_trained": "considerably higher; gradual decrease of < 2 % per iteration",
    "n_samples": 1_138_612,
}
DAYS = ("Tuesday-WorkingHours.pcap_ISCX.csv", "Wednesday-workingHours.pcap_ISCX.csv")


def load(root: Path):
    frames = []
    for name in DAYS:
        f = next(root.rglob(name), None)
        if f is None:
            raise FileNotFoundError(f"{name} not found under {root}")
        df = pd.read_csv(f, encoding="latin-1", low_memory=False)
        df.columns = [c.strip() for c in df.columns]
        frames.append(df)
    df = pd.concat(frames, ignore_index=True)
    n_raw = len(df)
    y = df.pop("Label").astype(str).str.strip().to_numpy()
    X = df.apply(pd.to_numeric, errors="coerce").to_numpy(dtype=np.float64)
    ok = np.isfinite(X).all(1)
    return X[ok], y[ok], list(df.columns), n_raw


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", type=Path,
                    default=Path(os.environ.get("FEINT_DATA") or "data") / "cicids2017")
    ap.add_argument("--out", type=Path, default=Path("results/repro"))
    ap.add_argument("--iterations", type=int, default=50)
    ap.add_argument("--patience", type=int, default=2)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--max-rows", type=int, default=0, help="stratified subsample (0 = all; smoke tests)")
    a = ap.parse_args()

    import a2pm
    import sklearn
    from a2pm import A2PMethod
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import f1_score
    from sklearn.model_selection import train_test_split
    from sklearn.neural_network import MLPClassifier
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import LabelEncoder, StandardScaler

    t0 = time.time()
    X, labels, cols, n_raw = load(a.data_dir)
    if a.max_rows and len(X) > a.max_rows:
        X, _, labels, _ = train_test_split(X, labels, train_size=a.max_rows, stratify=labels,
                                           random_state=a.seed)
    enc = LabelEncoder().fit(labels)
    y = enc.transform(labels)
    benign = int(enc.transform(["BENIGN"])[0])
    counts = {str(k): int(v) for k, v in zip(*np.unique(labels, return_counts=True))}
    print(f"{len(y)} flows ({n_raw} raw), classes {counts}", flush=True)

    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.3, stratify=y, random_state=a.seed)
    port = cols.index("Destination Port")
    binary = [i for i in range(len(cols)) if i != port and set(np.unique(Xtr[:, i])) <= {0.0, 1.0}]
    numeric = [i for i in range(len(cols)) if i != port and i not in binary]
    integer = [i for i in numeric if np.all(Xtr[:, i] == np.round(Xtr[:, i]))]
    pattern = (
        {"type": "interval", "features": numeric, "integer_features": integer,
         "ratio": 0.1, "max_ratio": 0.3, "probability": 0.6},
        {"type": "combination", "features": binary + [port], "locked_features": [port],
         "probability": 0.4},
    )

    def method(Xf, yf):
        return A2PMethod(pattern=pattern, preassigned_patterns={benign: None}, seed=a.seed).fit(Xf, yf)

    def rf():
        return RandomForestClassifier(n_estimators=100, criterion="gini", max_depth=32, min_samples_leaf=2,
                                      max_features="sqrt", class_weight="balanced", n_jobs=-1,
                                      random_state=a.seed)

    def mlp():
        return make_pipeline(StandardScaler(), MLPClassifier(
            hidden_layer_sizes=(64, 32), activation="relu", solver="adam", learning_rate_init=1e-3,
            batch_size=512, max_iter=50, early_stopping=True, validation_fraction=0.2,
            random_state=a.seed))

    # adversarial training set: one A2PM example per malicious training flow
    mal_tr = ytr != benign
    Xadv_tr = method(Xtr, ytr).transform(Xtr[mal_tr], ytr[mal_tr])
    Xat, yat = np.vstack([Xtr, Xadv_tr]), np.r_[ytr, ytr[mal_tr]]

    mal_te = yte != benign
    attack_method = method(Xte, yte)

    def evaluate(clf, Xe):
        p = clf.predict(Xe)
        return {"accuracy_malicious": float((p[mal_te] == yte[mal_te]).mean()),
                "macro_f1": float(f1_score(yte, p, average="macro"))}

    results = {}
    for name, factory in (("RF", rf), ("MLP", mlp)):
        for training, (Xf, yf) in (("regular", (Xtr, ytr)), ("adversarial", (Xat, yat))):
            t = time.time()
            clf = factory().fit(Xf, yf)
            row = {"clean": evaluate(clf, Xte), "train_seconds": round(time.time() - t, 1)}
            for kind, target in (("targeted", np.full(int(mal_te.sum()), benign)), ("untargeted", None)):
                for iters, pat in (("1", 0), (str(a.iterations), a.patience)):
                    Xa = Xte.copy()
                    Xa[mal_te] = attack_method.generate(clf, Xte[mal_te], yte[mal_te], y_target=target,
                                                        iterations=int(iters), patience=pat)
                    row[f"{kind}_{iters}it"] = evaluate(clf, Xa)
            results[f"{name}_{training}"] = row
            print(name, training, json.dumps(row), flush=True)

    r = {
        "paper": "Vitorino, Oliveira & Praca 2022, Adaptative Perturbation Patterns: Realistic "
                 "Adversarial Learning for Robust Intrusion Detection, Future Internet 14(4):108, "
                 "doi:10.3390/fi14040108 (arXiv:2203.04234)",
        "paper_results": PAPER,
        "n_flows": int(len(y)), "n_raw": int(n_raw), "class_counts": counts,
        "n_features": len(cols), "n_numeric": len(numeric), "n_integer": len(integer),
        "n_binary": len(binary),
        "assumptions": [
            "MachineLearningCVE Tuesday + Wednesday CSVs (78 numerical features), rows with NaN/inf dropped",
            "Combination pattern on the binary TCP-flag features with Destination Port locked "
            "(the paper one-hot encoded categorical features and locked port and protocol)",
            "scikit-learn MLPClassifier (64, 32), no dropout and no class weights (paper: Keras, dropout 0.1, "
            "balanced class weights)",
            f"A2PM generate: iterations 1 and {a.iterations}, early-stopping patience {a.patience}",
            f"stratified 70/30 split, seed {a.seed}"
            + (f", stratified subsample of {a.max_rows}" if a.max_rows else ""),
        ],
        "results": results,
        "environment": {"python": platform.python_version(), "a2pm": getattr(a2pm, "__version__", "1.2.0"),
                        "numpy": np.__version__, "sklearn": sklearn.__version__},
        "seconds": round(time.time() - t0, 1),
    }
    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "vitorino2022.json").write_text(json.dumps(r, indent=2))
    (a.out / "vitorino2022.md").write_text(to_markdown(r), encoding="utf-8")
    print(to_markdown(r))
    return 0


def to_markdown(r: dict) -> str:
    L = ["# Reproduction: Vitorino, Oliveira & Praca 2022 (A2PM), CIC-IDS2017 Enterprise scenario", "",
         f"{r['n_flows']} flows; classes {r['class_counts']}. Paper: {r['paper_results']['n_samples']} flows.", "",
         "Assumptions / deviations:", ""] + [f"- {x}" for x in r["assumptions"]] + [
        "", "Accuracy is on the malicious evaluation flows only (the paper's definition); macro-F1 over all "
        "evaluation flows. Attacks are A2PM fitted on the evaluation set.", "",
        "| model | clean acc / F1 | targeted, 1 it | targeted, max it | untargeted, 1 it | untargeted, max it |",
        "|---|---|---|---|---|---|"]
    for name, row in r["results"].items():
        keys = [k for k in row if k not in ("train_seconds",)]
        cells = [f"{row[k]['accuracy_malicious']:.4f} / {row[k]['macro_f1']:.4f}" for k in keys]
        L.append(f"| {name} | " + " | ".join(cells) + " |")
    L += ["", "Paper (Section 4.5, partly read from figures):", ""] + [
        f"- {k}: {v}" for k, v in r["paper_results"].items() if k != "n_samples"]
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
