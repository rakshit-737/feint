"""Reproductions of published results under (as close as possible to) the papers' own setups.

Each function returns a dict with the paper's number, our reproduction and every assumption we had
to make because the paper does not state it. Nothing here touches the FEINT feature schema: the
point is to check that our data and tooling reproduce the literature before FEINT departs from it.

* Sharafaldin, Habibi Lashkari & Ghorbani, ICISSP 2018 (CIC-IDS2017), Table 4: seven classifiers on
  the per-attack features selected in Table 3 (union), weighted multi-class P / R / F1.
* Moustafa & Slay 2016 (UNSW-NB15): classic classifiers on the official training / testing partition
  with the published feature columns, accuracy and false-alarm rate.
"""
from __future__ import annotations

import json
import time
from collections.abc import Iterable, Sequence
from pathlib import Path

import numpy as np

from .data import data_root

# Table 3 of Sharafaldin et al. 2018 (best 4 features per label, RandomForestRegressor), mapped to
# MachineLearningCVE header names. "B.Packet Len Std" listed twice for DoS Hulk is kept once.
SHARAFALDIN_T3 = [
    "Bwd Packet Length Min", "Subflow Fwd Bytes", "Total Length of Fwd Packets", "Fwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow IAT Min", "Fwd IAT Min", "Flow IAT Mean", "Flow Duration",
    "Flow IAT Std", "Active Min", "Active Mean", "Bwd IAT Mean", "Fwd IAT Mean", "Init_Win_bytes_forward",
    "ACK Flag Count", "Fwd PSH Flags", "SYN Flag Count", "Fwd Packets/s", "Init_Win_bytes_backward",
    "Bwd Packets/s", "PSH Flag Count", "Average Packet Size",
]
SHARAFALDIN_T4 = {  # weighted Pr, Rc, F1 and execution time (s), verbatim from Table 4
    "KNN": (0.96, 0.96, 0.96, 1908.23), "RF": (0.98, 0.97, 0.97, 74.39), "ID3": (0.98, 0.98, 0.98, 235.02),
    "Adaboost": (0.77, 0.84, 0.77, 1126.24), "MLP": (0.77, 0.83, 0.76, 575.73),
    "Naive-Bayes": (0.88, 0.04, 0.04, 14.77), "QDA": (0.97, 0.88, 0.92, 18.79),
}


def _classifiers(seed: int) -> dict:
    from sklearn.discriminant_analysis import QuadraticDiscriminantAnalysis
    from sklearn.ensemble import AdaBoostClassifier, RandomForestClassifier
    from sklearn.naive_bayes import GaussianNB
    from sklearn.neighbors import KNeighborsClassifier
    from sklearn.neural_network import MLPClassifier
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler
    from sklearn.tree import DecisionTreeClassifier

    return {
        "KNN": make_pipeline(StandardScaler(), KNeighborsClassifier(n_jobs=-1)),
        "RF": RandomForestClassifier(random_state=seed, n_jobs=-1),
        "ID3": DecisionTreeClassifier(criterion="entropy", random_state=seed),
        "Adaboost": AdaBoostClassifier(random_state=seed),
        "MLP": make_pipeline(StandardScaler(), MLPClassifier(random_state=seed, max_iter=200)),
        "Naive-Bayes": GaussianNB(),
        "QDA": QuadraticDiscriminantAnalysis(reg_param=0.0),
        # deviation from the defaults, reported next to the failed default fit: a small covariance
        # regulariser, as scikit-learn's error message suggests for rank-deficient classes
        "QDA (reg_param=1e-3)": QuadraticDiscriminantAnalysis(reg_param=1e-3),
    }


# header spellings of the corrected re-release (Engelen et al. 2021) that differ by more than case,
# punctuation or a trailing plural 's'
_CORRECTED_ALIASES = {"Init_Win_bytes_forward": "FWD Init Win Bytes",
                      "Init_Win_bytes_backward": "Bwd Init Win Bytes"}


def _resolve_columns(header: Sequence[str], wanted: Iterable[str]) -> dict:
    """Map each wanted MachineLearningCVE name to a header column of another CICFlowMeter release."""
    from .data import _key

    def k(c: str) -> str:
        return _key(c).rstrip("s")

    by_key = {}
    for h in header:
        by_key.setdefault(k(h), h)
    out, missing = {}, []
    for w in wanted:
        h = by_key.get(k(w)) or by_key.get(k(_CORRECTED_ALIASES.get(w, w)))
        if h is None:
            missing.append(w)
        else:
            out[h] = w
    if missing:
        raise KeyError(f"columns not found in the corrected CSVs: {missing}; header: {list(header)}")
    return out


def sharafaldin2018(root: str | Path | None = None, seed: int = 0, knn_max_train: int = 300_000,
                    models: Sequence[str] | None = None, corrected: bool = False) -> dict:
    """Multi-class reproduction of Table 4 (duplicates kept).

    ``corrected=False`` uses the original MachineLearningCVE CSVs; ``corrected=True`` the corrected
    re-release of Engelen et al. 2021, with '- Attempted' flows relabelled benign.
    """
    import warnings

    import pandas as pd
    from sklearn.metrics import precision_recall_fscore_support
    from sklearn.model_selection import train_test_split

    from .data import CIC_DAYS, _norm_family

    if corrected:
        root = Path(root) if root else data_root() / "cicids2017-corrected"
        files = sorted(p for p in root.glob("*.csv") if p.stem.lower() in {d.lower() for d in CIC_DAYS})
    else:
        root = Path(root) if root else data_root() / "cicids2017"
        files = sorted(root.rglob("*pcap_ISCX.csv"))
    if not files:
        raise FileNotFoundError(f"no CIC-IDS2017 CSVs under {root}")
    frames = []
    for f in files:
        head = pd.read_csv(f, nrows=0, encoding="latin-1").columns
        cmap = _resolve_columns(head, SHARAFALDIN_T3 + ["Label"])
        df = pd.read_csv(f, usecols=list(cmap), encoding="latin-1", low_memory=False).rename(columns=cmap)
        frames.append(df[SHARAFALDIN_T3 + ["Label"]])
    df = pd.concat(frames, ignore_index=True)
    n_raw = len(df)
    X = df[SHARAFALDIN_T3].apply(pd.to_numeric, errors="coerce").to_numpy(dtype=np.float64)
    ok = np.isfinite(X).all(1)
    labels = df["Label"].astype(str).str.strip()
    if corrected:
        labels = labels.map(_norm_family)
    X, y = X[ok], labels.to_numpy()[ok]
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.3, random_state=seed, stratify=y)
    out = {"paper": "Sharafaldin, Habibi Lashkari & Ghorbani, ICISSP 2018, Table 4",
           "assumptions": [
               "union of the Table 3 per-label feature selections (23 features)",
               ("corrected CIC-IDS2017 (Engelen et al. 2021), 5 day files, '- Attempted' flows relabelled "
                "benign" if corrected else "all 8 MachineLearningCVE CSVs")
               + ", duplicates kept, rows with inf/NaN dropped",
               "stratified 70/30 split (the paper does not report its split)",
               "scikit-learn defaults; ID3 = DecisionTree(criterion='entropy'); KNN and MLP on standardised"
               " features (not stated in the paper)",
               f"KNN trained on a stratified subsample of at most {knn_max_train} flows (runtime)",
               f"weighted multi-class precision / recall / F1 over the {len(set(y))} labels",
               "'QDA (reg_param=1e-3)' deviates from the defaults (covariance regulariser); the default"
               " fit is reported as well"],
           "corrected": bool(corrected),
           "rows_raw": int(n_raw), "rows_used": int(len(y)), "n_test": int(len(yte)), "results": {}}
    for name, clf in _classifiers(seed).items():
        if models and name not in models:
            continue
        Xf, yf = Xtr, ytr
        if name == "KNN" and len(ytr) > knn_max_train:
            Xf, _, yf, _ = train_test_split(Xtr, ytr, train_size=knn_max_train, random_state=seed, stratify=ytr)
        note = None
        if name.startswith("QDA ("):
            # QDA needs more training rows than features in every class: drop the classes that
            # have fewer (e.g. Heartbleed) from training only; they still count, as errors, in test
            labs, cnt = np.unique(yf, return_counts=True)
            keep = np.isin(yf, labs[cnt > Xf.shape[1]])
            dropped = sorted(map(str, labs[cnt <= Xf.shape[1]]))
            Xf, yf = Xf[keep], yf[keep]
            note = f"deviation: reg_param=1e-3; classes dropped from training: {dropped}"
        t = time.time()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            try:
                clf.fit(Xf, yf)
            except (np.linalg.LinAlgError, ValueError) as e:
                # e.g. QDA: rank-deficient class covariances, and classes (Heartbleed, 8 training
                # flows) with fewer samples than features. Record the failure instead of losing the
                # other classifiers' results.
                out["results"][name] = {"paper": dict(zip(("pr", "rc", "f1", "time_s"),
                                                          SHARAFALDIN_T4[name.split(" ")[0]])),
                                        "ours": None, "note": f"failed to fit: {str(e)[:200]}"}
                continue
            p = clf.predict(Xte)
        pr, rc, f1, _ = precision_recall_fscore_support(yte, p, average="weighted", zero_division=0)
        paper = SHARAFALDIN_T4[name.split(" ")[0]]
        out["results"][name] = {"paper": {"pr": paper[0], "rc": paper[1], "f1": paper[2], "time_s": paper[3]},
                                "ours": {"pr": float(pr), "rc": float(rc), "f1": float(f1),
                                         "time_s": round(time.time() - t, 1)}}
        if note:
            out["results"][name]["note"] = note
    return out


def moustafa_slay2016(root: str | Path | None = None, seed: int = 0) -> dict:
    """Classic classifiers on the official UNSW-NB15 partition (binary label), all published columns."""
    import warnings

    import pandas as pd
    from sklearn.linear_model import LogisticRegression
    from sklearn.naive_bayes import GaussianNB
    from sklearn.neural_network import MLPClassifier
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler
    from sklearn.tree import DecisionTreeClassifier

    root = Path(root) if root else data_root() / "unsw-nb15"
    tr = pd.read_csv(root / "UNSW_NB15_training-set.csv")
    te = pd.read_csv(root / "UNSW_NB15_testing-set.csv")
    drop = ["id", "attack_cat", "label"]
    both = pd.get_dummies(pd.concat([tr.drop(columns=drop), te.drop(columns=drop)]),
                          columns=["proto", "service", "state"], dtype=float)
    Xtr, Xte = both.iloc[:len(tr)].to_numpy(float), both.iloc[len(tr):].to_numpy(float)
    ytr, yte = tr["label"].to_numpy(), te["label"].to_numpy()
    clfs = {"DT": DecisionTreeClassifier(random_state=seed),
            "LR": make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000)),
            "NB": GaussianNB(),
            "ANN": make_pipeline(StandardScaler(), MLPClassifier(random_state=seed, max_iter=200))}
    out = {"paper": "Moustafa & Slay 2016, Inf. Secur. J. 25(1-3); DT accuracy 85.56 %, FAR 15.78 % "
                    "(unverified: paper paywalled, no open copy or open secondary source found)",
           "paper_dt": {"accuracy": 0.8556, "far": 0.1578},
           "assumptions": ["official training (175,341) / testing (82,332) partition, binary label",
                           "all 42 published feature columns; proto / service / state one-hot",
                           "scikit-learn defaults (the paper used other tooling)"],
           "results": {}}
    for name, clf in clfs.items():
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            p = clf.fit(Xtr, ytr).predict(Xte)
        fp = int(((p == 1) & (yte == 0)).sum())
        out["results"][name] = {"accuracy": float((p == yte).mean()),
                                "far": fp / max(int((yte == 0).sum()), 1)}
    return out


def to_markdown(r: dict) -> str:
    """Markdown table of a reproduction: the paper's numbers, ours and the assumptions."""
    L = [f"# Reproduction: {r['paper']}", "", "Assumptions:", ""] + [f"- {a}" for a in r["assumptions"]] + [""]
    if "paper_dt" in r:
        L += ["| model | accuracy | FAR |", "|---|---|---|",
              f"| DT (paper) | {r['paper_dt']['accuracy']:.4f} | {r['paper_dt']['far']:.4f} |"]
        L += [f"| {k} (ours) | {v['accuracy']:.4f} | {v['far']:.4f} |" for k, v in r["results"].items()]
    else:
        L += ["| model | paper Pr / Rc / F1 | ours Pr / Rc / F1 | ours time (s) |", "|---|---|---|---|"]
        for k, v in r["results"].items():
            p, o = v["paper"], v["ours"]
            ours = (f"{o['pr']:.3f} / {o['rc']:.3f} / {o['f1']:.3f} | {o['time_s']}" if o
                    else f"{v.get('note', 'failed')} | -")
            L.append(f"| {k} | {p['pr']:.2f} / {p['rc']:.2f} / {p['f1']:.2f} | {ours} |")
    return "\n".join(L) + "\n"


def save(r: dict, out_dir: str | Path, name: str) -> Path:
    """Write ``<name>.json`` (with the environment) and ``<name>.md`` into ``out_dir``."""
    from .pipeline import environment

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    r = {**r, "environment": environment()}
    (out / f"{name}.json").write_text(json.dumps(r, indent=2))
    (out / f"{name}.md").write_text(to_markdown(r), encoding="utf-8")
    return out
