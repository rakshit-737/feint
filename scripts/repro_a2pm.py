"""Reproduce Vitorino, Oliveira & Praca 2022 (A2PM, Future Internet 14(4):108), Enterprise scenario.

Setup taken from the paper (Sections 3-4):

* CIC-IDS2017 Tuesday + Wednesday captures, 8 classes, stratified 70/30 holdout split;
* A2PM base configuration: Interval pattern on the numerical features (integer perturbations on the
  discrete ones, ratio in [0.1, 0.3], probability 0.6); Combination pattern on the categorical features
  with port and protocol locked (probability 0.4); the Benign class is never perturbed;
* RF (Table 4): 100 trees, gini, max depth 32, min samples per leaf 2, sqrt features, balanced class weights;
* MLP (Section 4.3, Table 3): Keras, hidden layers 64 and 32 (ReLU, 10 % dropout), softmax output,
  categorical cross-entropy, Adam with learning rate 1e-3, batch 512, at most 50 epochs with early
  stopping on a 20 % validation split, balanced class weights;
* adversarial training: one A2PM example per malicious training flow, A2PM fitted on the training data;
* attacks: A2PM fitted on the evaluation set, 50 iterations, targeted (towards Benign) and untargeted;
* metrics: accuracy on the malicious evaluation flows only, macro-F1 over all evaluation flows.

The paper's numbers are the legends of Figures 5-7 (iteration 0 -> iteration 50) and Section 4.5.

Deviations (all recorded in the output):

* we use the MachineLearningCVE CSVs (78 numerical features, destination port only), not the 83-feature
  version with one-hot categorical features the authors built; the Combination pattern therefore runs on
  the binary TCP-flag features with the destination port locked, and there is no protocol feature;
* rows with NaN / inf are dropped; the MLP sees standardised features (the paper does not say);
* a2pm 1.2.0's pattern transforms loop over every value in Python (about 10 minutes per pass over the
  ~80k malicious evaluation flows, so a 50-iteration attack takes hours). By default we use vectorised
  subclasses that draw the same random quantities in bulk: the same distribution, a different random
  stream. A self-check compares both implementations on a sample of the training data and aborts if
  they disagree; ``--reference-patterns`` runs the library's own transforms instead.

Usage:  python scripts/repro_a2pm.py [--data-dir DIR] [--out results/repro] [--iterations 50]
Needs numpy < 2 (a2pm 1.2.0 pins it) and TensorFlow 2.16 for the default Keras MLP (``--mlp sklearn``
uses scikit-learn's MLPClassifier instead: no dropout, no class weights).
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import time
from importlib.metadata import version
from pathlib import Path

import numpy as np
import pandas as pd

# Legends of Figures 5-7 (value at iteration 0 -> value after 50 iterations) and the text of Section 4.5.
PAPER = {
    "targeted_accuracy": {"RF_regular": [0.9993, 0.0000], "RF_adversarial": [0.9991, 0.9991],
                          "MLP_regular": [0.9998, 0.1038], "MLP_adversarial": [0.9998, 0.9435]},
    "untargeted_accuracy": {"RF_regular": [0.9989, 0.0001], "RF_adversarial": [0.9989, 0.8996],
                            "MLP_regular": [0.9985, 0.0093], "MLP_adversarial": [0.9986, 0.7888]},
    "untargeted_macro_f1": {"RF_regular": [0.9976, 0.2087], "RF_adversarial": [0.9976, 0.5426],
                            "MLP_regular": [0.9691, 0.1833], "MLP_adversarial": [0.9519, 0.5095]},
    "targeted_after_1_iteration": "accuracy lowered by approximately 15 % (MLP) and 33 % (RF), regular training",
    "generation_rate": "10 examples per 1.7 ms (16 GB RAM, 8-core CPU, 6 GB GPU)",
    "class_counts": {"BENIGN": 873_066, "DoS Hulk": 230_124, "DoS GoldenEye": 10_293, "FTP-Patator": 7_926,
                     "SSH-Patator": 5_897, "DoS slowloris": 5_796, "DoS Slowhttptest": 5_499, "Heartbleed": 11},
    "n_samples": 1_138_612,
}
DAYS = ("Tuesday-WorkingHours.pcap_ISCX.csv", "Wednesday-workingHours.pcap_ISCX.csv")
MODELS = ("RF_regular", "RF_adversarial", "MLP_regular", "MLP_adversarial")


def load(root: Path, sample_frac: float = 0.0, seed: int = 0) -> tuple[np.ndarray, np.ndarray, list[str], int]:
    """Read the Tuesday and Wednesday MachineLearningCVE CSVs; drop rows with NaN or inf.

    ``sample_frac`` keeps each row with that probability while reading (local smoke tests only).
    """
    rng = np.random.default_rng(seed)
    frames = []
    for name in DAYS:
        f = next(root.rglob(name), None)
        if f is None:
            raise FileNotFoundError(f"{name} not found under {root}; run scripts/download_cicids2017.py")
        skip = (lambda i: i > 0 and rng.random() > sample_frac) if sample_frac else None
        df = pd.read_csv(f, encoding="latin-1", low_memory=False, skiprows=skip)
        df.columns = [c.strip() for c in df.columns]
        frames.append(df)
    df = pd.concat(frames, ignore_index=True)
    n_raw = len(df)
    y = df.pop("Label").astype(str).str.strip().to_numpy()
    X = df.apply(pd.to_numeric, errors="coerce").to_numpy(dtype=np.float64)
    ok = np.isfinite(X).all(1)
    return X[ok], y[ok], list(df.columns), n_raw


def pattern_classes(reference: bool) -> tuple[type, type]:
    """Return (IntervalPattern, CombinationPattern): a2pm 1.2.0's own or vectorised subclasses.

    The subclasses only replace ``transform``. Per value, the Interval pattern draws "apply?" with the
    pattern's probability, a ratio uniform in [ratio, max_ratio] and a direction coin, steps by
    ratio * (max - min) of the class's fitted interval (up if the value is at or below the minimum, down
    if at or above the maximum), clips to the interval and rounds integer features. Per row, the
    Combination pattern draws "apply?" and then a recorded combination uniformly among those whose
    locked features equal the row's. That is what the library does one Python call at a time.
    """
    from a2pm.patterns import CombinationPattern, IntervalPattern

    if reference:
        return IntervalPattern, CombinationPattern

    class VectorisedIntervalPattern(IntervalPattern):
        def transform(self, X):
            if not hasattr(self, "moving_mins_"):
                raise AttributeError("Pattern has not been fitted.")
            X = np.array(X, copy=True)
            cols = np.arange(X.shape[1]) if self.features is None else self.features
            Xf = X[:, cols]
            lo, hi = self.moving_mins_, self.moving_maxs_
            g = self.generator
            apply = (g.random(Xf.shape) < self.probability) & (lo != hi)
            if self.missing_value is not None:
                apply &= Xf != self.missing_value
            ratio = self.ratio
            if self.max_ratio is not None:
                ratio = (self.max_ratio - self.ratio) * g.random(Xf.shape) + self.ratio
            step = (hi - lo) * ratio
            coin = g.random(Xf.shape)
            up = ((coin >= 0.5) & (Xf < hi)) | ((coin < 0.5) & (Xf <= lo))
            new = np.where(up, np.minimum(Xf + step, hi), np.maximum(Xf - step, lo))
            integer = self._IntervalPattern__integer_idcs
            if integer is not None:
                new[:, integer] = np.round(new[:, integer])
            X[:, cols] = np.where(apply, new, Xf)
            return X

    class VectorisedCombinationPattern(CombinationPattern):
        def transform(self, X):
            if not hasattr(self, "valid_cmbs_"):
                raise AttributeError("Pattern has not been fitted.")
            X = np.array(X, copy=True)
            cols = np.arange(X.shape[1]) if self.features is None else self.features
            Xf = X[:, cols]
            cmbs, g = self.valid_cmbs_, self.generator
            rows = np.flatnonzero(g.random(len(Xf)) < self.probability)
            if len(rows) == 0:
                return X
            locked = self._CombinationPattern__locked_idcs
            if locked is None:
                pick = g.integers(0, len(cmbs), size=len(rows))
            else:
                keys, inv = np.unique(cmbs[:, locked], axis=0, return_inverse=True)
                inv = inv.reshape(-1)
                order = np.argsort(inv, kind="stable")
                counts = np.bincount(inv, minlength=len(keys))
                starts = np.cumsum(counts) - counts
                index = {tuple(k): i for i, k in enumerate(keys.tolist())}
                row_keys, row_inv = np.unique(Xf[rows][:, locked], axis=0, return_inverse=True)
                k = np.array([index.get(tuple(r), -1) for r in row_keys.tolist()], dtype=int)[row_inv.reshape(-1)]
                if (k < 0).any():
                    raise ValueError("a row's locked values match no recorded combination of its class")
                offset = np.minimum((g.random(len(rows)) * counts[k]).astype(int), counts[k] - 1)
                pick = order[starts[k] + offset]
            Xf[rows] = cmbs[pick]
            X[:, cols] = Xf
            return X

    return VectorisedIntervalPattern, VectorisedCombinationPattern


def make_patterns(classes: tuple[type, type], numeric: list[int], integer: list[int], combination: list[int],
                  locked: list[int], seed: int) -> tuple:
    """The Enterprise base configuration of Section 4.2 as a pattern sequence."""
    interval, combo = classes
    return (interval(features=numeric, integer_features=integer, ratio=0.1, max_ratio=0.3, probability=0.6,
                     seed=seed),
            combo(features=combination, locked_features=locked, probability=0.4, seed=seed))


def self_check(Xs: np.ndarray, ys: np.ndarray, benign: int, numeric: list[int], integer: list[int],
               combination: list[int], port: int, seed: int) -> dict:
    """Transform the same sample with the library's and the vectorised patterns and compare them."""
    from a2pm import A2PMethod
    from scipy.stats import ks_2samp

    span = np.ptp(Xs[:, numeric], axis=0)
    span[span == 0] = 1.0
    out: dict = {"rows": int(len(Xs)), "classes": int(len(np.unique(ys)))}
    stats = {}
    for name, reference in (("library", True), ("vectorised", False)):
        pat = make_patterns(pattern_classes(reference), numeric, integer, combination, [port], seed)
        method = A2PMethod(pattern=pat, preassigned_patterns={benign: None}, seed=seed).fit(Xs, ys)
        t = time.perf_counter()
        Xp = method.transform(Xs, ys)
        seconds = time.perf_counter() - t
        valid = {cls: {tuple(c) for c in p[1].valid_cmbs_.tolist()}
                 for cls, p in method.class_mapping_.items() if p is not None}
        combos_valid = all(tuple(row) in valid[cls] for row, cls in zip(Xp[:, combination].tolist(), ys.tolist()))
        stats[name] = {
            "seconds": round(seconds, 3),
            "ms_per_row": round(1000 * seconds / len(Xs), 4),
            "frac_numeric_values_changed": float(np.mean(Xp[:, numeric] != Xs[:, numeric])),
            "frac_rows_combination_changed": float(np.mean((Xp[:, combination] != Xs[:, combination]).any(1))),
            "mean_abs_normalised_step": float(np.mean(np.abs(Xp[:, numeric] - Xs[:, numeric]) / span)),
            "port_unchanged": bool(np.all(Xp[:, port] == Xs[:, port])),
            "integers_integral": bool(np.all(Xp[:, integer] == np.round(Xp[:, integer]))),
            "combinations_recorded_for_class": bool(combos_valid),
        }
        stats[name]["_steps"] = ((Xp[:, numeric] - Xs[:, numeric]) / span).ravel()
    ks = ks_2samp(stats["library"].pop("_steps"), stats["vectorised"].pop("_steps"))
    lib, vec = stats["library"], stats["vectorised"]
    out.update(stats)
    out["ks_statistic_normalised_steps"] = float(ks.statistic)
    out["ks_pvalue_normalised_steps"] = float(ks.pvalue)
    out["speedup"] = round(lib["seconds"] / max(vec["seconds"], 1e-9), 1)
    out["checks"] = {
        "numeric change fraction within 0.01": abs(lib["frac_numeric_values_changed"]
                                                   - vec["frac_numeric_values_changed"]) < 0.01,
        "combination change fraction within 0.06": abs(lib["frac_rows_combination_changed"]
                                                       - vec["frac_rows_combination_changed"]) < 0.06,
        "KS statistic of normalised steps below 0.02": out["ks_statistic_normalised_steps"] < 0.02,
        "port never changed": lib["port_unchanged"] and vec["port_unchanged"],
        "integer features stay integral": lib["integers_integral"] and vec["integers_integral"],
        "every new combination recorded for its class": (lib["combinations_recorded_for_class"]
                                                         and vec["combinations_recorded_for_class"]),
    }
    out["passed"] = all(out["checks"].values())
    return out


def end_to_end_check(clf, method_factory, X_mal: np.ndarray, y_mal: np.ndarray, benign: int, rows: int,
                     seeds: int, iterations: int = 3) -> dict:
    """Targeted A2PM attack on the same model and flows with both pattern implementations, several seeds.

    ``method_factory(reference, seed)`` returns a fitted A2PMethod. Passes when, after every iteration,
    the mean accuracies of the two implementations differ by at most max(0.02, 4 binomial standard
    errors of a difference of two k-seed means over n flows).
    """
    pick = np.random.default_rng(0).permutation(len(X_mal))[:rows]
    Xc, yc = X_mal[pick], y_mal[pick]
    out: dict = {"rows": int(len(Xc)), "seeds": seeds, "iterations": iterations}
    for name, reference in (("library", True), ("vectorised", False)):
        curves = []
        t = time.perf_counter()
        for s in range(seeds):
            curve: list[float] = []
            method_factory(reference, s).generate(
                clf, Xc, yc, y_target=np.full(len(yc), benign), iterations=iterations, patience=0,
                callback=lambda X, out=curve, **_: out.append(float(np.mean(clf.predict(X) == yc))))
            curves.append(curve + [curve[-1]] * (iterations + 1 - len(curve)))
        out[name] = {"accuracy_mean": np.mean(curves, 0).round(4).tolist(),
                     "accuracy_sd": np.std(curves, 0).round(4).tolist(),
                     "seconds": round(time.perf_counter() - t, 1)}
    lib, vec = np.array(out["library"]["accuracy_mean"]), np.array(out["vectorised"]["accuracy_mean"])
    p = (lib + vec) / 2
    tol = np.maximum(0.02, 4 * np.sqrt(p * (1 - p) / len(Xc)) * np.sqrt(2 / seeds))
    out["abs_diff"] = np.abs(lib - vec).round(4).tolist()
    out["tolerance"] = tol.round(4).tolist()
    out["max_abs_diff"] = round(float(np.max(np.abs(lib - vec))), 4)
    out["passed"] = bool(np.all(np.abs(lib - vec) <= tol))
    return out


class KerasMLP:
    """The paper's Enterprise MLP (Section 4.3, Table 3) behind a scikit-learn style fit / predict."""

    def __init__(self, seed: int, epochs: int = 50, patience: int = 5) -> None:
        self.seed, self.epochs, self.patience = seed, epochs, patience

    def fit(self, X: np.ndarray, y: np.ndarray) -> KerasMLP:
        os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")
        import tensorflow as tf
        from sklearn.model_selection import train_test_split
        from sklearn.preprocessing import StandardScaler
        from sklearn.utils.class_weight import compute_class_weight

        tf.keras.utils.set_random_seed(self.seed)
        n_classes = int(y.max()) + 1
        self.scaler = StandardScaler().fit(X)
        Xs = self.scaler.transform(X).astype(np.float32)
        Xa, Xv, ya, yv = train_test_split(Xs, y, test_size=0.2, stratify=y, random_state=self.seed)
        weights = compute_class_weight("balanced", classes=np.arange(n_classes), y=ya)
        self.model = tf.keras.Sequential([
            tf.keras.Input(shape=(X.shape[1],)),
            tf.keras.layers.Dense(64, activation="relu"), tf.keras.layers.Dropout(0.1),
            tf.keras.layers.Dense(32, activation="relu"), tf.keras.layers.Dropout(0.1),
            tf.keras.layers.Dense(n_classes, activation="softmax"),
        ])
        self.model.compile(optimizer=tf.keras.optimizers.Adam(learning_rate=1e-3),
                           loss="sparse_categorical_crossentropy")
        stop = tf.keras.callbacks.EarlyStopping(monitor="val_loss", patience=self.patience,
                                                restore_best_weights=True)
        hist = self.model.fit(Xa, ya, validation_data=(Xv, yv), epochs=self.epochs, batch_size=512,
                              class_weight=dict(enumerate(weights.tolist())), callbacks=[stop], verbose=2)
        self.epochs_run = len(hist.history["loss"])
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        p = self.model.predict(self.scaler.transform(X).astype(np.float32), batch_size=8192, verbose=0)
        return p.argmax(1)


def scores(p_mal: np.ndarray, y_mal: np.ndarray, p_ben: np.ndarray, y_ben: np.ndarray, benign: int) -> dict:
    """Accuracy and detection on the malicious flows, macro-F1 over all evaluation flows."""
    from sklearn.metrics import f1_score

    return {"accuracy": float(np.mean(p_mal == y_mal)),
            "detection": float(np.mean(p_mal != benign)),
            "macro_f1": float(f1_score(np.r_[y_ben, y_mal], np.r_[p_ben, p_mal], average="macro"))}


def attack_curve(method, clf, X_mal: np.ndarray, y_mal: np.ndarray, p_ben: np.ndarray, y_ben: np.ndarray,
                 benign: int, targeted: bool, iterations: int, patience: int) -> dict:
    """Run one A2PM attack and record the scores after every iteration (callback before each one)."""
    curve: list[dict] = []
    ns: list[int] = []

    def record(X, iteration, samples_left, nanoseconds, **_):
        row = scores(clf.predict(X), y_mal, p_ben, y_ben, benign)
        row.update(iteration=int(iteration), samples_left=int(samples_left))
        curve.append(row)
        ns.append(int(nanoseconds))

    target = np.full(len(y_mal), benign) if targeted else None
    t = time.perf_counter()
    method.generate(clf, X_mal, y_mal, y_target=target, iterations=iterations, patience=patience,
                    callback=record)
    run = curve[-1]["iteration"]
    examples = sum(r["samples_left"] for r in curve[:-1])
    full = curve + [dict(curve[-1], iteration=i) for i in range(run + 1, iterations + 1)]
    return {
        "iterations_run": run,
        "examples_generated": int(examples),
        "transform_cpu_seconds": round(sum(ns[1:]) / 1e9, 2),
        "seconds": round(time.perf_counter() - t, 1),
        **{k: [r[k] for r in full] for k in ("accuracy", "detection", "macro_f1", "samples_left")},
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--data-dir", type=Path,
                    default=Path(os.environ.get("FEINT_DATA") or "data") / "cicids2017")
    ap.add_argument("--out", type=Path, default=Path("results/repro"))
    ap.add_argument("--iterations", type=int, default=50)
    ap.add_argument("--patience", type=int, default=0, help="A2PM early-stopping patience (0 = off)")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--mlp", choices=("keras", "sklearn"), default="keras")
    ap.add_argument("--reference-patterns", action="store_true",
                    help="use a2pm's own pattern transforms (slow) instead of the vectorised ones")
    ap.add_argument("--check-rows", type=int, default=400, help="self-check rows per malicious class")
    ap.add_argument("--e2e-rows", type=int, default=4000,
                    help="malicious evaluation flows in the end-to-end library-vs-vectorised check (0 = off)")
    ap.add_argument("--e2e-seeds", type=int, default=4, help="seeds of the end-to-end check")
    ap.add_argument("--sample-frac", type=float, default=0.0,
                    help="keep each CSV row with this probability (local smoke tests only)")
    a = ap.parse_args()

    import sklearn
    from a2pm import A2PMethod
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.neural_network import MLPClassifier
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import LabelEncoder, StandardScaler

    t0 = time.time()
    X, labels, cols, n_raw = load(a.data_dir, a.sample_frac, a.seed)
    if a.sample_frac:  # stratification needs every class at least a few times
        names, n = np.unique(labels, return_counts=True)
        keep = np.isin(labels, names[n >= 10])
        X, labels = X[keep], labels[keep]
    enc = LabelEncoder().fit(labels)
    y = enc.transform(labels)
    benign = int(enc.transform(["BENIGN"])[0])
    counts = {str(k): int(v) for k, v in zip(*np.unique(labels, return_counts=True))}
    print(f"{len(y)} flows ({n_raw} raw), classes {counts}", flush=True)

    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.3, stratify=y, random_state=a.seed)
    del X
    port = cols.index("Destination Port")
    binary = [i for i in range(len(cols)) if i != port and set(np.unique(Xtr[:, i])) <= {0.0, 1.0}]
    numeric = [i for i in range(len(cols)) if i != port and i not in binary]
    integer = [i for i in numeric if np.all(Xtr[:, i] == np.round(Xtr[:, i]))]
    combination = sorted(binary + [port])

    # self-check: the vectorised patterns must behave like the library's on real training rows
    rng = np.random.default_rng(a.seed)
    idx = np.concatenate([rng.permutation(np.flatnonzero(ytr == c))[:a.check_rows]
                          for c in np.unique(ytr) if c != benign])
    check = self_check(Xtr[idx], ytr[idx], benign, numeric, integer, combination, port, a.seed)
    print("self-check", json.dumps(check), flush=True)
    if not check["passed"]:
        raise SystemExit("vectorised A2PM patterns disagree with the library; see the self-check above")

    def method(Xf: np.ndarray, yf: np.ndarray, reference: bool = a.reference_patterns, seed: int = a.seed):
        pat = make_patterns(pattern_classes(reference), numeric, integer, combination, [port], seed)
        return A2PMethod(pattern=pat, preassigned_patterns={benign: None}, seed=seed).fit(Xf, yf)

    # adversarial training data: one A2PM example per malicious training flow, A2PM fitted on training data
    mal_tr = ytr != benign
    t = time.perf_counter()
    Xadv = method(Xtr, ytr).transform(Xtr[mal_tr], ytr[mal_tr])
    adv_seconds = round(time.perf_counter() - t, 1)
    Xat, yat = np.vstack([Xtr, Xadv]), np.r_[ytr, ytr[mal_tr]]
    del Xadv

    mal = yte != benign
    X_mal, y_mal, X_ben, y_ben = Xte[mal], yte[mal], Xte[~mal], yte[~mal]
    attack = method(Xte, yte)  # the attacker adapts A2PM to the evaluation set (Section 4.4)

    def rf():
        return RandomForestClassifier(n_estimators=100, criterion="gini", max_depth=32, min_samples_leaf=2,
                                      max_features="sqrt", class_weight="balanced", n_jobs=-1,
                                      random_state=a.seed)

    def mlp():
        if a.mlp == "keras":
            return KerasMLP(a.seed)
        return make_pipeline(StandardScaler(), MLPClassifier(
            hidden_layer_sizes=(64, 32), activation="relu", solver="adam", learning_rate_init=1e-3,
            batch_size=512, max_iter=50, early_stopping=True, validation_fraction=0.2, random_state=a.seed))

    r = {
        "paper": "Vitorino, Oliveira & Praca 2022, Adaptative Perturbation Patterns: Realistic Adversarial "
                 "Learning for Robust Intrusion Detection, Future Internet 14(4):108, doi:10.3390/fi14040108 "
                 "(arXiv:2203.04234)",
        "paper_results": PAPER,
        "n_flows": int(len(y)), "n_raw": int(n_raw), "class_counts": counts,
        "n_train": int(len(ytr)), "n_eval": int(len(yte)), "n_eval_malicious": int(mal.sum()),
        "n_features": len(cols), "n_numeric": len(numeric), "n_integer": len(integer), "n_binary": len(binary),
        "patterns": "library (a2pm 1.2.0 transforms)" if a.reference_patterns else "vectorised (self-checked)",
        "mlp": a.mlp,
        "self_check": check,
        "adversarial_training_examples": int(mal_tr.sum()), "adversarial_example_seconds": adv_seconds,
        "assumptions": [
            "MachineLearningCVE Tuesday + Wednesday CSVs (78 numerical features), rows with NaN/inf dropped",
            "Interval pattern on the non-binary features (integer steps where every training value is an "
            "integer); Combination pattern on the binary TCP-flag features with Destination Port locked (the "
            "paper one-hot encoded its categorical features and locked port and protocol; these CSVs have no "
            "protocol column)",
            "A2PM pattern transforms: " + ("a2pm 1.2.0's own" if a.reference_patterns else
                                           "vectorised subclasses (same distribution, different random "
                                           "stream), checked against the library on a training sample"),
            ("MLP: Keras 64-32 ReLU, dropout 0.1, softmax, Adam 1e-3, batch 512, <= 50 epochs, early stopping "
             "(patience 5) on a stratified 20 % validation split, balanced class weights, standardised inputs"
             if a.mlp == "keras" else
             "MLP: scikit-learn MLPClassifier (64, 32), no dropout and no class weights, standardised inputs"),
            f"A2PM attacks: {a.iterations} iterations, early stopping "
            + (f"patience {a.patience}" if a.patience else "off") + ", scores recorded after every iteration",
            f"stratified 70/30 split, seed {a.seed}"
            + (f", rows sampled with probability {a.sample_frac} (smoke test)" if a.sample_frac else ""),
        ],
        "results": {},
        "environment": {"python": platform.python_version(), "a2pm": version("a2pm"),
                        "numpy": np.__version__, "pandas": pd.__version__, "sklearn": sklearn.__version__},
    }
    if a.mlp == "keras":
        import tensorflow as tf
        r["environment"]["tensorflow"] = tf.__version__

    for name in MODELS:
        kind, training = name.split("_")
        Xf, yf = (Xtr, ytr) if training == "regular" else (Xat, yat)
        t = time.perf_counter()
        clf = (rf() if kind == "RF" else mlp()).fit(Xf, yf)
        row: dict = {"train_seconds": round(time.perf_counter() - t, 1)}
        if hasattr(clf, "epochs_run"):
            row["epochs_run"] = clf.epochs_run
        if name == "RF_regular" and a.e2e_rows and not a.reference_patterns:
            e2e = end_to_end_check(clf, lambda ref, s: method(Xte, yte, ref, s), X_mal, y_mal, benign,
                                   a.e2e_rows, a.e2e_seeds)
            r["end_to_end_check"] = e2e
            print("end-to-end check", json.dumps(e2e), flush=True)
            if not e2e["passed"]:
                save(r, a.out)
                raise SystemExit("library and vectorised A2PM attacks disagree on RF_regular; see above")
        p_ben = clf.predict(X_ben)
        row["clean"] = scores(clf.predict(X_mal), y_mal, p_ben, y_ben, benign)
        for attack_kind in ("targeted", "untargeted"):
            row[attack_kind] = attack_curve(attack, clf, X_mal, y_mal, p_ben, y_ben, benign,
                                            attack_kind == "targeted", a.iterations, a.patience)
        r["results"][name] = row
        r["seconds"] = round(time.time() - t0, 1)
        brief = {k: (v if not isinstance(v, dict) else {m: v[m][-1] if isinstance(v[m], list) else v[m]
                                                         for m in v}) for k, v in row.items()}
        print(name, json.dumps(brief), flush=True)
        save(r, a.out)  # partial results survive a timeout
    print(to_markdown(r))
    return 0


def save(r: dict, out: Path) -> None:
    """Write vitorino2022.json / .md (and the curve figure when matplotlib is available)."""
    out.mkdir(parents=True, exist_ok=True)
    (out / "vitorino2022.json").write_text(json.dumps(r, indent=1))
    (out / "vitorino2022.md").write_text(to_markdown(r), encoding="utf-8")
    try:
        write_figure(r, out / "vitorino2022_curves.png")
    except ImportError:
        pass


def write_figure(r: dict, path: Path) -> None:
    """Three panels like the paper's Figures 5-7, with the paper's iteration-0 and -50 values as markers."""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    colours = {"RF_regular": "#1f77b4", "RF_adversarial": "#0b3c6b",
               "MLP_regular": "#ff7f0e", "MLP_adversarial": "#8c3b00"}
    panels = (("targeted", "accuracy", "targeted_accuracy", "Targeted (towards Benign): accuracy"),
              ("untargeted", "accuracy", "untargeted_accuracy", "Untargeted: accuracy"),
              ("untargeted", "macro_f1", "untargeted_macro_f1", "Untargeted: macro-F1"))
    fig, axes = plt.subplots(1, 3, figsize=(13, 3.8), sharey=True)
    for ax, (kind, metric, paper_key, title) in zip(axes, panels):
        for name, row in r["results"].items():
            ys = row[kind][metric]
            ax.plot(range(len(ys)), ys, color=colours[name], label=name.replace("_", ", "))
            start, end = r["paper_results"][paper_key][name]
            ax.plot([0, len(ys) - 1], [start, end], linestyle="none", marker="o", mfc="none",
                    color=colours[name])
        ax.set_title(title, fontsize=10)
        ax.set_xlabel("A2PM iteration")
        ax.set_ylim(-0.02, 1.02)
        ax.grid(alpha=0.3)
    axes[0].set_ylabel("score")
    axes[0].plot([], [], linestyle="none", marker="o", mfc="none", color="grey",
                 label="paper (Figs 5-7), iterations 0 and 50")
    axes[0].legend(fontsize=8, loc="lower left")
    fig.tight_layout()
    fig.savefig(path, dpi=90)
    plt.close(fig)


def to_markdown(r: dict) -> str:
    """Paper (Figures 5-7) vs reproduction table, self-check and assumptions."""
    P = r["paper_results"]
    L = ["# Reproduction: Vitorino, Oliveira & Praca 2022 (A2PM), CIC-IDS2017 Enterprise scenario", "",
         f"{r['n_flows']} flows ({r['n_eval_malicious']} malicious evaluation flows); classes "
         f"{r['class_counts']}.", f"Paper (Table 2): {P['n_samples']} flows, classes {P['class_counts']}.", "",
         f"Pattern transforms: {r['patterns']}; MLP: {r['mlp']}.", "",
         "Accuracy is on the malicious evaluation flows only (the paper's definition); detection is the share "
         "of malicious evaluation flows not classified Benign; macro-F1 is over all evaluation flows. Paper "
         "values are the legends of Figures 5-7 (iteration 0 -> 50); ours are iteration 0 -> 1 -> 50.", "",
         "| model | metric | paper, it 0 -> 50 | ours, it 0 -> 1 -> 50 |", "|---|---|---|---|"]
    for name, row in r["results"].items():
        for kind, metric, key in (("targeted", "accuracy", "targeted_accuracy"),
                                  ("targeted", "detection", None),
                                  ("untargeted", "accuracy", "untargeted_accuracy"),
                                  ("untargeted", "macro_f1", "untargeted_macro_f1")):
            c = row[kind][metric]
            paper = "-" if key is None else f"{P[key][name][0]:.4f} -> {P[key][name][1]:.4f}"
            L.append(f"| {name.replace('_', ', ')} | {kind} {metric.replace('_', '-')} | {paper} | "
                     f"{c[0]:.4f} -> {c[1]:.4f} -> {c[-1]:.4f} |")
    L += ["", "Run details:", ""]
    for name, row in r["results"].items():
        extra = f", {row['epochs_run']} epochs" if "epochs_run" in row else ""
        L.append(f"- {name}: trained in {row['train_seconds']} s{extra}; targeted attack ran "
                 f"{row['targeted']['iterations_run']} iterations ({row['targeted']['examples_generated']} "
                 f"examples), untargeted {row['untargeted']['iterations_run']} "
                 f"({row['untargeted']['examples_generated']} examples)")
    c = r["self_check"]
    L += ["", f"Self-check on {c['rows']} malicious training rows ({c['classes']} classes), library vs vectorised "
          f"patterns (speed-up {c['speedup']}x):", "",
          "| statistic | library | vectorised |", "|---|---|---|"]
    for k in ("frac_numeric_values_changed", "frac_rows_combination_changed", "mean_abs_normalised_step",
              "ms_per_row"):
        L.append(f"| {k.replace('_', ' ')} | {c['library'][k]:.4f} | {c['vectorised'][k]:.4f} |")
    L += ["", f"KS statistic of the normalised steps: {c['ks_statistic_normalised_steps']:.4f} "
          f"(p = {c['ks_pvalue_normalised_steps']:.3f}). Checks: "
          + "; ".join(f"{k}: {'pass' if v else 'FAIL'}" for k, v in c["checks"].items()) + "."]
    e = r.get("end_to_end_check")
    if e:
        L += ["", f"End-to-end check (targeted attack on the regularly trained RF, {e['rows']} malicious "
              f"evaluation flows, {e['seeds']} seeds, {e['iterations']} iterations), mean accuracy after "
              f"iterations 0..{e['iterations']}: library {e['library']['accuracy_mean']} "
              f"(sd {e['library']['accuracy_sd']}, {e['library']['seconds']} s), vectorised "
              f"{e['vectorised']['accuracy_mean']} (sd {e['vectorised']['accuracy_sd']}, "
              f"{e['vectorised']['seconds']} s); differences {e['abs_diff']} against tolerances "
              f"{e['tolerance']} ({'pass' if e['passed'] else 'FAIL'})."]
    L += ["", "Assumptions / deviations:", ""] + [f"- {x}" for x in r["assumptions"]]
    L += ["", f"Paper, Section 4.5: {P['targeted_after_1_iteration']}; generation rate {P['generation_rate']}.",
          f"Total runtime {r.get('seconds', 0)} s."]
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
