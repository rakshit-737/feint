"""Data-poisoning (backdoor) study and a training-data sanitiser.

Attack: the adversary contributes a small fraction of training flows (e.g. via a
honeypot feed or a mislabelled capture): copies of real malicious flows whose
attacker-controllable *trigger* feature is set to a rare value, labelled benign. At
test time the attacker stamps the trigger on its traffic to walk past the detector.

Defence: kNN label-consistency computed only on *robust* (attacker-immutable) features.
A backdoor trigger must live in a feature the attacker controls, so in robust-feature
space a poisoned flow sits among the malicious flows it was copied from, and its
"benign" label disagrees with its neighbourhood.
"""
from __future__ import annotations

import numpy as np
from sklearn.neighbors import NearestNeighbors

from .schema import Schema


def pick_trigger(schema: Schema, X_train) -> tuple[str, float]:
    """First free (range-controllable) feature and an integer value unseen in training."""
    f = next(iter(schema.free))
    lo, hi = schema.free[f]
    seen = set(np.round(X_train[:, schema.idx[f]]).astype(int).tolist())
    for v in list(range(int(hi) - 7, int(lo), -1)):
        if v not in seen:
            return f, float(v)
    raise ValueError("no unused trigger value")


def stamp(X, schema: Schema, feature: str, value: float) -> np.ndarray:
    X = np.array(X, dtype=float, copy=True)
    X[:, schema.idx[feature]] = value
    return schema.recompute(X)


def make_poison(X, y, schema: Schema, rate=0.02, trigger=None, seed=0):
    """Return (X_poisoned, y_poisoned, is_poison, (feature, value))."""
    rng = np.random.default_rng(seed)
    f, v = trigger or pick_trigger(schema, X)
    mal = np.flatnonzero(np.asarray(y) == 1)
    k = int(round(rate * len(y)))
    src = rng.choice(mal, size=k, replace=len(mal) < k)
    Xp = stamp(X[src], schema, f, v)
    Xn = np.vstack([X, Xp])
    yn = np.r_[y, np.zeros(k, dtype=int)]
    flag = np.r_[np.zeros(len(y), bool), np.ones(k, bool)]
    return Xn, yn, flag, (f, v)


def knn_sanitize(Z, y, cols, k=10, thr=0.5):
    """Flag benign-labelled points whose k robust-feature neighbours are mostly malicious."""
    Zr = Z[:, cols]
    nn = NearestNeighbors(n_neighbors=k + 1, n_jobs=-1).fit(Zr)
    ben = np.flatnonzero(np.asarray(y) == 0)
    _, nb = nn.kneighbors(Zr[ben])
    frac_mal = (np.asarray(y)[nb[:, 1:]] == 1).mean(1)
    flag = np.zeros(len(y), bool)
    flag[ben[frac_mal > thr]] = True
    return flag


def backdoor_study(det_factory, X_tr, y_tr, X_te, y_te, schema: Schema, rate=0.02, seed=0,
                   robust_cols=None, k=10):
    """Train clean / poisoned / sanitised models and report backdoor success.

    ``det_factory(X, y)`` must return a fitted detector.
    """
    Xp, yp, is_p, (f, v) = make_poison(X_tr, y_tr, schema, rate=rate, seed=seed)
    X_mal = X_te[y_te == 1]
    X_trig = stamp(X_mal, schema, f, v)
    res = {"trigger_feature": f, "trigger_value": v, "rate": rate, "n_poison": int(is_p.sum())}

    def evaluate(det, tag):
        p = det.predict(X_te)
        res[tag] = {
            "clean_accuracy": float((p == y_te).mean()),
            "clean_recall": float((det.predict(X_mal) == 1).mean()),
            "triggered_recall": float((det.predict(X_trig) == 1).mean()),
        }
        res[tag]["backdoor_success"] = 1.0 - res[tag]["triggered_recall"]

    clean = det_factory(X_tr, y_tr)
    evaluate(clean, "clean_model")
    poisoned = det_factory(Xp, yp)
    evaluate(poisoned, "poisoned_model")
    if robust_cols is not None and len(robust_cols):
        Z = poisoned.pre.transform(Xp)
        flag = knn_sanitize(Z, yp, robust_cols, k=k)
        tp = int((flag & is_p).sum())
        res["sanitizer"] = {
            "flagged": int(flag.sum()),
            "poison_recall": tp / max(int(is_p.sum()), 1),
            "precision": tp / max(int(flag.sum()), 1),
            "clean_benign_removed_frac": float((flag & ~is_p).sum() / max(int((yp == 0).sum() - is_p.sum()), 1)),
        }
        sanitized = det_factory(Xp[~flag], yp[~flag])
        evaluate(sanitized, "sanitized_model")
    return res
