"""Hardening: adversarial training, robust-feature selection, adversarial-input detection."""
from __future__ import annotations

import numpy as np

from .metrics import metrics_from_scores
from .schema import Schema


def adversarial_training(det, X, y, attack, eps=1.0, rounds=3, n_adv=None, seed=0):
    """Return a hardened copy of ``det``.

    Each round crafts evasions of (a sample of) the malicious training flows against the
    *current* model with ``attack(model, X_mal, eps_r)``, adds them with label 1 and
    retrains. Budgets ``eps_r`` are drawn in [0.25, 1] * eps so robustness covers the
    whole curve rather than one radius. Only the malicious class is perturbed: only
    attackers have an incentive to evade. The preprocessor stays fixed so attacks and
    training share one z-space.
    """
    rng = np.random.default_rng(seed)
    hard = det.clone()
    y = np.asarray(y)
    Z_pool, y_pool = hard.pre.transform(X), y.copy()
    mal = X[y == 1]
    for r in range(rounds):
        sub = mal if n_adv is None or n_adv >= len(mal) else mal[rng.choice(len(mal), n_adv, replace=False)]
        e = float(rng.uniform(0.25, 1.0)) * eps if rounds > 1 else eps
        if r == rounds - 1:
            e = eps  # always finish with the full budget
        X_adv = attack(hard, sub, e)
        Z_pool = np.vstack([Z_pool, hard.pre.transform(X_adv)])
        y_pool = np.r_[y_pool, np.ones(len(X_adv), dtype=int)]
        hard.fit_z(Z_pool, y_pool)
    return hard


def robust_feature_indices(schema: Schema) -> np.ndarray:
    """Column indices of features the attacker cannot move (directly or via derivation)."""
    return np.array([schema.idx[f] for f in schema.robust_features()])


class AdversarialInputDetector:
    """Binary classifier: does this flow look *optimised against us*?

    Trained on clean flows (label 0) vs. constrained adversarial flows (label 1) crafted
    against the deployed detector. Uses gradient-boosted trees on z-features plus the
    deployed detector's own score (adversarial flows cluster just under the threshold).
    """

    def __init__(self, target, seed=0):
        from xgboost import XGBClassifier

        self.target = target
        self.clf = XGBClassifier(n_estimators=200, max_depth=6, learning_rate=0.1,
                                 tree_method="hist", random_state=seed, n_jobs=-1)

    def _feat(self, X):
        Z = self.target.pre.transform(X)
        return np.column_stack([Z, self.target.predict_proba_z(Z)])

    def fit(self, X_clean, X_adv):
        F = np.vstack([self._feat(X_clean), self._feat(X_adv)])
        lab = np.r_[np.zeros(len(X_clean)), np.ones(len(X_adv))]
        self.clf.fit(F, lab)
        # threshold so that <= 1% of clean training flows are flagged
        self.thr = float(np.quantile(self.clf.predict_proba(self._feat(X_clean))[:, 1], 0.99))
        return self

    def score(self, X):
        return self.clf.predict_proba(self._feat(X))[:, 1]

    def evaluate(self, X_clean, X_adv):
        s = np.r_[self.score(X_clean), self.score(X_adv)]
        lab = np.r_[np.zeros(len(X_clean)), np.ones(len(X_adv))]
        m = metrics_from_scores(s, lab, thr=self.thr)
        return {"auc": m["auc"], "tpr": m["recall"], "fpr": m["fpr"], "threshold": self.thr}
