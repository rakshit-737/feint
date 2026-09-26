"""Hardening: adversarial training against constrained PGD."""
from __future__ import annotations

import copy

import numpy as np

from .attack import pgd


def adversarial_training(det, X, y, eps=1.0, rounds=3, steps=10, constrained=True, seed=0):
    """Return a hardened copy of `det`.

    Each round: craft PGD evasions of the malicious training flows against the
    current model, add them (label=1) to the training pool, retrain. Only the
    malicious class is perturbed because only attackers have an incentive to evade.
    The preprocessor is kept fixed so attacks and training share one z-space.
    """
    rng = np.random.default_rng(seed)
    hard = copy.deepcopy(det)
    Z_pool, y_pool = hard.pre.transform(X), np.asarray(y)
    mal = X[y == 1]
    for _ in range(rounds):
        # mix of budgets so the model is robust across the whole curve, not one eps
        e = rng.uniform(0.25, 1.0, size=1)[0] * eps
        X_adv = pgd(hard, mal, np.ones(len(mal)), eps=e, steps=steps, constrained=constrained)
        Z_pool = np.vstack([Z_pool, hard.pre.transform(X_adv)])
        y_pool = np.r_[y_pool, np.ones(len(X_adv), dtype=int)]
        hard.fit_z(Z_pool, y_pool)
    return hard
