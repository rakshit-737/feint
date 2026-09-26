"""Detection metrics, robustness curves and base-rate-honest precision."""
from __future__ import annotations

import numpy as np
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score

from .attack import is_valid, pgd


def detection_metrics(det, X, y):
    p = det.predict_proba(X)
    yhat = (p >= 0.5).astype(int)
    tn = int(((yhat == 0) & (y == 0)).sum())
    fp = int(((yhat == 1) & (y == 0)).sum())
    return {
        "accuracy": float(accuracy_score(y, yhat)),
        "precision": float(precision_score(y, yhat, zero_division=0)),
        "recall": float(recall_score(y, yhat, zero_division=0)),
        "f1": float(f1_score(y, yhat, zero_division=0)),
        "auc": float(roc_auc_score(y, p)) if len(set(y)) > 1 else float("nan"),
        "fpr": fp / max(fp + tn, 1),
    }


def precision_at_base_rate(tpr: float, fpr: float, prevalence: float) -> float:
    """Bayes: P(attack | alert) at a realistic attack prevalence."""
    num = tpr * prevalence
    den = num + fpr * (1 - prevalence)
    return float(num / den) if den > 0 else 0.0


def robustness_curve(det, X_mal, eps_list, constrained=True, steps=20):
    """Detection rate on malicious flows vs perturbation budget eps.

    Also returns attack success rate (ASR): fraction of flows detected at eps=0
    that the attack pushes to 'benign', and constraint validity of the adv flows.
    """
    y1 = np.ones(len(X_mal))
    clean = det.predict(X_mal) == 1
    out = []
    for eps in eps_list:
        Xa = pgd(det, X_mal, y1, eps=eps, steps=steps, constrained=constrained)
        det_adv = det.predict(Xa) == 1
        out.append({
            "eps": float(eps),
            "detection_rate": float(det_adv.mean()),
            "attack_success_rate": float((clean & ~det_adv).sum() / max(clean.sum(), 1)),
            "valid_rate": float(is_valid(Xa, X_mal).mean()),
        })
    return out
