"""Detection metrics, robustness curves and base-rate-honest precision."""
from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from .schema import Schema

if TYPE_CHECKING:
    from .model import BaseDetector


def detection_metrics(det: BaseDetector, X: np.ndarray, y: np.ndarray, thr: float = 0.5) -> dict:
    """Clean detection metrics of ``det`` on flows ``X`` (see :func:`metrics_from_scores`)."""
    p = det.predict_proba(X)
    return metrics_from_scores(p, y, thr)


def metrics_from_scores(p: np.ndarray, y: np.ndarray, thr: float = 0.5) -> dict:
    """Accuracy, precision, recall, F1, ROC-AUC, PR-AUC, FPR and precision at 1 % / 0.1 % prevalence.

    ``p`` are malicious scores, ``y`` binary labels (1 = malicious), ``thr`` the alert threshold.
    AUCs are NaN when ``y`` has a single class.
    """
    y = np.asarray(y)
    yhat = (p >= thr).astype(int)
    tn = int(((yhat == 0) & (y == 0)).sum())
    fp = int(((yhat == 1) & (y == 0)).sum())
    two = len(set(y.tolist())) > 1
    m = {
        "accuracy": float(accuracy_score(y, yhat)),
        "precision": float(precision_score(y, yhat, zero_division=0)),
        "recall": float(recall_score(y, yhat, zero_division=0)),
        "f1": float(f1_score(y, yhat, zero_division=0)),
        "auc": float(roc_auc_score(y, p)) if two else float("nan"),
        "pr_auc": float(average_precision_score(y, p)) if two else float("nan"),
        "fpr": fp / max(fp + tn, 1),
    }
    for prev in (0.01, 0.001):
        m[f"precision_at_{prev:g}"] = precision_at_base_rate(m["recall"], m["fpr"], prev)
    return m


def precision_at_base_rate(tpr: float, fpr: float, prevalence: float) -> float:
    """Bayes: P(attack | alert) at a realistic attack prevalence."""
    num = tpr * prevalence
    den = num + fpr * (1 - prevalence)
    return float(num / den) if den > 0 else 0.0


AttackFn = Callable[[object, np.ndarray, float], np.ndarray]


def robustness_curve(det: BaseDetector, X_mal: np.ndarray, eps_list: Sequence[float], schema: Schema,
                     attack: AttackFn, constrained: bool = True) -> list[dict]:
    """Detection rate on malicious flows vs perturbation budget eps.

    ``attack(det, X_mal, eps)`` returns adversarial flows. Also reports attack success
    rate (ASR: fraction of flows detected at eps=0 that the attack flips to benign) and
    the fraction of adversarial flows that are realisable under ``schema``.
    """
    clean = det.predict(X_mal) == 1
    out = []
    evaded = np.zeros(len(X_mal), dtype=bool)
    for eps in sorted(eps_list):
        Xa = attack(det, X_mal, eps)
        # an attacker with budget eps may also use any smaller budget's successful flow
        evaded |= det.predict(Xa) == 0
        det_adv = ~evaded
        out.append({
            "eps": float(eps),
            "detection_rate": float(det_adv.mean()),
            "attack_success_rate": float((clean & ~det_adv).sum() / max(clean.sum(), 1)),
            "valid_rate": float(schema.is_valid(Xa, X_mal).mean()),
        })
    return out


def area_under_curve(curve: list[dict]) -> float:
    """Mean detection rate over the eps grid (trapezoid, normalised to [0, 1])."""
    e = np.array([c["eps"] for c in curve])
    d = np.array([c["detection_rate"] for c in curve])
    if len(e) < 2 or e[-1] == e[0]:
        return float(d.mean())
    return float(np.trapezoid(d, e) / (e[-1] - e[0]))
