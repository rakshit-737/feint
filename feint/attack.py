"""Evasion attacks: PGD in standardised space with optional domain-constraint projection."""
from __future__ import annotations

import numpy as np

from .data import CONTROLLABLE, IDX, MAX_PKT, MIN_PKT, recompute_derived

FIXED = ["bwd_pkts", "bwd_bytes", "syn_count"]


def project_constraints(X_adv: np.ndarray, X_orig: np.ndarray) -> np.ndarray:
    """Map an arbitrary perturbed flow back to a realisable one.

    The attacker can only *add* to its own side of the flow:
      * non-controllable features (server replies, SYN count) reset to original
      * controllable features may only increase (padding, delays, extra packets)
      * packet counts are integers
      * fwd_bytes lies within [MIN_PKT, MAX_PKT] * fwd_pkts
      * derived features are recomputed from base features, never set directly
    """
    X = X_orig.copy()
    for name in CONTROLLABLE:
        j = IDX[name]
        X[:, j] = np.maximum(X_adv[:, j], X_orig[:, j])
    fp, fb = IDX["fwd_pkts"], IDX["fwd_bytes"]
    X[:, fp] = np.ceil(np.round(X[:, fp], 6))
    X[:, fb] = np.clip(X[:, fb], MIN_PKT * X[:, fp], MAX_PKT * X[:, fp])
    return recompute_derived(X)


def is_valid(X: np.ndarray, X_orig: np.ndarray, tol: float = 1e-6) -> np.ndarray:
    """Per-row check that adversarial flows satisfy the domain constraints."""
    rel = lambda a, b: np.abs(a - b) <= tol * (1 + np.abs(b))  # noqa: E731
    ok = np.all(X >= -tol, axis=1)
    for name in FIXED:
        ok &= rel(X[:, IDX[name]], X_orig[:, IDX[name]])
    for name in CONTROLLABLE:
        ok &= X[:, IDX[name]] >= X_orig[:, IDX[name]] * (1 - tol) - tol
    fp, fb = X[:, IDX["fwd_pkts"]], X[:, IDX["fwd_bytes"]]
    ok &= np.abs(fp - np.round(fp)) <= 1e-6
    ok &= (fb >= MIN_PKT * fp * (1 - tol)) & (fb <= MAX_PKT * fp * (1 + tol))
    ok &= rel(X[:, IDX["fwd_bpp"]], fb / np.maximum(fp, 1))
    ok &= rel(X[:, IDX["pkt_ratio"]], fp / (X[:, IDX["bwd_pkts"]] + 1))
    return ok


def pgd(det, X, y, eps=0.5, steps=20, alpha=None, constrained=True):
    """L_inf PGD in z-space (standardised log-features).

    unconstrained: every feature perturbed freely (textbook, physically unrealisable)
    constrained:   gradient masked to controllable features + raw-space projection
                   after every step, so every returned flow is realisable.
    Returns raw-space adversarial flows.
    """
    X = np.asarray(X, dtype=float)
    y = np.asarray(y, dtype=float)
    if eps <= 0:
        return X.copy()
    alpha = alpha if alpha is not None else 2.5 * eps / steps
    pre = det.pre
    Z0 = pre.transform(X)
    Z = Z0.copy()
    mask = np.ones(Z.shape[1])
    if constrained:
        mask = np.zeros(Z.shape[1])
        for n in CONTROLLABLE:
            mask[IDX[n]] = 1.0
    for _ in range(steps):
        g = det.grad_z(Z, y)
        Z = Z0 + np.clip(Z + alpha * np.sign(g) * mask - Z0, -eps, eps)
        if constrained:
            Z = pre.transform(project_constraints(pre.inverse(Z), X))
    Xa = pre.inverse(Z)
    return project_constraints(Xa, X) if constrained else Xa
