"""Evasion attacks in standardised log-feature space (z), with domain-constraint projection.

Threat model: the attacker controls only its own side of a malicious flow (see
:mod:`feint.schema`) and wants it classified benign. Budgets ``eps`` are L_inf radii in
z-space (1.0 = one standard deviation of the log-feature) around the original flow.

* :func:`pgd`            white-box PGD for differentiable detectors (MLP)
* :func:`random_search`  score-based black-box search (works on trees, ensembles, anything)
* :func:`adaptive`       strongest available: PGD if differentiable, else transfer from a
                         differentiable surrogate followed by black-box search

With ``constrained=True`` every step is projected onto the realisable-flow set so every
returned flow passes ``schema.is_valid``; ``constrained=False`` is the textbook
(physically meaningless) attack that perturbs every feature freely.
"""
from __future__ import annotations

import numpy as np

from .schema import Schema


def _mask(schema: Schema, n: int, constrained: bool) -> np.ndarray:
    return schema.mask() if constrained else np.ones(n)


def _finish(det, schema, Z, X, constrained):
    Xa = det.pre.inverse(Z)
    return schema.project(Xa, X) if constrained else Xa


def pgd(det, X, schema: Schema, eps=0.5, steps=20, alpha=None, constrained=True, y=None):
    """L_inf PGD maximising the detector's loss on label ``y`` (default: all malicious).

    Returns raw-space adversarial flows.
    """
    X = np.asarray(X, dtype=float)
    y = np.ones(len(X)) if y is None else np.asarray(y, dtype=float)
    if eps <= 0 or len(X) == 0:
        return X.copy()
    alpha = alpha if alpha is not None else 2.5 * eps / steps
    pre = det.pre
    Z0 = pre.transform(X)
    Z = Z0.copy()
    mask = _mask(schema, Z.shape[1], constrained)
    for _ in range(steps):
        g = det.grad_z(Z, y)
        Z = Z0 + np.clip(Z + alpha * np.sign(g) * mask - Z0, -eps, eps)
        if constrained:
            Z = pre.transform(schema.project(pre.inverse(Z), X))
    return _finish(det, schema, Z, X, constrained)


def random_search(det, X, schema: Schema, eps=0.5, iters=100, constrained=True, seed=0,
                  X_start=None, p_init=0.5):
    """Score-based black-box evasion (Square-Attack-style coordinate sign search).

    Each iteration proposes, per flow, a vertex of the eps-ball on a random subset of the
    allowed coordinates, projects it, queries ``predict_proba`` and keeps it if the
    malicious score went down. Flows already classified benign stop moving.
    Query cost: ``iters`` batched ``predict_proba`` calls.
    """
    X = np.asarray(X, dtype=float)
    if eps <= 0 or len(X) == 0:
        return X.copy()
    rng = np.random.default_rng(seed)
    pre = det.pre
    Z0 = pre.transform(X)
    cur_X = X.copy() if X_start is None else np.asarray(X_start, dtype=float).copy()
    cur_Z = pre.transform(cur_X)
    cur_p = det.predict_proba_z(cur_Z)
    allowed = np.flatnonzero(_mask(schema, Z0.shape[1], constrained))
    for t in range(iters):
        active = cur_p >= 0.5
        if not active.any():
            break
        frac = p_init * (1 - t / max(iters, 1)) + 0.05  # shrink the coordinate subset over time
        k = max(1, int(round(frac * len(allowed))))
        idx = np.flatnonzero(active)
        D = np.zeros((len(idx), Z0.shape[1]))
        cols = allowed[np.argsort(rng.random((len(idx), len(allowed))), axis=1)[:, :k]]
        rows = np.repeat(np.arange(len(idx)), k)
        # multi-scale: a vertex of a randomly shrunk ball, so large budgets never hurt the attacker
        scale = rng.choice([0.25, 0.5, 1.0], size=(len(idx), 1))
        D[rows, cols.ravel()] = (rng.choice([-1.0, 1.0], size=(len(idx), k)) * eps * scale).ravel()
        # vertex step relative to the current point, then clip back into the eps-ball
        Zc = cur_Z[idx].copy()
        sel = D != 0
        Zc[sel] = (Z0[idx] + D)[sel]
        Zc = Z0[idx] + np.clip(Zc - Z0[idx], -eps, eps)
        Xc = pre.inverse(Zc)
        if constrained:
            Xc = schema.project(Xc, X[idx])
            Zc = pre.transform(Xc)
        p = det.predict_proba_z(Zc)
        better = p < cur_p[idx]
        upd = idx[better]
        cur_Z[upd], cur_X[upd], cur_p[upd] = Zc[better], Xc[better], p[better]
    return schema.project(cur_X, X) if constrained else cur_X


def adaptive(det, X, schema: Schema, eps=0.5, constrained=True, surrogate=None, steps=20,
             iters=100, seed=0):
    """Strongest attack we have against ``det``.

    * differentiable detector: white-box PGD, then black-box search seeded from it
    * otherwise: PGD against ``surrogate`` (transfer), then black-box search seeded from it
    Returns the per-flow best (lowest malicious score) of the candidates.
    """
    X = np.asarray(X, dtype=float)
    if eps <= 0 or len(X) == 0:
        return X.copy()
    cands = []
    grad_model = det if getattr(det, "differentiable", False) else surrogate
    if grad_model is not None:
        cands.append(pgd(grad_model, X, schema, eps=eps, steps=steps, constrained=constrained))
    start = cands[0] if cands else None
    if start is not None and not constrained:
        # keep the transfer start inside the target's own eps-ball
        Z0 = det.pre.transform(X)
        start = det.pre.inverse(Z0 + np.clip(det.pre.transform(start) - Z0, -eps, eps))
    cands.append(random_search(det, X, schema, eps=eps, iters=iters, constrained=constrained,
                               seed=seed, X_start=start))
    P = np.stack([det.predict_proba(c) for c in cands])
    best = P.argmin(0)
    return np.stack(cands)[best, np.arange(len(X))]


def is_valid(X, X_orig, schema: Schema, tol: float = 1e-6):
    return schema.is_valid(X, X_orig, tol)


def project_constraints(X_adv, X_orig, schema: Schema):
    return schema.project(X_adv, X_orig)
