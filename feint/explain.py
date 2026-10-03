"""Explanations: TreeSHAP attributions and domain-valid counterfactuals.

* :func:`global_importance` / :func:`local_explanation` use XGBoost's native exact
  TreeSHAP (``pred_contribs``), identical to ``shap.TreeExplainer`` for tree models but
  with no extra dependency.
* :func:`counterfactual` finds, for a flagged flow, a *realisable* variant (it passes
  ``schema.is_valid``) that the detector calls benign, with the smallest budget found by
  bisection, then greedily reverts every change that is not needed. The result answers
  "which attacker-controllable features, changed by how much, would evade this alert?"
"""
from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

import numpy as np

from .attack import adaptive
from .schema import Schema

if TYPE_CHECKING:
    from .model import BaseDetector, XGBDetector


def global_importance(det: XGBDetector, X: np.ndarray, feature_names: Sequence[str]) -> list[dict]:
    """Mean |SHAP| per feature (log-odds units), sorted descending."""
    C = det.contributions_z(det.pre.transform(X))[:, :-1]
    names = list(np.asarray(feature_names)[det.cols]) if det.cols is not None else list(feature_names)
    imp = np.abs(C).mean(0)
    order = np.argsort(-imp)
    return [{"feature": names[i], "mean_abs_shap": float(imp[i])} for i in order]


def local_explanation(det: XGBDetector, x: np.ndarray, feature_names: Sequence[str], top: int = 5) -> list[dict]:
    """Top-``top`` SHAP contributions for one flow (positive = pushes towards malicious)."""
    c = det.contributions_z(det.pre.transform(np.atleast_2d(x)))[0, :-1]
    names = list(np.asarray(feature_names)[det.cols]) if det.cols is not None else list(feature_names)
    order = np.argsort(-np.abs(c))[:top]
    return [{"feature": names[i], "shap": float(c[i])} for i in order]


def _changes(x0: np.ndarray, x1: np.ndarray, schema: Schema, base_only: bool = True) -> list[dict]:
    out = []
    for f in schema.controllable:
        j = schema.idx[f]
        if not np.isclose(x0[j], x1[j], rtol=1e-6, atol=1e-9):
            out.append({"feature": f, "from": float(x0[j]), "to": float(x1[j])})
    return out


def counterfactual(det: BaseDetector, X: np.ndarray, schema: Schema,
                   surrogate: BaseDetector | Sequence[BaseDetector | None] | None = None, eps_max: float = 3.0,
                   bisect: int = 6, iters: int = 60, seed: int = 0) -> tuple[list[dict], np.ndarray]:
    """Minimal-budget, sparsified, constraint-valid counterfactuals for flagged flows ``X``.

    Returns ``(records, X_cf)``: one dict per flow with ``found`` (verdict flipped), ``eps``
    (smallest budget that worked), ``changes`` (list of {feature, from, to}) and ``valid``
    (schema check), and the counterfactual flows themselves (the original row where none was found).
    """
    X = np.asarray(X, dtype=float)
    n = len(X)
    lo, hi = np.zeros(n), np.full(n, eps_max)
    best = X.copy()

    def run(eps_vec: np.ndarray, rows: np.ndarray) -> np.ndarray:
        out = np.empty((len(rows), X.shape[1]))
        # group rows by budget to keep the attack batched
        for e in np.unique(eps_vec):
            m = eps_vec == e
            out[m] = adaptive(det, X[rows][m], schema, eps=float(e), surrogate=surrogate,
                              iters=iters, seed=seed)
        return out

    rows = np.arange(n)
    Xa = run(hi, rows)
    found = det.predict(Xa) == 0
    best[found] = Xa[found]
    for _ in range(bisect):
        rows = np.flatnonzero(found)
        if len(rows) == 0:
            break
        mid = np.round((lo[rows] + hi[rows]) / 2, 3)
        Xm = run(mid, rows)
        ok = det.predict(Xm) == 0
        hi[rows[ok]] = mid[ok]
        best[rows[ok]] = Xm[ok]
        lo[rows[~ok]] = mid[~ok]
    # sparsify: revert each controllable feature to its original value if still evasive
    for f in schema.controllable:
        j = schema.idx[f]
        cand = best.copy()
        cand[:, j] = X[:, j]
        cand = schema.project(cand, X)
        keep = found & (det.predict(cand) == 0)
        best[keep] = cand[keep]
    valid = schema.is_valid(best, X)
    return [{"found": bool(found[i]), "eps": float(hi[i]) if found[i] else None,
             "valid": bool(valid[i]), "changes": _changes(X[i], best[i], schema) if found[i] else []}
            for i in range(n)], best


def describe_counterfactual(cf: dict) -> str:
    """One-line, analyst-facing summary of a counterfactual record."""
    if not cf["found"]:
        return "no realisable evasion within budget: this alert is robust to the modelled attacker"
    parts = [f"{c['feature']} {c['from']:.4g} -> {c['to']:.4g}" for c in cf["changes"]]
    return "flip to benign by: " + "; ".join(parts) if parts else "already benign"
