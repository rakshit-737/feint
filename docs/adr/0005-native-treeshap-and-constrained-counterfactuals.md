# ADR 0005: Exact TreeSHAP from XGBoost; counterfactuals from the constrained red-team

- Status: accepted
- Date: 2026-09-26

## Context

Global and per-alert attributions are needed for the XGBoost member, and the spec asks for
DiCE-style counterfactuals that respect network-feature semantics. The `shap` package pulls
in numba/llvmlite, which often lack wheels for new Python versions; DiCE does not know about
our domain constraints.

## Decision

- Attributions: `Booster.predict(..., pred_contribs=True)`, XGBoost's built-in implementation
  of the same exact TreeSHAP algorithm used by `shap.TreeExplainer`. A test checks local
  accuracy (SHAP values plus bias reproduce the model's log-odds).
- Counterfactuals: reuse the adaptive constrained attack with bisection on the budget, then
  greedily revert every controllable feature whose change is not needed for the flip. The
  result is always schema-valid and sparse, and is reported in raw units.

## Consequences

- No extra dependency; attributions are exact.
- SHAP values are in z-space (log-standardised) features, which is what the model sees.
- "No counterfactual found within the budget" is itself informative: that alert is robust to
  the modelled attacker.
