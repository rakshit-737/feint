# ADR 0002: Perturbation budgets are L-inf balls in standardised log space

- Status: accepted
- Date: 2026-09-26

## Context

Flow features span 10+ orders of magnitude (microsecond durations to gigabit rates) and are
heavy-tailed. An L-inf budget in raw units is meaningless; min-max scaling lets a single
outlier define the unit.

## Decision

All models consume `z = (log1p(x) - mu) / sigma` (fit on training data, `Preprocessor`).
Attacks operate in z-space with an L-inf radius `eps`, then invert to raw space and project
onto the constraint set. `eps = 1` therefore means "move a controllable feature by up to one
standard deviation of its log", i.e. a *multiplicative* change, which matches how padding
and delay budgets behave.

## Consequences

- Budgets are comparable across features and datasets but not directly interpretable in bytes
  or seconds; counterfactual explanations report raw before/after values to compensate.
- Projection (integer rounding, relations) can move a point slightly outside the z-ball; `eps`
  is the attacker's search radius, not a certified bound.
- Tree models are invariant to this monotone transform, so XGBoost and random forest are
  unaffected; the MLP and autoencoder benefit from it.
