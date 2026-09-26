# ADR 0003: In-house attack engine instead of IBM ART

- Status: accepted
- Date: 2026-09-26

## Context

The original spec planned to use the Adversarial Robustness Toolbox (ART) for attack
primitives. ART's evasion attacks assume box constraints; domain constraints (monotone
features, integer counts, cross-feature relations, derived features) would have to be
injected into every attack's inner loop anyway. ART is also a heavy dependency, and its
tree-model support is limited to specific attack classes.

## Decision

Implement three small, schema-aware attacks in `feint/attack.py`:

1. **PGD** (white-box) for differentiable models, using analytic input gradients of the
   scikit-learn MLP (checked against finite differences in the test suite).
2. **Random search** (score-based black-box, Square-Attack-style multi-scale coordinate
   vertex search) for any model exposing `predict_proba`.
3. **Adaptive**: PGD against the target (or against a differentiable surrogate for trees and
   ensembles), then black-box refinement from that start; the per-flow best candidate wins.

Robustness curves take, per flow, the best result over all budgets up to `eps`, so curves are
monotone and a defence cannot "benefit" from step-size artefacts of the attack.

## Consequences

- One code path for every model, including the ensemble with its autoencoder OR-gate, so we
  report *adaptive* attacks against the defended system instead of attacking only the
  undefended classifier (a common evaluation mistake).
- Our attacks are neither certified nor exhaustive; a stronger attacker could do better.
  All robustness numbers are therefore upper bounds on true robustness.
