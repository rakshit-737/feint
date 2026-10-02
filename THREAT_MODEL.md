# FEINT Threat Model

FEINT is a research pipeline. This document describes the **adversary it simulates** and,
separately, the risks of **running FEINT itself**.

## 1. Modelled adversaries

| Item | Assumption |
| --- | --- |
| Assets | The flow-based detector (ensemble) and its training data |
| Knowledge | **White-box / Kerckhoffs**: architecture, weights, preprocessing and constraint model are known. Gradients are exact for the MLP; trees and the ensemble are attacked by transfer from a differentiable surrogate plus score-based black-box search (query access to `predict_proba`). |
| Evasion goal | A malicious flow is classified benign while still being a realisable flow |
| Evasion capability (constrained) | Defined per dataset in [`feint/schema.py`](feint/schema.py) and [ADR 0001](docs/adr/0001-feature-space-constraint-schemas.md): the attacker may only *increase* its own duration / packets / payload (integer counts, `bytes <= packets * MTU`, max packet length consistent with mean), may set its own TCP window (CIC, UNSW) and IP TTL (UNSW) to any valid integer, and cannot touch server replies, destination port, protocol-bound flags or host-context counters. Derived features are recomputed, never set. |
| Evasion capability (unconstrained) | Reference only: every feature perturbed within an L-inf budget in standardised log space. Produces unrealisable flows (validity 0 %); reported to show how much textbook evaluations misstate the attacker. |
| Budget | `eps` = L-inf radius in standardised log-feature space ([ADR 0002](docs/adr/0002-perturbation-budget-in-log-space.md)). |
| Poisoning goal | Backdoor: attacker-supplied training flows (e.g. via a honeypot or a mislabelled capture) teach the model that a trigger value in an attacker-controllable feature means "benign". Budget: 2 % of the training set. |
| Detector-aware attacker | For the adversarial-input alarm we also evaluate an attacker who optimises against `detector OR alarm`, not only the static case. |

### Out of scope / known gaps
- **Problem-space attacks** (rewriting pcaps and re-running CICFlowMeter). Constraints approximate
  this in feature space; cross-feature side effects (e.g. more packets also lengthen duration,
  more connections change `ct_*` counters) are not modelled, and the attack's own purpose (a DoS
  needs its volume) is not enforced; that favours the attacker. Conversely the schema treats as
  fixed several features a client can influence indirectly (`ct_*` via pacing or decoy
  connections, `trans_depth` via pipelining, server-response `bwd_*` / `dbytes` and `syn_count` via
  request choice and retransmissions); that favours the defender, and the robust-feature model's
  result is conditional on it.
- **Model stealing** is studied separately (`feint steal`): a label-only `/score` endpoint lets an
  attacker train a surrogate whose transfer attack is as strong as one built from the true labels.
- **The explanation endpoint is an evasion oracle.** `/score` with `explain=true` returns a
  constraint-valid counterfactual, i.e. an evasion recipe, to any client. The API caps requests
  (1-1000 flows, at most 20 explained) and binds to localhost; do not expose it.
- **Certified robustness**: all robustness numbers are empirical upper bounds from our attacks.
- **Clean-label poisoning** and poisoning of the unsupervised member are not studied.

## 2. Risks of running FEINT

| Risk | Mitigation |
| --- | --- |
| Loading an untrusted CSV or Parquet file | Parsed with pandas / pyarrow (`data` extra, pyarrow>=14.0.1 for CVE-2023-47248) into numeric arrays only; non-numeric / non-finite values dropped; no pickle or eval on inputs. |
| Loading a model bundle (`feint serve --model`) | Bundles are joblib pickles: **only load bundles you produced yourself**. |
| Misuse as an evasion tool | Attacks operate on feature vectors against models trained locally on public datasets; no traffic is generated or sent, no exploit code, no malware. |
| Overclaiming robustness | Curves across budgets, constrained and unconstrained, adaptive attacks against the defended system, precision at 1 % and 0.1 % prevalence, and explicit limitations in the README. |
| API exposure | `feint serve` binds to 127.0.0.1 by default and has no authentication; it is a lab demo, not a production service. |

All data is public (CIC-IDS2017 original and corrected, UNSW-NB15, CSE-CIC-IDS2018, a CICIoT2023 re-export) or synthetic. No live network interaction.
