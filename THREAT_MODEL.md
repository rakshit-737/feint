# FEINT Threat Model

FEINT is a research pipeline. Its threat model describes the **adversary it simulates**, and separately the risks of **running FEINT itself**.

## 1. Modelled adversary (what the robustness study assumes)

| Item | Assumption |
| --- | --- |
| Assets | The flow-based detector and its training data |
| Knowledge | **White-box** (Kerckhoffs): attacker knows architecture, weights, preprocessing. Gradients are exact. |
| Goal | Evasion: make a malicious flow be classified benign while still performing the attack |
| Capability (constrained) | Can only *add* to its own direction of the flow: extra forward packets, padding bytes, delays (longer IAT / duration). Cannot change server replies (`bwd_pkts`, `bwd_bytes`) or protocol-bound counts (`syn_count`). Packet counts integer; bytes per packet in [40, 1500]; derived features are recomputed, never set. |
| Capability (unconstrained) | Reference only: any feature perturbed within an L-inf budget in standardised log-space. Produces physically unrealisable flows; reported to show how much textbook evaluations overstate the attacker. |
| Budget | `eps` = L-inf radius in standardised log-feature space (before projection). eps=1 is roughly "scale a controllable feature by e^(1 sigma)". |

### Out of scope in the MVP (documented TODO)
- Data poisoning / backdoors (Grade C/D: needs poisoning study design).
- Model stealing / black-box query attacks.
- Problem-space attacks (actually rewriting pcaps and re-running CICFlowMeter) — the constraints approximate this in feature space only; semantic validity beyond the rules above is Grade D research.
- Adaptive attacks against the IsolationForest backstop (it is non-differentiable; the current result that it catches evasions is **not** a robustness claim).

## 2. Risks of running FEINT

| Risk | Mitigation |
| --- | --- |
| Loading an untrusted CSV | Parsed with `csv` + `float()` only; no pickle/eval; bad rows skipped. |
| Misuse as an evasion tool | Attacks operate on feature vectors against a model you train locally; no traffic is generated or sent. |
| Overclaiming robustness | Reports curves across budgets, constrained and unconstrained, plus precision at 0.1% prevalence. Synthetic-data numbers are illustrative only. |

All data is synthetic or user-supplied public datasets. No live network interaction.
