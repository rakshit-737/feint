# FEINT

**A network intrusion detector built to be attacked.** FEINT trains a flow-based NIDS ensemble on
CIC-IDS2017 and UNSW-NB15, red-teams it with *adaptive* evasion that respects what a network
attacker can actually change, poisons its training data, hardens it, explains every alert with
SHAP and constraint-valid counterfactuals, and reports **robustness curves and base-rate-honest
precision** instead of a single accuracy number.

> Everyone reports 99 % accuracy on CIC-IDS2017. FEINT asks what is left of that number when the
> attacker knows the model and pads, delays or adds packets to its own traffic.
> Short answer: **XGBoost at 99.7 % clean accuracy still detects only 42 % of attack flows under
> a realisable attack, and 0 % on UNSW-NB15**. Adversarial training brings that back to 80-96 %,
> and a model restricted to attacker-immutable features is untouched by the attack at a
> 2.2-point FPR cost.

- **[Getting started](getting-started.md)**: install, smoke study, API
- **[Architecture](architecture.md)**: pipeline and module map
- **[Benchmarks](benchmarks.md)**: real CIC-IDS2017 / UNSW-NB15 results, multi-seed confidence intervals
- **[Interactive results dashboard](demo/index.html)**: static view over the committed reports
- **[Threat model](threat-model.md)** and **[limitations](limitations.md)**

!!! warning "Lab-only"
    FEINT perturbs *feature vectors*; it never crafts, captures or sends packets. See [Security](security.md).
