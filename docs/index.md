# FEINT

**Contribution in one sentence:** FEINT derives the attacker, adversarial training, a robust-feature
model, a poison sanitiser and counterfactual explanations from *one declarative attacker-capability
schema*, and measures over 5 seeds (95 % CIs), on four datasets plus a cross-dataset transfer, what
each schema-derived defence buys against realisable adaptive evasion.

[Results dashboard](demo/index.html){ .md-button .md-button--primary } [Evaluation](evaluation.md){ .md-button } [Reproduce](reproduce.md){ .md-button }

[![FEINT results dashboard: detection rate vs attack budget for every model, CIC-IDS2017](img/dashboard.png)](demo/index.html)

| constrained detection at eps=2 (5 seeds, mean [95 % CI]) | CIC-IDS2017 | UNSW-NB15 |
|---|---|---|
| XGBoost | 0.405 [0.376, 0.433] | 0.000 [0.000, 0.000] |
| FEINT ensemble | 0.369 [0.279, 0.459] | 0.328 [0.262, 0.394] |
| FEINT ensemble + adversarial training | 0.793 [0.763, 0.823] | 0.962 [0.957, 0.968] |
| XGBoost, robust features only (conditional on the schema) | 0.994 [0.993, 0.995] | 0.942 [0.935, 0.950] |

Trained on corrected CIC-IDS2017 and tested on CSE-CIC-IDS2018, XGBoost scores F1 0.000 on the shared
attack families: none of these detectors transfers across datasets.

**Try it in 60 seconds:** `docker run --rm ghcr.io/rakshit-737/feint:latest run --quick --n 2000 --eps 0 1 --no-figures --out /tmp/demo`

- **[Getting started](getting-started.md)**: install, smoke study, API
- **[Architecture](architecture.md)**: pipeline and module map
- **[Evaluation](evaluation.md)**: methodology and every result with confidence intervals
- **[Reproduce](reproduce.md)**: exact commands, runtimes and expected numbers
- **[Threat model](threat-model.md)** and **[limitations](limitations.md)**

!!! warning "Lab-only"
    FEINT perturbs *feature vectors*; it never crafts, captures or sends packets. See [Security](security.md).
