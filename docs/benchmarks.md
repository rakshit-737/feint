# Benchmarks

All numbers come from `results/<dataset>/report.json`, produced by the committed code (seed 0,
CPU only). Attack budgets `eps` are L-inf radii in standardised log-feature space
([ADR 0002](adr/0002-perturbation-budget-in-log-space.md)); detection rates are measured on
1,000 held-out attack flows; every constrained adversarial flow passed the schema validity check
(100 %).

**Detection rate under constrained, adaptive evasion (higher is better)**

| model | CIC-IDS2017 eps=0 | eps=0.5 | eps=1 | eps=2 | UNSW-NB15 eps=0 | eps=0.5 | eps=1 | eps=2 |
|---|---|---|---|---|---|---|---|---|
| MLP | 0.991 | 0.576 | 0.349 | 0.123 | 0.967 | 0.398 | 0.173 | 0.056 |
| Random forest (baseline) | 0.995 | 0.507 | 0.435 | 0.397 | 0.968 | 0.623 | 0.163 | 0.000 |
| XGBoost | 0.999 | 0.498 | 0.451 | 0.417 | 0.965 | 0.178 | 0.146 | 0.000 |
| FEINT ensemble (XGB + MLP, OR autoencoder) | 0.998 | 0.590 | 0.491 | 0.400 | 0.969 | 0.501 | 0.416 | 0.255 |
| MLP + adversarial training | 0.991 | 0.857 | 0.779 | 0.732 | 0.957 | 0.925 | 0.907 | 0.865 |
| XGBoost + adversarial training | 1.000 | 0.806 | 0.805 | 0.803 | 0.967 | 0.963 | 0.962 | 0.954 |
| **FEINT ensemble + adversarial training** | 0.998 | **0.860** | **0.840** | **0.830** | 0.969 | **0.966** | **0.965** | **0.963** |
| XGBoost, robust features only | 0.994 | 0.994 | 0.994 | 0.994 | 0.940 | 0.940 | 0.940 | 0.940 |

![CIC-IDS2017 robustness curves](assets/cicids2017/robustness_curves.png)

What the numbers say:

1. **The collapse is real, and unconstrained attacks overstate it.** Textbook (unconstrained)
   attacks drive every undefended model to 0.000-0.032 detection on CIC-IDS2017 at eps=0.5, but
   produce 0 % realisable flows. Under the realistic constraints the undefended XGBoost keeps 42 %,
   almost entirely volume attacks (DoS Hulk 94 %, GoldenEye 64 %, DDoS 57 %) whose server-side
   features the attacker cannot touch; PortScan, slowloris, Slowhttptest, FTP/SSH-Patator, Bot and
   web attacks all go to 0 %. The unconstrained attack is not a strict upper bound, though: on
   UNSW-NB15 the ensemble keeps 0.467 detection at eps=2 against it versus 0.255 against the
   constrained attack, because large unconstrained perturbations trip the autoencoder; our
   attacks are strong but not optimal (see Limitations).
2. **The most important feature is attacker-controlled.** TreeSHAP ranks `init_win_fwd` (client TCP
   window) first on CIC-IDS2017 and `sttl` (source IP TTL, a known UNSW-NB15 testbed artefact) first
   on UNSW-NB15. Controlling *only* `sttl` drops UNSW XGBoost detection to 0.2 %; controlling only
   `init_win_fwd` drops CIC detection to 48 %.
3. **Hardening works at little clean cost.** Adversarial training keeps clean F1 within 0.001
   (CIC XGBoost 0.9942 -> 0.9932) and restores constrained detection to 80-96 %. Restricting the
   model to attacker-immutable features makes it immune to this attacker by construction, for a
   clean FPR of 2.6 % instead of 0.35 % on CIC.
4. **Base rates matter more than the leaderboard.** XGBoost's 99.7 % accuracy and 0.35 % FPR mean
   only **22 % of its alerts are real at a 0.1 % attack prevalence**; on UNSW-NB15 (26 % FPR on the
   official test split) that falls to 0.4 %.

| study | CIC-IDS2017 | UNSW-NB15 |
|---|---|---|
| Counterfactuals: XGBoost alerts with a realisable evasion within eps=2 | 59.5 % (1.71 features changed, median eps 0.031) | 98.5 % (2.16 features) |
| ...same, against the adversarially-trained ensemble | 6.0 % | 0.5 % |
| Adversarial-input alarm, static attacker (ROC-AUC / FPR) | 1.000 / 0.9 % | 1.000 / 1.3 % |
| ...detector-aware adaptive attacker vs. XGBoost OR alarm (detection at eps=2) | 0.880 (XGBoost alone: 0.417), benign FPR 2.3 % | 0.998 (XGBoost alone: 0.000), benign FPR 27.3 % (XGBoost alone: 25.9 %) |
| Backdoor, 2 % poisoned training flows: success rate clean -> poisoned -> sanitised | 0.33 -> **1.00** -> 0.52 | 0.04 -> **1.00** -> 0.76 |
| Poison recall / precision of robust-feature kNN sanitiser | 0.81 / 0.71 | 0.93 / 0.38 |

**Drift (CIC-IDS2017, train Monday-Wednesday, test Thursday-Friday).** Supervised models do not
generalise to unseen attack families: XGBoost recall is 0.6 % on PortScan, 0 % on Bot, 1.4 % on web
brute force, 0 % on Infiltration. The benign-trained autoencoder catches 81 % of Infiltration
flows, which is why the ensemble ORs it in (at 3.2 % FPR instead of 0.04 %).

## Full results

Complete generated reports, including per-family tables, SHAP rankings, single-feature
exploitability, counterfactual statistics, poisoning and drift tables:
[CIC-IDS2017](https://github.com/rakshit-737/feint/blob/main/results/cicids2017/report.md) · [UNSW-NB15](https://github.com/rakshit-737/feint/blob/main/results/unsw_nb15/report.md).

**Clean detection vs. baselines and published numbers**

| model | CIC acc | CIC F1 | CIC FPR | CIC prec @0.1 % | UNSW acc | UNSW F1 | UNSW FPR |
|---|---|---|---|---|---|---|---|
| Logistic regression | 0.8925 | 0.7833 | 0.0607 | 0.012 | 0.8128 | 0.8512 | 0.3832 |
| Random forest | 0.9963 | 0.9928 | 0.0032 | 0.236 | 0.8643 | 0.8874 | 0.2661 |
| IsolationForest (unsupervised) | 0.7420 | 0.0420 | 0.0093 | 0.002 | 0.4459 | 0.0108 | 0.0146 |
| Autoencoder (unsupervised) | 0.7611 | 0.1751 | 0.0100 | 0.010 | 0.5857 | 0.4167 | 0.0259 |
| MLP | 0.9925 | 0.9854 | 0.0064 | 0.134 | 0.8566 | 0.8817 | 0.2822 |
| XGBoost | **0.9970** | **0.9942** | 0.0035 | 0.223 | **0.8655** | **0.8879** | 0.2593 |
| FEINT ensemble | 0.9894 | 0.9797 | 0.0133 | 0.070 | 0.8568 | 0.8820 | 0.2848 |
| FEINT ensemble + adv. training | 0.9890 | 0.9790 | 0.0137 | 0.068 | 0.8610 | 0.8847 | 0.2707 |
| XGBoost, robust features only | 0.9793 | 0.9611 | 0.0257 | 0.037 | 0.8165 | 0.8493 | 0.3338 |
| *Published: RF, Sharafaldin et al. 2018, Table 4 (all 80 features, weighted P/R/F1)* | | *0.97* | | | | | |
| *Published: decision tree, Moustafa & Slay 2016 [^ms16] (FAR 15.78 %)* | | | | | *0.8556* | | |

Our clean numbers are in line with the literature: on CIC-IDS2017 with 11 of the ~80 CICFlowMeter
features and de-duplicated data, XGBoost reaches F1 0.994; on the UNSW-NB15 official split the
well-known ~13-15 % accuracy gap between the training and testing distributions reproduces
(XGBoost 86.6 % vs. the published 85.6 % decision tree). Published numbers use different feature
sets and preprocessing and are shown for orientation, not as a controlled comparison.
The Sharafaldin et al. figure (RF: Pr 0.98, Rc 0.97, F1 0.97) was checked against Table 4 of the
ICISSP 2018 paper; the Moustafa & Slay figure (DT: 85.56 % accuracy, 15.78 % FAR) was checked
against secondary sources only, as the paper itself is paywalled.

[^ms16]: N. Moustafa, J. Slay. *The evaluation of Network Anomaly Detection Systems: Statistical
    analysis of the UNSW-NB15 data set and the comparison with the KDD99 data set.* Information
    Security Journal: A Global Perspective 25(1-3), 2016.

![UNSW-NB15 robustness curves](assets/unsw_nb15/robustness_curves.png)

| CIC-IDS2017 global importance | CIC-IDS2017 drift |
|---|---|
| ![SHAP](assets/cicids2017/shap_importance.png) | ![drift](assets/cicids2017/drift_recall.png) |

## Prior art

| work | what it does | FEINT's difference |
|---|---|---|
| Thousands of CIC-IDS / NSL-KDD classifier repos | Train, report accuracy | Robustness curves, adaptive attacks, base-rate precision, drift, poisoning |
| IBM Adversarial Robustness Toolbox | Attack / defence primitives | End-to-end NIDS study; attacks are *schema-constrained* inside the loop and adaptive against the full ensemble ([ADR 0003](adr/0003-own-attack-engine-instead-of-art.md)) |
| Kitsune (Mirsky et al., NDSS 2018) | Online autoencoder NIDS | Uses an autoencoder member, but the study is about adaptive-adversary robustness |
| Constrained / feasible evasion research (e.g. Sheatsley et al. 2022; Chernikova & Oprea, FENCE 2022; Apruzzese et al. 2022; Pierazzi et al., S&P 2020 on problem-space attacks) | Show that realistic constraints change robustness conclusions | FEINT is a reproducible, tested, two-dataset implementation of that methodology with hardening, counterfactual explanations and poisoning in one pipeline, not a new algorithm |
| SHAP / LIME / DiCE | Generic explainers | Counterfactuals obey the same network constraints as the red team, so "what would evade this alert" is a realisable answer |

**Honest gap:** the attack primitives, datasets and explainers all exist. FEINT's contribution is the
disciplined end-to-end study and its honesty rules: realisable perturbations only, adaptive attacks
against the *defended* system, monotone curves, fixed-prevalence precision, and published limitations.


## Seed variance and model stealing (v1.0.0)

### Multi-seed robustness: cicids2017

Seeds [0, 1, 2] (n=3); mean with 95 % Student-t CI across seeds. Constrained adaptive attack, detection rate on held-out attack flows (higher is better).

| model | clean F1 | FPR | eps=0.0 | eps=0.5 | eps=1.0 | eps=2.0 |
|---|---|---|---|---|---|---|
| mlp | 0.986 [0.984, 0.987] | 0.007 [0.006, 0.007] | 0.991 [0.989, 0.992] | 0.507 [0.357, 0.657] | 0.329 [0.247, 0.411] | 0.100 [0.000, 0.202] |
| random_forest | 0.992 [0.992, 0.993] | 0.004 [0.003, 0.004] | 0.995 [0.993, 0.996] | 0.466 [0.375, 0.557] | 0.418 [0.389, 0.448] | 0.390 [0.364, 0.416] |
| xgboost | 0.994 [0.992, 0.995] | 0.004 [0.003, 0.005] | 0.998 [0.997, 1.000] | 0.470 [0.387, 0.554] | 0.435 [0.400, 0.470] | 0.405 [0.379, 0.431] |
| ensemble | 0.979 [0.976, 0.981] | 0.014 [0.012, 0.016] | 0.997 [0.995, 0.999] | 0.545 [0.432, 0.658] | 0.476 [0.445, 0.508] | 0.422 [0.340, 0.503] |
| xgboost_robust_features | 0.960 [0.954, 0.965] | 0.026 [0.024, 0.028] | 0.992 [0.984, 1.000] | 0.992 [0.984, 1.000] | 0.992 [0.984, 1.000] | 0.992 [0.984, 1.000] |

Per-seed binomial (Wilson) 95 % interval half-width at n=1000 evaluated flows is at most 0.031.


### Multi-seed robustness: unsw_nb15

Seeds [0, 1, 2] (n=3); mean with 95 % Student-t CI across seeds. Constrained adaptive attack, detection rate on held-out attack flows (higher is better).

| model | clean F1 | FPR | eps=0.0 | eps=0.5 | eps=1.0 | eps=2.0 |
|---|---|---|---|---|---|---|
| mlp | 0.880 [0.873, 0.888] | 0.283 [0.255, 0.311] | 0.970 [0.962, 0.979] | 0.421 [0.360, 0.482] | 0.187 [0.132, 0.243] | 0.070 [0.044, 0.096] |
| random_forest | 0.888 [0.887, 0.889] | 0.266 [0.262, 0.269] | 0.972 [0.953, 0.991] | 0.689 [0.557, 0.821] | 0.147 [0.101, 0.193] | 0.000 [0.000, 0.002] |
| xgboost | 0.888 [0.887, 0.889] | 0.261 [0.257, 0.264] | 0.968 [0.953, 0.983] | 0.179 [0.149, 0.208] | 0.138 [0.110, 0.166] | 0.001 [0.000, 0.002] |
| ensemble | 0.881 [0.877, 0.885] | 0.286 [0.272, 0.301] | 0.973 [0.959, 0.986] | 0.580 [0.337, 0.824] | 0.462 [0.345, 0.579] | 0.375 [0.224, 0.527] |
| xgboost_robust_features | 0.850 [0.848, 0.852] | 0.334 [0.329, 0.339] | 0.942 [0.918, 0.966] | 0.942 [0.918, 0.966] | 0.942 [0.918, 0.966] | 0.942 [0.918, 0.966] |

Per-seed binomial (Wilson) 95 % interval half-width at n=1000 evaluated flows is at most 0.031.


Across three seeds the undefended models' constrained detection varies by up to ±0.24 (UNSW ensemble at
eps=0.5), far more than the ±0.03 binomial error of a single run: single-seed robustness numbers
(including the headline table above, seed 0) should be read with that spread in mind. The ordering
holds: robust-feature XGBoost > ensemble > single models at eps=2 on both datasets; on CIC-IDS2017 the
ensemble's advantage over XGBoost at eps>=1 is within the seed CI.

### Model stealing (label-only queries -> transfer attack)

Victim: xgboost; 1000 held-out attack flows; transfer = constrained PGD on the surrogate, no score queries to the victim. Victim detection rate (higher is better for the defender).

| surrogate | test agreement | eps=0.0 | eps=0.5 | eps=1.0 | eps=2.0 |
|---|---|---|---|---|---|
| true labels, full training set | 0.937 | 0.965 | 0.544 | 0.400 | 0.245 |
| stolen, 500 label queries | 0.785 | 0.965 | 0.568 | 0.329 | 0.178 |
| stolen, 2000 label queries | 0.914 | 0.965 | 0.435 | 0.360 | 0.001 |
| stolen, 10000 label queries | 0.918 | 0.965 | 0.514 | 0.422 | 0.001 |

A label-only API leaks enough: with 2,000 hard-label queries the stolen MLP agrees with the victim on
91 % of test flows, and pure transfer from it (no score queries) drives XGBoost detection to 0.001 at
eps=2, *stronger* than transfer from an MLP trained on the true labels (0.245), because the stolen copy
imitates the victim's decision boundary rather than the ground truth. Single seed.
