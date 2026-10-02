# FEINT robustness report: cicids2017-corrected

- split: stratified random 70/30; train 78,666 / test 33,715 flows; attack prevalence in test 82.8%
- attacker-controllable features: duration, fwd_pkts, fwd_bytes, fwd_pkt_len_max, init_win_fwd
- robust (attacker-immutable) features: bwd_pkts, bwd_bytes, bwd_pkt_len_max, syn_count, dst_port, init_win_bwd
- attacked flows per curve point: 1000

## Clean detection (held-out test set)

| model | acc | prec | recall | F1 | ROC-AUC | PR-AUC | FPR | prec @1% prev. | prec @0.1% prev. |
|---|---|---|---|---|---|---|---|---|---|
| Logistic regression | 0.9571 | 0.9574 | 0.9923 | 0.9745 | 0.9689 | 0.9890 | 0.2121 | 0.045 | 0.005 |
| Random forest | 0.9997 | 0.9999 | 0.9998 | 0.9998 | 1.0000 | 1.0000 | 0.0005 | 0.951 | 0.659 |
| IsolationForest | 0.1948 | 0.9361 | 0.0294 | 0.0570 | 0.9009 | 0.9617 | 0.0096 | 0.030 | 0.003 |
| MLP | 0.9993 | 0.9996 | 0.9996 | 0.9996 | 0.9999 | 1.0000 | 0.0021 | 0.830 | 0.326 |
| XGBoost | 0.9999 | 0.9999 | 0.9999 | 0.9999 | 1.0000 | 1.0000 | 0.0005 | 0.951 | 0.659 |
| Autoencoder | 0.5436 | 0.9946 | 0.4512 | 0.6207 | 0.9529 | 0.9878 | 0.0119 | 0.277 | 0.037 |
| FEINT ensemble | 0.9978 | 0.9975 | 0.9999 | 0.9987 | 1.0000 | 1.0000 | 0.0122 | 0.452 | 0.076 |
| MLP + adv. training | 0.9979 | 0.9979 | 0.9995 | 0.9987 | 0.9996 | 0.9999 | 0.0100 | 0.503 | 0.091 |
| XGBoost + adv. training | 0.9998 | 0.9999 | 0.9999 | 0.9999 | 1.0000 | 1.0000 | 0.0005 | 0.951 | 0.659 |
| FEINT ensemble + adv. training | 0.9977 | 0.9974 | 0.9999 | 0.9986 | 1.0000 | 1.0000 | 0.0127 | 0.442 | 0.073 |
| XGBoost, robust features only | 0.9987 | 0.9989 | 0.9996 | 0.9992 | 1.0000 | 1.0000 | 0.0055 | 0.647 | 0.154 |

## Detection rate under constrained adaptive evasion (attack flows)

| model | eps=0 | eps=0.25 | eps=0.5 | eps=1 | eps=1.5 | eps=2 | area | valid flows @max eps |
|---|---|---|---|---|---|---|---|---|
| MLP | 1.000 | 0.715 | 0.409 | 0.267 | 0.210 | 0.078 | 0.358 | 1.000 |
| XGBoost | 1.000 | 0.643 | 0.592 | 0.505 | 0.500 | 0.496 | 0.567 | 1.000 |
| Random forest | 1.000 | 0.483 | 0.208 | 0.004 | 0.000 | 0.000 | 0.163 | 1.000 |
| FEINT ensemble | 1.000 | 0.699 | 0.632 | 0.484 | 0.468 | 0.455 | 0.563 | 1.000 |
| MLP + adv. training | 1.000 | 0.996 | 0.995 | 0.994 | 0.986 | 0.986 | 0.992 | 1.000 |
| XGBoost + adv. training | 1.000 | 0.997 | 0.997 | 0.997 | 0.997 | 0.997 | 0.997 | 1.000 |
| FEINT ensemble + adv. training | 1.000 | 1.000 | 1.000 | 1.000 | 0.999 | 0.999 | 1.000 | 1.000 |
| XGBoost, robust features only | 0.999 | 0.999 | 0.999 | 0.999 | 0.999 | 0.999 | 0.999 | 1.000 |

## Detection rate under unconstrained adaptive evasion (attack flows)

| model | eps=0 | eps=0.25 | eps=0.5 | eps=1 | eps=1.5 | eps=2 | area | valid flows @max eps |
|---|---|---|---|---|---|---|---|---|
| MLP | 1.000 | 0.115 | 0.000 | 0.000 | 0.000 | 0.000 | 0.077 | 0.000 |
| XGBoost | 1.000 | 0.039 | 0.000 | 0.000 | 0.000 | 0.000 | 0.067 | 0.000 |
| FEINT ensemble | 1.000 | 0.204 | 0.075 | 0.047 | 0.034 | 0.029 | 0.126 | 0.000 |

## Per attack family (XGBoost, constrained eps=2)

| family | n | clean detection | adversarial detection |
|---|---|---|---|
| DoS Hulk | 205 | 1.000 | 0.995 |
| DDoS | 196 | 1.000 | 0.985 |
| Portscan | 194 | 1.000 | 0.000 |
| Infiltration - Portscan | 167 | 1.000 | 0.000 |
| DoS GoldenEye | 78 | 1.000 | 0.974 |
| DoS Slowloris | 55 | 1.000 | 0.036 |
| FTP-Patator | 41 | 1.000 | 0.000 |
| SSH-Patator | 38 | 1.000 | 0.026 |
| DoS Slowhttptest | 19 | 1.000 | 0.684 |
| Botnet | 7 | 1.000 | 1.000 |

## Which controllable features are exploitable? (XGBoost, one feature at a time, eps=2)

| attacker controls only | detection rate |
|---|---|
| duration | 0.642 |
| fwd_bytes | 0.997 |
| fwd_pkts | 0.999 |
| fwd_pkt_len_max | 1.000 |
| init_win_fwd | 1.000 |

## Global feature importance (XGBoost, mean |TreeSHAP|, log-odds)

| feature | mean abs SHAP | attacker-controllable |
|---|---|---|
| syn_count | 1.632 |  |
| bwd_pkt_len_max | 1.628 |  |
| init_win_bwd | 1.386 |  |
| init_win_fwd | 1.228 | yes |
| bwd_bytes | 1.137 |  |
| dst_port | 1.052 |  |
| mean_iat | 1.037 |  |
| duration | 0.708 | yes |
| fwd_bytes | 0.666 | yes |
| fwd_pkt_len_max | 0.598 | yes |
| bwd_pkts | 0.468 |  |
| fwd_bpp | 0.356 |  |
| pkt_ratio | 0.336 |  |
| fwd_pkts | 0.187 | yes |
| bytes_per_s | 0.154 |  |

## Counterfactual explanations (XGBoost alerts)

- 200 flagged attack flows; realisable counterfactual found for 50.5% (validity under schema: 100.0%)
- mean controllable features changed: 2.27; median budget: 0.031
- features used: {'duration': 86, 'init_win_fwd': 41, 'fwd_pkt_len_max': 40, 'fwd_pkts': 38, 'fwd_bytes': 24}
- hardened ensemble: counterfactual found for 0.0% of its alerts

Examples:

- flip to benign by: duration 5.6e-05 -> 0.04583
- no realisable evasion within budget: this alert is robust to the modelled attacker
- no realisable evasion within budget: this alert is robust to the modelled attacker
- no realisable evasion within budget: this alert is robust to the modelled attacker
- flip to benign by: duration 9.8e-05 -> 0.04587

## Adversarial-input detector

Trained on 2238 successful constrained evasions (eps 0.5/1/2) of training flows.

| test budget | evasions | ROC-AUC | TPR | FPR on clean |
|---|---|---|---|---|
| 1.0 | 495 | 1.000 | 1.000 | 0.009 |
| 1.5 | 500 | 1.000 | 1.000 | 0.009 |

Detector-aware adaptive attacker (eps=2) against XGBoost OR adv-input alarm: detection 1.000 (XGBoost alone would miss 0.001 of these flows); guarded FPR on benign 0.0180. The static AUC above is therefore optimistic: it only holds against attackers unaware of the alarm.

## Backdoor poisoning

1573 poisoned flows (2% of training): malicious flows with `init_win_fwd = 65528`, labelled benign.

| model | clean acc. | recall (clean attacks) | recall (triggered attacks) | backdoor success |
|---|---|---|---|---|
| clean model | 0.9998 | 0.9999 | 0.9997 | 0.0003 |
| poisoned model | 0.9998 | 0.9999 | 0.0001 | 0.9999 |
| sanitized model | 0.9995 | 0.9999 | 0.9999 | 0.0001 |

Robust-feature kNN sanitiser flagged 1706 training flows: poison recall 0.999, precision 0.921, clean benign removed 0.0099.

## Timings (s)

train_members: 11.18, train_baselines: 3.53, adv_training: 30.01, robust_features: 0.6, robustness_curves: 49.1, feature_robustness: 2.61, explain: 2.81, adv_input_detector: 4.15, poisoning: 3.93
