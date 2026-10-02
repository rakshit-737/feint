# FEINT robustness report: cicids2017

- split: stratified random 70/30; train 177,281 / test 75,978 flows; attack prevalence in test 25.7%
- attacker-controllable features: duration, fwd_pkts, fwd_bytes, fwd_pkt_len_max, init_win_fwd
- robust (attacker-immutable) features: bwd_pkts, bwd_bytes, bwd_pkt_len_max, syn_count, dst_port, init_win_bwd
- attacked flows per curve point: 1000

## Clean detection (held-out test set)

| model | acc | prec | recall | F1 | ROC-AUC | PR-AUC | FPR | prec @1% prev. | prec @0.1% prev. |
|---|---|---|---|---|---|---|---|---|---|
| Logistic regression | 0.8925 | 0.8117 | 0.7568 | 0.7833 | 0.9308 | 0.8210 | 0.0607 | 0.112 | 0.012 |
| Random forest | 0.9963 | 0.9907 | 0.9949 | 0.9928 | 0.9998 | 0.9995 | 0.0032 | 0.757 | 0.236 |
| IsolationForest | 0.7420 | 0.4512 | 0.0220 | 0.0420 | 0.8510 | 0.5546 | 0.0093 | 0.023 | 0.002 |
| MLP | 0.9925 | 0.9816 | 0.9892 | 0.9854 | 0.9995 | 0.9987 | 0.0064 | 0.610 | 0.134 |
| XGBoost | 0.9970 | 0.9898 | 0.9986 | 0.9942 | 0.9999 | 0.9997 | 0.0035 | 0.740 | 0.220 |
| Autoencoder | 0.7611 | 0.7732 | 0.0987 | 0.1751 | 0.9103 | 0.7438 | 0.0100 | 0.091 | 0.010 |
| FEINT ensemble | 0.9892 | 0.9627 | 0.9968 | 0.9794 | 0.9995 | 0.9989 | 0.0134 | 0.430 | 0.070 |
| MLP + adv. training | 0.9928 | 0.9808 | 0.9913 | 0.9860 | 0.9995 | 0.9986 | 0.0067 | 0.599 | 0.129 |
| XGBoost + adv. training | 0.9966 | 0.9889 | 0.9979 | 0.9934 | 0.9999 | 0.9997 | 0.0039 | 0.722 | 0.205 |
| FEINT ensemble + adv. training | 0.9889 | 0.9616 | 0.9967 | 0.9789 | 0.9995 | 0.9988 | 0.0137 | 0.423 | 0.068 |
| XGBoost, robust features only | 0.9794 | 0.9308 | 0.9937 | 0.9612 | 0.9969 | 0.9872 | 0.0255 | 0.282 | 0.037 |

## Detection rate under constrained adaptive evasion (attack flows)

| model | eps=0 | eps=0.25 | eps=0.5 | eps=1 | eps=1.5 | eps=2 | area | valid flows @max eps |
|---|---|---|---|---|---|---|---|---|
| MLP | 0.991 | 0.787 | 0.576 | 0.349 | 0.159 | 0.123 | 0.411 | 1.000 |
| XGBoost | 0.999 | 0.510 | 0.481 | 0.438 | 0.406 | 0.400 | 0.477 | 1.000 |
| Random forest | 0.995 | 0.610 | 0.507 | 0.430 | 0.397 | 0.397 | 0.490 | 1.000 |
| FEINT ensemble | 0.998 | 0.724 | 0.540 | 0.467 | 0.402 | 0.384 | 0.519 | 1.000 |
| MLP + adv. training | 0.991 | 0.884 | 0.857 | 0.779 | 0.741 | 0.732 | 0.805 | 1.000 |
| XGBoost + adv. training | 0.999 | 0.773 | 0.768 | 0.767 | 0.762 | 0.762 | 0.781 | 1.000 |
| FEINT ensemble + adv. training | 0.998 | 0.885 | 0.876 | 0.856 | 0.828 | 0.822 | 0.861 | 1.000 |
| XGBoost, robust features only | 0.995 | 0.995 | 0.995 | 0.995 | 0.995 | 0.995 | 0.995 | 1.000 |

## Detection rate under unconstrained adaptive evasion (attack flows)

| model | eps=0 | eps=0.25 | eps=0.5 | eps=1 | eps=1.5 | eps=2 | area | valid flows @max eps |
|---|---|---|---|---|---|---|---|---|
| MLP | 0.991 | 0.028 | 0.000 | 0.000 | 0.000 | 0.000 | 0.065 | 0.000 |
| XGBoost | 0.999 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.062 | 0.000 |
| FEINT ensemble | 0.998 | 0.107 | 0.044 | 0.039 | 0.034 | 0.034 | 0.107 | 0.000 |

## Per attack family (XGBoost, constrained eps=2)

| family | n | clean detection | adversarial detection |
|---|---|---|---|
| DoS Hulk | 269 | 1.000 | 0.941 |
| DDoS | 191 | 1.000 | 0.565 |
| PortScan | 121 | 0.992 | 0.000 |
| DoS slowloris | 91 | 1.000 | 0.000 |
| DoS GoldenEye | 87 | 1.000 | 0.471 |
| DoS Slowhttptest | 76 | 1.000 | 0.000 |
| FTP-Patator | 57 | 1.000 | 0.000 |
| SSH-Patator | 52 | 1.000 | 0.000 |
| Bot | 25 | 1.000 | 0.000 |
| Web Attack - Brute Force | 23 | 1.000 | 0.000 |
| Web Attack - XSS | 7 | 1.000 | 0.000 |
| Infiltration | 1 | 1.000 | 0.000 |

## Which controllable features are exploitable? (XGBoost, one feature at a time, eps=2)

| attacker controls only | detection rate |
|---|---|
| init_win_fwd | 0.474 |
| fwd_pkts | 0.780 |
| duration | 0.839 |
| fwd_bytes | 0.848 |
| fwd_pkt_len_max | 0.999 |

## Global feature importance (XGBoost, mean |TreeSHAP|, log-odds)

| feature | mean abs SHAP | attacker-controllable |
|---|---|---|
| init_win_fwd | 2.279 | yes |
| dst_port | 2.082 |  |
| bwd_pkt_len_max | 1.549 |  |
| init_win_bwd | 1.290 |  |
| fwd_bytes | 0.746 | yes |
| mean_iat | 0.662 |  |
| bwd_bytes | 0.622 |  |
| pkt_ratio | 0.572 |  |
| duration | 0.469 | yes |
| bwd_pkts | 0.462 |  |
| fwd_bpp | 0.378 |  |
| fwd_pkt_len_max | 0.309 | yes |
| fwd_pkts | 0.307 | yes |
| bytes_per_s | 0.290 |  |
| syn_count | 0.047 |  |

## Counterfactual explanations (XGBoost alerts)

- 200 flagged attack flows; realisable counterfactual found for 60.0% (validity under schema: 100.0%)
- mean controllable features changed: 2.07; median budget: 0.031
- features used: {'init_win_fwd': 108, 'fwd_pkts': 46, 'duration': 35, 'fwd_pkt_len_max': 32, 'fwd_bytes': 27}
- hardened ensemble: counterfactual found for 7.5% of its alerts

Examples:

- no realisable evasion within budget: this alert is robust to the modelled attacker
- flip to benign by: fwd_bytes 2 -> 3; fwd_pkt_len_max 2 -> 3
- flip to benign by: duration 8.398 -> 10.1; fwd_pkts 9 -> 10; fwd_bytes 102 -> 129; init_win_fwd 2.92e+04 -> 4.3e+04
- no realisable evasion within budget: this alert is robust to the modelled attacker
- flip to benign by: duration 10.44 -> 330.6; fwd_pkts 5 -> 13; init_win_fwd 2.92e+04 -> 6.554e+04

## Adversarial-input detector

Trained on 2839 successful constrained evasions (eps 0.5/1/2) of training flows.

| test budget | evasions | ROC-AUC | TPR | FPR on clean |
|---|---|---|---|---|
| 1.0 | 562 | 1.000 | 1.000 | 0.012 |
| 1.5 | 591 | 1.000 | 1.000 | 0.012 |

Detector-aware adaptive attacker (eps=2) against XGBoost OR adv-input alarm: detection 0.876 (XGBoost alone would miss 0.233 of these flows); guarded FPR on benign 0.0280. The static AUC above is therefore optimistic: it only holds against attackers unaware of the alarm.

## Backdoor poisoning

2000 poisoned flows (2% of training): malicious flows with `init_win_fwd = 65528`, labelled benign.

| model | clean acc. | recall (clean attacks) | recall (triggered attacks) | backdoor success |
|---|---|---|---|---|
| clean model | 0.9969 | 0.9983 | 0.6928 | 0.3072 |
| poisoned model | 0.9968 | 0.9980 | 0.0000 | 1.0000 |
| sanitized model | 0.9862 | 0.9992 | 0.9466 | 0.0534 |

Robust-feature kNN sanitiser flagged 3901 training flows: poison recall 0.992, precision 0.509, clean benign removed 0.0258.

## Temporal drift / unseen attack families

Train on Monday, Tuesday, Wednesday; test on Thursday, Friday. Families seen in training: DoS GoldenEye, DoS Hulk, DoS Slowhttptest, DoS slowloris, FTP-Patator, Heartbleed, SSH-Patator.

| test family | n | XGBoost | Autoencoder | Ensemble |
|---|---|---|---|---|
| DDoS | 12746 | 0.626 | 0.208 | 0.632 |
| PortScan | 9074 | 0.005 | 0.000 | 0.005 |
| Bot | 1940 | 0.000 | 0.016 | 0.016 |
| Web Attack - Brute Force | 1469 | 0.002 | 0.048 | 0.049 |
| Web Attack - XSS | 651 | 0.009 | 0.025 | 0.029 |
| Infiltration | 36 | 0.000 | 0.806 | 0.806 |
| Web Attack - Sql Injection | 21 | 0.381 | 0.000 | 0.238 |
| benign FPR | | 0.0003 | 0.0320 | 0.0323 |

## Timings (s)

train_members: 19.2, train_baselines: 8.17, adv_training: 63.41, robust_features: 1.39, robustness_curves: 51.61, feature_robustness: 2.91, explain: 5.27, adv_input_detector: 4.34, poisoning: 8.43, drift: 15.56
