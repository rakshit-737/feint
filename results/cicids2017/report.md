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
| XGBoost | 0.9970 | 0.9900 | 0.9984 | 0.9942 | 0.9999 | 0.9997 | 0.0035 | 0.743 | 0.223 |
| Autoencoder | 0.7611 | 0.7732 | 0.0987 | 0.1751 | 0.9103 | 0.7438 | 0.0100 | 0.091 | 0.010 |
| FEINT ensemble | 0.9894 | 0.9628 | 0.9971 | 0.9797 | 0.9995 | 0.9989 | 0.0133 | 0.431 | 0.070 |
| MLP + adv. training | 0.9928 | 0.9808 | 0.9913 | 0.9860 | 0.9995 | 0.9986 | 0.0067 | 0.599 | 0.129 |
| XGBoost + adv. training | 0.9965 | 0.9885 | 0.9981 | 0.9932 | 0.9999 | 0.9996 | 0.0040 | 0.715 | 0.199 |
| FEINT ensemble + adv. training | 0.9890 | 0.9617 | 0.9969 | 0.9790 | 0.9995 | 0.9988 | 0.0137 | 0.423 | 0.068 |
| XGBoost, robust features only | 0.9793 | 0.9303 | 0.9940 | 0.9611 | 0.9969 | 0.9871 | 0.0257 | 0.281 | 0.037 |

## Detection rate under constrained adaptive evasion (attack flows)

| model | eps=0 | eps=0.25 | eps=0.5 | eps=1 | eps=1.5 | eps=2 | area | valid flows @max eps |
|---|---|---|---|---|---|---|---|---|
| MLP | 0.991 | 0.787 | 0.576 | 0.349 | 0.159 | 0.123 | 0.411 | 1.000 |
| XGBoost | 0.999 | 0.514 | 0.498 | 0.451 | 0.418 | 0.417 | 0.489 | 1.000 |
| Random forest | 0.995 | 0.610 | 0.507 | 0.435 | 0.397 | 0.397 | 0.491 | 1.000 |
| FEINT ensemble | 0.998 | 0.744 | 0.590 | 0.491 | 0.412 | 0.400 | 0.542 | 1.000 |
| MLP + adv. training | 0.991 | 0.884 | 0.857 | 0.779 | 0.741 | 0.732 | 0.805 | 1.000 |
| XGBoost + adv. training | 1.000 | 0.808 | 0.806 | 0.805 | 0.803 | 0.803 | 0.817 | 1.000 |
| FEINT ensemble + adv. training | 0.998 | 0.874 | 0.860 | 0.840 | 0.834 | 0.830 | 0.855 | 1.000 |
| XGBoost, robust features only | 0.994 | 0.994 | 0.994 | 0.994 | 0.994 | 0.994 | 0.994 | 1.000 |

## Detection rate under unconstrained adaptive evasion (attack flows)

| model | eps=0 | eps=0.25 | eps=0.5 | eps=1 | eps=1.5 | eps=2 | area | valid flows @max eps |
|---|---|---|---|---|---|---|---|---|
| MLP | 0.991 | 0.028 | 0.000 | 0.000 | 0.000 | 0.000 | 0.065 | 0.000 |
| XGBoost | 0.999 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.062 | 0.000 |
| FEINT ensemble | 0.998 | 0.093 | 0.032 | 0.026 | 0.024 | 0.024 | 0.096 | 0.000 |

## Per attack family (XGBoost, constrained eps=2)

| family | n | clean detection | adversarial detection |
|---|---|---|---|
| DoS Hulk | 269 | 1.000 | 0.941 |
| DDoS | 191 | 1.000 | 0.565 |
| PortScan | 121 | 0.992 | 0.000 |
| DoS slowloris | 91 | 1.000 | 0.000 |
| DoS GoldenEye | 87 | 1.000 | 0.644 |
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
| init_win_fwd | 0.480 |
| duration | 0.834 |
| fwd_bytes | 0.848 |
| fwd_pkts | 0.863 |
| fwd_pkt_len_max | 0.999 |

## Global feature importance (XGBoost, mean |TreeSHAP|, log-odds)

| feature | mean abs SHAP | attacker-controllable |
|---|---|---|
| init_win_fwd | 1.942 | yes |
| dst_port | 1.802 |  |
| bwd_pkt_len_max | 1.707 |  |
| init_win_bwd | 1.527 |  |
| fwd_bytes | 0.966 | yes |
| mean_iat | 0.660 |  |
| bwd_bytes | 0.624 |  |
| pkt_ratio | 0.568 |  |
| duration | 0.484 | yes |
| fwd_bpp | 0.451 |  |
| bwd_pkts | 0.352 |  |
| bytes_per_s | 0.330 |  |
| fwd_pkt_len_max | 0.298 | yes |
| fwd_pkts | 0.282 | yes |
| syn_count | 0.042 |  |

## Counterfactual explanations (XGBoost alerts)

- 200 flagged attack flows; realisable counterfactual found for 59.5% (validity under schema: 100.0%)
- mean controllable features changed: 1.71; median budget: 0.031
- features used: {'init_win_fwd': 113, 'fwd_pkts': 51, 'duration': 24, 'fwd_pkt_len_max': 9, 'fwd_bytes': 7}
- hardened ensemble: counterfactual found for 6.0% of its alerts

Examples:

- no realisable evasion within budget: this alert is robust to the modelled attacker
- flip to benign by: init_win_fwd 1024 -> 901
- flip to benign by: fwd_pkts 9 -> 10; init_win_fwd 2.92e+04 -> 3.015e+04
- no realisable evasion within budget: this alert is robust to the modelled attacker
- no realisable evasion within budget: this alert is robust to the modelled attacker

## Adversarial-input detector

Trained on 2791 successful constrained evasions (eps 0.5/1/2) of training flows.

| test budget | evasions | ROC-AUC | TPR | FPR on clean |
|---|---|---|---|---|
| 1.0 | 549 | 1.000 | 1.000 | 0.009 |
| 1.5 | 582 | 1.000 | 1.000 | 0.009 |

Detector-aware adaptive attacker (eps=2) against XGBoost OR adv-input alarm: detection 0.880 (XGBoost alone would miss 0.182 of these flows); guarded FPR on benign 0.0230. The static AUC above is therefore optimistic: it only holds against attackers unaware of the alarm.

## Backdoor poisoning

2000 poisoned flows (2% of training): malicious flows with `init_win_fwd = 65528`, labelled benign.

| model | clean acc. | recall (clean attacks) | recall (triggered attacks) | backdoor success |
|---|---|---|---|---|
| clean model | 0.9969 | 0.9983 | 0.6739 | 0.3261 |
| poisoned model | 0.9968 | 0.9983 | 0.0000 | 1.0000 |
| sanitized model | 0.9965 | 0.9985 | 0.4834 | 0.5166 |

Robust-feature kNN sanitiser flagged 2267 training flows: poison recall 0.809, precision 0.714, clean benign removed 0.0087.

## Temporal drift / unseen attack families

Train on Monday, Tuesday, Wednesday; test on Thursday, Friday. Families seen in training: DoS GoldenEye, DoS Hulk, DoS Slowhttptest, DoS slowloris, FTP-Patator, Heartbleed, SSH-Patator.

| test family | n | XGBoost | Autoencoder | Ensemble |
|---|---|---|---|---|
| DDoS | 12746 | 0.626 | 0.208 | 0.631 |
| PortScan | 9074 | 0.006 | 0.000 | 0.005 |
| Bot | 1940 | 0.000 | 0.016 | 0.016 |
| Web Attack - Brute Force | 1469 | 0.014 | 0.048 | 0.049 |
| Web Attack - XSS | 651 | 0.012 | 0.025 | 0.031 |
| Infiltration | 36 | 0.000 | 0.806 | 0.806 |
| Web Attack - Sql Injection | 21 | 0.476 | 0.000 | 0.333 |
| benign FPR | | 0.0004 | 0.0320 | 0.0323 |

## Timings (s)

train_members: 813.99, train_baselines: 72.11, adv_training: 1126.94, robust_features: 126.28, robustness_curves: 587.37, feature_robustness: 33.7, explain: 94.4, adv_input_detector: 60.17, poisoning: 270.26, drift: 339.88
