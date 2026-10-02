# FEINT robustness report: unsw_nb15

- split: official train/test partition; train 175,341 / test 82,332 flows; attack prevalence in test 55.1%
- attacker-controllable features: dur, spkts, sbytes, sttl, swin
- robust (attacker-immutable) features: dpkts, dbytes, dttl, dwin, trans_depth, ct_srv_src, ct_dst_ltm, ct_src_ltm, ct_srv_dst, proto_tcp, proto_udp, dmean
- attacked flows per curve point: 1000

## Clean detection (held-out test set)

| model | acc | prec | recall | F1 | ROC-AUC | PR-AUC | FPR | prec @1% prev. | prec @0.1% prev. |
|---|---|---|---|---|---|---|---|---|---|
| Logistic regression | 0.8128 | 0.7567 | 0.9729 | 0.8513 | 0.9095 | 0.9141 | 0.3833 | 0.025 | 0.003 |
| Random forest | 0.8643 | 0.8172 | 0.9708 | 0.8874 | 0.9752 | 0.9811 | 0.2661 | 0.036 | 0.004 |
| IsolationForest | 0.4459 | 0.3161 | 0.0055 | 0.0108 | 0.8082 | 0.7817 | 0.0146 | 0.004 | 0.000 |
| MLP | 0.8566 | 0.8081 | 0.9700 | 0.8817 | 0.9683 | 0.9757 | 0.2822 | 0.034 | 0.003 |
| XGBoost | 0.8654 | 0.8199 | 0.9681 | 0.8879 | 0.9769 | 0.9833 | 0.2605 | 0.036 | 0.004 |
| Autoencoder | 0.5857 | 0.9271 | 0.2687 | 0.4167 | 0.7338 | 0.7796 | 0.0259 | 0.095 | 0.010 |
| FEINT ensemble | 0.8566 | 0.8067 | 0.9727 | 0.8820 | 0.9738 | 0.9807 | 0.2856 | 0.033 | 0.003 |
| MLP + adv. training | 0.8641 | 0.8231 | 0.9594 | 0.8861 | 0.9653 | 0.9728 | 0.2526 | 0.037 | 0.004 |
| XGBoost + adv. training | 0.8645 | 0.8183 | 0.9689 | 0.8873 | 0.9771 | 0.9834 | 0.2635 | 0.036 | 0.004 |
| FEINT ensemble + adv. training | 0.8605 | 0.8135 | 0.9687 | 0.8844 | 0.9728 | 0.9798 | 0.2720 | 0.035 | 0.004 |
| XGBoost, robust features only | 0.8159 | 0.7755 | 0.9368 | 0.8485 | 0.9275 | 0.9405 | 0.3324 | 0.028 | 0.003 |

## Detection rate under constrained adaptive evasion (attack flows)

| model | eps=0 | eps=0.25 | eps=0.5 | eps=1 | eps=1.5 | eps=2 | area | valid flows @max eps |
|---|---|---|---|---|---|---|---|---|
| MLP | 0.967 | 0.642 | 0.398 | 0.173 | 0.110 | 0.056 | 0.293 | 1.000 |
| XGBoost | 0.965 | 0.162 | 0.157 | 0.149 | 0.000 | 0.000 | 0.147 | 1.000 |
| Random forest | 0.968 | 0.930 | 0.623 | 0.163 | 0.071 | 0.000 | 0.352 | 1.000 |
| FEINT ensemble | 0.970 | 0.591 | 0.477 | 0.423 | 0.278 | 0.264 | 0.432 | 1.000 |
| MLP + adv. training | 0.957 | 0.935 | 0.925 | 0.907 | 0.868 | 0.865 | 0.902 | 1.000 |
| XGBoost + adv. training | 0.963 | 0.961 | 0.958 | 0.957 | 0.947 | 0.947 | 0.954 | 1.000 |
| FEINT ensemble + adv. training | 0.967 | 0.965 | 0.962 | 0.962 | 0.958 | 0.958 | 0.961 | 1.000 |
| XGBoost, robust features only | 0.943 | 0.943 | 0.943 | 0.943 | 0.943 | 0.943 | 0.943 | 1.000 |

## Detection rate under unconstrained adaptive evasion (attack flows)

| model | eps=0 | eps=0.25 | eps=0.5 | eps=1 | eps=1.5 | eps=2 | area | valid flows @max eps |
|---|---|---|---|---|---|---|---|---|
| MLP | 0.967 | 0.163 | 0.005 | 0.000 | 0.000 | 0.000 | 0.082 | 0.000 |
| XGBoost | 0.965 | 0.050 | 0.019 | 0.000 | 0.000 | 0.000 | 0.070 | 0.000 |
| FEINT ensemble | 0.970 | 0.432 | 0.362 | 0.354 | 0.353 | 0.353 | 0.403 | 0.000 |

## Per attack family (XGBoost, constrained eps=2)

| family | n | clean detection | adversarial detection |
|---|---|---|---|
| Generic | 430 | 1.000 | 0.000 |
| Exploits | 235 | 0.996 | 0.000 |
| Fuzzers | 134 | 0.754 | 0.000 |
| DoS | 90 | 1.000 | 0.000 |
| Reconnaissance | 69 | 1.000 | 0.000 |
| Backdoor | 19 | 1.000 | 0.000 |
| Analysis | 15 | 0.933 | 0.000 |
| Shellcode | 7 | 1.000 | 0.000 |
| Worms | 1 | 1.000 | 0.000 |

## Which controllable features are exploitable? (XGBoost, one feature at a time, eps=2)

| attacker controls only | detection rate |
|---|---|
| sttl | 0.002 |
| spkts | 0.686 |
| sbytes | 0.851 |
| dur | 0.949 |
| swin | 0.950 |

## Global feature importance (XGBoost, mean |TreeSHAP|, log-odds)

| feature | mean abs SHAP | attacker-controllable |
|---|---|---|
| sttl | 2.912 | yes |
| sbytes | 1.130 | yes |
| smean | 0.841 |  |
| dload | 0.572 |  |
| ct_srv_dst | 0.420 |  |
| ct_srv_src | 0.329 |  |
| swin | 0.312 | yes |
| ct_dst_ltm | 0.309 |  |
| rate | 0.307 |  |
| ct_src_ltm | 0.254 |  |
| dbytes | 0.250 |  |
| dttl | 0.239 |  |
| dmean | 0.195 |  |
| spkts | 0.192 | yes |
| dur | 0.124 | yes |
| proto_udp | 0.121 |  |
| dpkts | 0.118 |  |
| sload | 0.109 |  |
| trans_depth | 0.104 |  |
| sinpkt | 0.103 |  |
| proto_tcp | 0.026 |  |
| dwin | 0.002 |  |

## Counterfactual explanations (XGBoost alerts)

- 200 flagged attack flows; realisable counterfactual found for 99.5% (validity under schema: 100.0%)
- mean controllable features changed: 2.09; median budget: 0.031
- features used: {'sttl': 184, 'sbytes': 130, 'dur': 88, 'spkts': 13}
- hardened ensemble: counterfactual found for 0.5% of its alerts

Examples:

- flip to benign by: sbytes 114 -> 154; sttl 254 -> 250
- flip to benign by: sttl 254 -> 61
- flip to benign by: dur 7e-06 -> 0.0102; sbytes 114 -> 154; sttl 254 -> 250
- flip to benign by: dur 7e-06 -> 0.0205; sbytes 200 -> 211; sttl 254 -> 246
- flip to benign by: sttl 254 -> 50

## Adversarial-input detector

Trained on 4341 successful constrained evasions (eps 0.5/1/2) of training flows.

| test budget | evasions | ROC-AUC | TPR | FPR on clean |
|---|---|---|---|---|
| 1.0 | 842 | 1.000 | 1.000 | 0.017 |
| 1.5 | 1000 | 1.000 | 1.000 | 0.017 |

Detector-aware adaptive attacker (eps=2) against XGBoost OR adv-input alarm: detection 1.000 (XGBoost alone would miss 0.005 of these flows); guarded FPR on benign 0.2830. The static AUC above is therefore optimistic: it only holds against attackers unaware of the alarm.

## Backdoor poisoning

2000 poisoned flows (2% of training): malicious flows with `sttl = 248`, labelled benign.

| model | clean acc. | recall (clean attacks) | recall (triggered attacks) | backdoor success |
|---|---|---|---|---|
| clean model | 0.8652 | 0.9689 | 0.9593 | 0.0407 |
| poisoned model | 0.8658 | 0.9685 | 0.0000 | 1.0000 |
| sanitized model | 0.8416 | 0.9799 | 0.2577 | 0.7423 |

Robust-feature kNN sanitiser flagged 5266 training flows: poison recall 0.947, precision 0.360, clean benign removed 0.1056.

## Timings (s)

train_members: 29.89, train_baselines: 10.17, adv_training: 63.47, robust_features: 1.64, robustness_curves: 61.8, feature_robustness: 2.83, explain: 9.53, adv_input_detector: 3.76, poisoning: 8.33
