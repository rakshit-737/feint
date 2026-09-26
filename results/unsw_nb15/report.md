# FEINT robustness report: unsw_nb15

- split: official train/test partition; train 175,341 / test 82,332 flows; attack prevalence in test 55.1%
- attacker-controllable features: dur, spkts, sbytes, sttl, swin
- robust (attacker-immutable) features: dpkts, dbytes, dttl, dwin, trans_depth, ct_srv_src, ct_dst_ltm, ct_src_ltm, ct_srv_dst, proto_tcp, proto_udp, dmean
- attacked flows per curve point: 1000

## Clean detection (held-out test set)

| model | acc | prec | recall | F1 | ROC-AUC | PR-AUC | FPR | prec @1% prev. | prec @0.1% prev. |
|---|---|---|---|---|---|---|---|---|---|
| Logistic regression | 0.8128 | 0.7567 | 0.9728 | 0.8512 | 0.9095 | 0.9142 | 0.3832 | 0.025 | 0.003 |
| Random forest | 0.8643 | 0.8172 | 0.9708 | 0.8874 | 0.9752 | 0.9811 | 0.2661 | 0.036 | 0.004 |
| IsolationForest | 0.4459 | 0.3161 | 0.0055 | 0.0108 | 0.8082 | 0.7817 | 0.0146 | 0.004 | 0.000 |
| MLP | 0.8566 | 0.8081 | 0.9700 | 0.8817 | 0.9683 | 0.9757 | 0.2822 | 0.034 | 0.003 |
| XGBoost | 0.8655 | 0.8205 | 0.9674 | 0.8879 | 0.9770 | 0.9834 | 0.2593 | 0.036 | 0.004 |
| Autoencoder | 0.5857 | 0.9271 | 0.2687 | 0.4167 | 0.7338 | 0.7796 | 0.0259 | 0.095 | 0.010 |
| FEINT ensemble | 0.8568 | 0.8071 | 0.9723 | 0.8820 | 0.9738 | 0.9807 | 0.2848 | 0.033 | 0.003 |
| MLP + adv. training | 0.8641 | 0.8231 | 0.9594 | 0.8861 | 0.9653 | 0.9728 | 0.2526 | 0.037 | 0.004 |
| XGBoost + adv. training | 0.8659 | 0.8201 | 0.9689 | 0.8883 | 0.9772 | 0.9835 | 0.2604 | 0.036 | 0.004 |
| FEINT ensemble + adv. training | 0.8610 | 0.8142 | 0.9685 | 0.8847 | 0.9728 | 0.9798 | 0.2707 | 0.035 | 0.004 |
| XGBoost, robust features only | 0.8165 | 0.7751 | 0.9392 | 0.8493 | 0.9274 | 0.9403 | 0.3338 | 0.028 | 0.003 |

## Detection rate under constrained adaptive evasion (attack flows)

| model | eps=0 | eps=0.25 | eps=0.5 | eps=1 | eps=1.5 | eps=2 | area | valid flows @max eps |
|---|---|---|---|---|---|---|---|---|
| MLP | 0.967 | 0.642 | 0.398 | 0.173 | 0.110 | 0.056 | 0.293 | 1.000 |
| XGBoost | 0.965 | 0.327 | 0.178 | 0.146 | 0.001 | 0.000 | 0.171 | 1.000 |
| Random forest | 0.968 | 0.930 | 0.623 | 0.163 | 0.071 | 0.000 | 0.352 | 1.000 |
| FEINT ensemble | 0.969 | 0.835 | 0.501 | 0.416 | 0.264 | 0.255 | 0.461 | 1.000 |
| MLP + adv. training | 0.957 | 0.935 | 0.925 | 0.907 | 0.868 | 0.865 | 0.902 | 1.000 |
| XGBoost + adv. training | 0.967 | 0.964 | 0.963 | 0.962 | 0.955 | 0.954 | 0.960 | 1.000 |
| FEINT ensemble + adv. training | 0.969 | 0.968 | 0.966 | 0.965 | 0.964 | 0.963 | 0.965 | 1.000 |
| XGBoost, robust features only | 0.940 | 0.940 | 0.940 | 0.940 | 0.940 | 0.940 | 0.940 | 1.000 |

## Detection rate under unconstrained adaptive evasion (attack flows)

| model | eps=0 | eps=0.25 | eps=0.5 | eps=1 | eps=1.5 | eps=2 | area | valid flows @max eps |
|---|---|---|---|---|---|---|---|---|
| MLP | 0.967 | 0.163 | 0.005 | 0.000 | 0.000 | 0.000 | 0.082 | 0.000 |
| XGBoost | 0.965 | 0.083 | 0.017 | 0.001 | 0.000 | 0.000 | 0.074 | 0.000 |
| FEINT ensemble | 0.969 | 0.563 | 0.477 | 0.467 | 0.467 | 0.467 | 0.512 | 0.000 |

## Per attack family (XGBoost, constrained eps=2)

| family | n | clean detection | adversarial detection |
|---|---|---|---|
| Generic | 430 | 1.000 | 0.000 |
| Exploits | 235 | 0.991 | 0.004 |
| Fuzzers | 134 | 0.754 | 0.000 |
| DoS | 90 | 1.000 | 0.000 |
| Reconnaissance | 69 | 1.000 | 0.000 |
| Backdoor | 19 | 1.000 | 0.000 |
| Analysis | 15 | 1.000 | 0.000 |
| Shellcode | 7 | 1.000 | 0.000 |
| Worms | 1 | 1.000 | 0.000 |

## Which controllable features are exploitable? (XGBoost, one feature at a time, eps=2)

| attacker controls only | detection rate |
|---|---|
| sttl | 0.002 |
| spkts | 0.761 |
| sbytes | 0.878 |
| swin | 0.950 |
| dur | 0.951 |

## Global feature importance (XGBoost, mean |TreeSHAP|, log-odds)

| feature | mean abs SHAP | attacker-controllable |
|---|---|---|
| sttl | 3.420 | yes |
| sbytes | 0.967 | yes |
| smean | 0.922 |  |
| swin | 0.428 | yes |
| ct_srv_dst | 0.395 |  |
| dbytes | 0.335 |  |
| ct_srv_src | 0.328 |  |
| dload | 0.296 |  |
| ct_dst_ltm | 0.287 |  |
| ct_src_ltm | 0.232 |  |
| dpkts | 0.221 |  |
| dmean | 0.215 |  |
| proto_udp | 0.188 |  |
| dur | 0.148 | yes |
| spkts | 0.143 | yes |
| proto_tcp | 0.136 |  |
| rate | 0.123 |  |
| sload | 0.113 |  |
| trans_depth | 0.107 |  |
| sinpkt | 0.105 |  |
| dttl | 0.101 |  |
| dwin | 0.011 |  |

## Counterfactual explanations (XGBoost alerts)

- 200 flagged attack flows; realisable counterfactual found for 98.5% (validity under schema: 100.0%)
- mean controllable features changed: 2.16; median budget: 0.156
- features used: {'sbytes': 140, 'sttl': 138, 'dur': 81, 'spkts': 66, 'swin': 1}
- hardened ensemble: counterfactual found for 0.5% of its alerts

Examples:

- flip to benign by: spkts 2 -> 3; sbytes 114 -> 154
- flip to benign by: sttl 254 -> 61
- flip to benign by: dur 7e-06 -> 0.0102; spkts 2 -> 3; sbytes 114 -> 154
- flip to benign by: sbytes 200 -> 260; sttl 254 -> 215
- flip to benign by: sttl 254 -> 61

## Adversarial-input detector

Trained on 4314 successful constrained evasions (eps 0.5/1/2) of training flows.

| test budget | evasions | ROC-AUC | TPR | FPR on clean |
|---|---|---|---|---|
| 1.0 | 841 | 1.000 | 1.000 | 0.013 |
| 1.5 | 999 | 1.000 | 0.999 | 0.013 |

Detector-aware adaptive attacker (eps=2) against XGBoost OR adv-input alarm: detection 0.998 (XGBoost alone would miss 0.002 of these flows); guarded FPR on benign 0.2730. The static AUC above is therefore optimistic: it only holds against attackers unaware of the alarm.

## Backdoor poisoning

2000 poisoned flows (2% of training): malicious flows with `sttl = 248`, labelled benign.

| model | clean acc. | recall (clean attacks) | recall (triggered attacks) | backdoor success |
|---|---|---|---|---|
| clean model | 0.8653 | 0.9683 | 0.9574 | 0.0426 |
| poisoned model | 0.8643 | 0.9674 | 0.0000 | 1.0000 |
| sanitized model | 0.8423 | 0.9800 | 0.2417 | 0.7583 |

Robust-feature kNN sanitiser flagged 4886 training flows: poison recall 0.934, precision 0.382, clean benign removed 0.0945.

## Timings (s)

train_members: 204.96, train_baselines: 64.81, adv_training: 1719.29, robust_features: 254.96, robustness_curves: 868.84, feature_robustness: 35.22, explain: 148.33, adv_input_detector: 110.76, poisoning: 368.43
