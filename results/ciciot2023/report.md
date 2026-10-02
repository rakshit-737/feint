# FEINT robustness report: ciciot2023

- split: stratified random 70/30; train 87,901 / test 37,673 flows; attack prevalence in test 96.0%
- attacker-controllable features: duration, packets, bytes
- robust (attacker-immutable) features: packets_rev, bytes_rev, dst_port, proto_tcp, proto_udp, bpp_rev
- attacked flows per curve point: 1000

## Clean detection (held-out test set)

| model | acc | prec | recall | F1 | ROC-AUC | PR-AUC | FPR | prec @1% prev. | prec @0.1% prev. |
|---|---|---|---|---|---|---|---|---|---|
| Logistic regression | 0.9601 | 0.9602 | 0.9999 | 0.9796 | 0.7466 | 0.9869 | 1.0000 | 0.010 | 0.001 |
| Random forest | 0.9606 | 0.9671 | 0.9927 | 0.9797 | 0.9188 | 0.9962 | 0.8140 | 0.012 | 0.001 |
| IsolationForest | 0.2281 | 0.9982 | 0.1964 | 0.3283 | 0.7251 | 0.9838 | 0.0087 | 0.186 | 0.022 |
| MLP | 0.9602 | 0.9602 | 1.0000 | 0.9797 | 0.7577 | 0.9875 | 1.0000 | 0.010 | 0.001 |
| XGBoost | 0.9619 | 0.9656 | 0.9958 | 0.9805 | 0.9271 | 0.9967 | 0.8560 | 0.012 | 0.001 |
| Autoencoder | 0.3408 | 0.9981 | 0.3141 | 0.4778 | 0.7893 | 0.9893 | 0.0147 | 0.178 | 0.021 |
| FEINT ensemble | 0.9602 | 0.9603 | 0.9999 | 0.9797 | 0.9170 | 0.9960 | 0.9980 | 0.010 | 0.001 |
| MLP + adv. training | 0.9601 | 0.9607 | 0.9993 | 0.9796 | 0.8504 | 0.9928 | 0.9847 | 0.010 | 0.001 |
| XGBoost + adv. training | 0.9624 | 0.9650 | 0.9970 | 0.9808 | 0.9246 | 0.9966 | 0.8713 | 0.011 | 0.001 |
| FEINT ensemble + adv. training | 0.9611 | 0.9614 | 0.9997 | 0.9802 | 0.9157 | 0.9961 | 0.9687 | 0.010 | 0.001 |
| XGBoost, robust features only | 0.9602 | 0.9613 | 0.9988 | 0.9797 | 0.8628 | 0.9933 | 0.9707 | 0.010 | 0.001 |

## Detection rate under constrained adaptive evasion (attack flows)

| model | eps=0 | eps=0.25 | eps=0.5 | eps=1 | eps=1.5 | eps=2 | area | valid flows @max eps |
|---|---|---|---|---|---|---|---|---|
| MLP | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| XGBoost | 0.996 | 0.925 | 0.913 | 0.906 | 0.896 | 0.887 | 0.910 | 1.000 |
| Random forest | 0.993 | 0.927 | 0.917 | 0.912 | 0.911 | 0.909 | 0.919 | 1.000 |
| FEINT ensemble | 1.000 | 0.999 | 0.999 | 0.999 | 0.999 | 0.999 | 0.999 | 1.000 |
| MLP + adv. training | 1.000 | 0.998 | 0.998 | 0.987 | 0.955 | 0.931 | 0.976 | 1.000 |
| XGBoost + adv. training | 0.998 | 0.959 | 0.959 | 0.958 | 0.957 | 0.957 | 0.960 | 1.000 |
| FEINT ensemble + adv. training | 1.000 | 0.991 | 0.991 | 0.991 | 0.991 | 0.991 | 0.992 | 1.000 |
| XGBoost, robust features only | 0.999 | 0.999 | 0.999 | 0.999 | 0.999 | 0.999 | 0.999 | 1.000 |

## Detection rate under unconstrained adaptive evasion (attack flows)

| model | eps=0 | eps=0.25 | eps=0.5 | eps=1 | eps=1.5 | eps=2 | area | valid flows @max eps |
|---|---|---|---|---|---|---|---|---|
| MLP | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 |
| XGBoost | 0.996 | 0.846 | 0.730 | 0.605 | 0.497 | 0.438 | 0.635 | 0.000 |
| FEINT ensemble | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 |

## Per attack family (XGBoost, constrained eps=2)

| family | n | clean detection | adversarial detection |
|---|---|---|---|
| DoS-TCP_Flood | 52 | 1.000 | 1.000 |
| VulnerabilityScan | 50 | 1.000 | 0.900 |
| DDoS-SynonymousIP_Flood | 48 | 1.000 | 1.000 |
| DoS-HTTP_Flood | 48 | 1.000 | 1.000 |
| Recon-OSScan | 48 | 1.000 | 0.917 |
| DNS_Spoofing | 45 | 1.000 | 0.933 |
| DoS-SYN_Flood | 44 | 1.000 | 1.000 |
| MITM-ArpSpoofing | 43 | 1.000 | 0.884 |
| Recon-HostDiscovery | 43 | 1.000 | 1.000 |
| DoS-UDP_Flood | 42 | 1.000 | 0.976 |
| Recon-PortScan | 42 | 0.976 | 0.952 |
| DDoS-ICMP_Flood | 41 | 1.000 | 0.927 |
| DDoS-ACK_Fragmentation | 40 | 1.000 | 1.000 |
| DDoS-UDP_Fragmentation | 37 | 1.000 | 0.946 |
| XSS | 37 | 1.000 | 0.919 |
| SqlInjection | 36 | 0.944 | 0.833 |
| DDoS-ICMP_Fragmentation | 35 | 1.000 | 0.943 |
| DDoS-SlowLoris | 35 | 1.000 | 1.000 |
| DDoS-HTTP_Flood | 33 | 1.000 | 1.000 |
| CommandInjection | 32 | 1.000 | 0.906 |
| DDoS-UDP_Flood | 31 | 1.000 | 0.968 |
| DictionaryBruteForce | 28 | 0.964 | 0.821 |
| Mirai-udpplain | 25 | 1.000 | 0.840 |
| Mirai-greeth_flood | 24 | 1.000 | 1.000 |
| Backdoor_Malware | 19 | 1.000 | 0.947 |
| BrowserHijacking | 19 | 1.000 | 0.684 |
| Uploading_Attack | 13 | 1.000 | 0.923 |
| Recon-PingSweep | 10 | 1.000 | 0.900 |

## Which controllable features are exploitable? (XGBoost, one feature at a time, eps=2)

| attacker controls only | detection rate |
|---|---|
| duration | 0.958 |
| bytes | 0.995 |
| packets | 0.996 |

## Global feature importance (XGBoost, mean |TreeSHAP|, log-odds)

| feature | mean abs SHAP | attacker-controllable |
|---|---|---|
| bpp | 0.751 |  |
| proto_tcp | 0.629 |  |
| dst_port | 0.565 |  |
| duration | 0.561 | yes |
| pkt_ratio | 0.446 |  |
| bytes | 0.440 | yes |
| bpp_rev | 0.410 |  |
| bytes_per_s | 0.353 |  |
| bytes_rev | 0.273 |  |
| packets | 0.227 | yes |
| proto_udp | 0.095 |  |
| packets_rev | 0.078 |  |

## Counterfactual explanations (XGBoost alerts)

- 200 flagged attack flows; realisable counterfactual found for 3.0% (validity under schema: 100.0%)
- mean controllable features changed: 2.00; median budget: 1.4375
- features used: {'duration': 6, 'bytes': 4, 'packets': 2}
- hardened ensemble: counterfactual found for 0.0% of its alerts

Examples:

- no realisable evasion within budget: this alert is robust to the modelled attacker
- no realisable evasion within budget: this alert is robust to the modelled attacker
- no realisable evasion within budget: this alert is robust to the modelled attacker
- no realisable evasion within budget: this alert is robust to the modelled attacker
- no realisable evasion within budget: this alert is robust to the modelled attacker

## Adversarial-input detector

Trained on 224 successful constrained evasions (eps 0.5/1/2) of training flows.

| test budget | evasions | ROC-AUC | TPR | FPR on clean |
|---|---|---|---|---|
| 1.0 | 51 | 0.998 | 0.922 | 0.008 |
| 1.5 | 51 | 0.998 | 0.922 | 0.008 |

Detector-aware adaptive attacker (eps=2) against XGBoost OR adv-input alarm: detection 0.995 (XGBoost alone would miss 0.005 of these flows); guarded FPR on benign 0.8820. The static AUC above is therefore optimistic: it only holds against attackers unaware of the alarm.

## Backdoor poisoning

1758 poisoned flows (2% of training): malicious flows with `duration = 307`, labelled benign.

| model | clean acc. | recall (clean attacks) | recall (triggered attacks) | backdoor success |
|---|---|---|---|---|
| clean model | 0.9619 | 0.9956 | 0.9601 | 0.0399 |
| poisoned model | 0.9626 | 0.9963 | 0.0000 | 1.0000 |
| sanitized model | 0.9613 | 0.9987 | 0.8187 | 0.1813 |

Robust-feature kNN sanitiser flagged 4776 training flows: poison recall 0.984, precision 0.362, clean benign removed 0.8706.

## Timings (s)

train_members: 3.99, train_baselines: 3.31, adv_training: 19.88, robust_features: 0.76, robustness_curves: 70.51, feature_robustness: 2.09, explain: 8.16, adv_input_detector: 6.71, poisoning: 4.97
