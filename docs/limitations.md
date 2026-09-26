# Limitations and roadmap

- **Feature-space, not problem-space.** Constraints approximate what packet-level changes can do;
  side effects (more packets also lengthen duration and change `ct_*` counters) and attack
  semantics (a DoS needs its volume) are not enforced. Both simplifications favour the attacker.
- **Empirical robustness only.** Our attacks are strong but not exhaustive; every robustness number
  is an upper bound. Evidence: the unconstrained attack (a superset of the constrained one) is
  *weaker* than the constrained one against the UNSW-NB15 ensemble (0.467 vs 0.255 detection at
  eps=2). Adversarial training was evaluated with the same attack family it trained on.
- **The adversarial-input alarm's 1.000 AUC is not a robustness claim.** Against a detector-aware
  attacker it still helps on CIC-IDS2017 (0.417 -> 0.880 detection) but raises FPR 0.35 % -> 2.3 %.
- **Poisoning defence is partial.** The robust-feature kNN sanitiser recovers most poisons but a
  handful of survivors keeps the backdoor alive (success 0.52 on CIC, 0.76 on UNSW). On CIC the
  trigger value alone already evades 33 % of the clean model's detections because `init_win_fwd` is
  itself a strong, attacker-controlled feature.
- **Dataset artefacts.** CIC-IDS2017 has known labelling issues (Engelen et al., 2021) and UNSW-NB15's
  `sttl` / `swin` separate classes because of the testbed; both inflate clean scores. FEINT surfaces
  them (SHAP, single-feature attacks) rather than fixing them.
- **Sampling.** CIC results use a de-duplicated 10 % per-class sample (253 k flows) for CPU
  budget; UNSW uses the full official split. One seed; no confidence intervals yet.
- **Not implemented from the spec:** self-captured lab pcaps via CICFlowMeter, React dashboard
  (replaced by generated PNG/Markdown reports and a JSON API), model-stealing experiments.

## Roadmap

- [ ] Multiple seeds with confidence intervals; bootstrap the robustness curves
- [ ] Problem-space validation: replay perturbed flows in a lab network and re-extract with CICFlowMeter
- [ ] Coupled constraints (packets -> duration, connection rate -> `ct_*`) and attack-semantics constraints
- [ ] Certified / randomised-smoothing baseline for tabular features
- [ ] Stronger poisoning defences (spectral signatures, trigger-value audits) and clean-label poisoning
- [ ] CIC-IDS2018 and CICIoT2023 schemas; small web dashboard over the JSON reports

## Safety and ethics

FEINT is a defensive, lab-only research tool. It attacks **feature vectors** of public datasets
against models trained locally; it generates no traffic, contains no exploit code or malware and
scans nothing. The evasion techniques studied (padding, delays, TCP window / TTL choice) are
well known; publishing their measured effect helps defenders choose robust features. See
[THREAT_MODEL.md](https://github.com/rakshit-737/feint/blob/main/THREAT_MODEL.md) and [SECURITY.md](security.md).

## License and citation

Code: [MIT](https://github.com/rakshit-737/feint/blob/main/LICENSE). Datasets keep their original terms; cite the dataset papers above when using
the results. Contributions welcome, see [CONTRIBUTING.md](https://github.com/rakshit-737/feint/blob/main/CONTRIBUTING.md) and the
[changelog](changelog.md).