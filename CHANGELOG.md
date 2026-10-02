# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Datasets: CSE-CIC-IDS2018 (three days, SHA-256 pinned from a size-verified CI download),
  corrected CIC-IDS2017 (Engelen et al. 2021 / Liu et al. 2022), CICIoT2023 ipfixprobe subsample.
- `feint xdata` cross-dataset study (corrected CIC-IDS2017 <-> CSE-CIC-IDS2018, 5 seeds).
- `feint repro`: Moustafa & Slay 2016 and Sharafaldin et al. 2018 reproductions.
- `feint seeds --adv --poison`: adversarial training and poisoning with 5-seed CIs.
- `bench.yml` workflow for every heavy study; `paper.yml` builds the preprint draft in `paper/`.
- Docs: Evaluation and Reproduce pages, dashboard over all datasets; CITATION.cff, templates.

### Changed
- Headline numbers are now 5-seed means with CIs (they moved by up to 0.07 from the seed-0 table).
- Hardened tree models are attacked through both the undefended and the hardened MLP.
- Corrected claims: budget semantics (constrained and textbook attacks are not budget-matched),
  defender-favourable schema assumptions, UNSW derived-feature agreement, Sharafaldin setup.

### Fixed
- Download helper: single stream, per-destination lock, size and hash checks; a corrupted local
  CSE-CIC-IDS2018 file produced by two concurrent downloaders was deleted and never used.
- API input validation, data root default, single-threaded RF scoring, release notes extraction,
  sdist fixtures.

## [1.0.0] - 2026-09-26

### Added
- `feint seeds`: multi-seed robustness study with 95 % Student-t CIs (and Wilson intervals);
  3-seed results for CIC-IDS2017 and UNSW-NB15 in `results/*/seeds.{json,md}`.
- `feint steal`: model-stealing study (label-only queries -> transfer attack); UNSW-NB15 results.
- MkDocs Material docs site on GitHub Pages with a static results dashboard (`/demo/`).
- Dockerfile (slim, non-root), docker-compose for the scoring API, release workflow publishing
  `ghcr.io/rakshit-737/feint` and wheel/sdist on `v*` tags.

### Changed
- Architecture mermaid labels quoted; README limitations/roadmap updated.

## [0.2.0] - 2026-09-26

### Added
- Real data: CIC-IDS2017 (MachineLearningCVE, 2,830,743 flows) and UNSW-NB15 (official
  175,341 / 82,332 partition) loaders, with SHA-256-verified, resumable download scripts.
- Declarative domain-constraint schemas (`feint/schema.py`) for both datasets: monotone,
  range-bounded, integer, fixed and derived features plus cross-feature relations.
- Detector ensemble: XGBoost + MLP (supervised) OR a benign-trained autoencoder
  (unsupervised); logistic regression, random forest and IsolationForest baselines.
- Attacks: white-box PGD, score-based black-box random search, and an adaptive attack
  (transfer from a differentiable surrogate + black-box refinement) for trees and the ensemble.
  Unconstrained reference variants.
- Hardening: generic adversarial training (MLP and XGBoost), robust-feature models, an
  adversarial-input detector.
- Explanations: exact TreeSHAP (XGBoost native) and constraint-valid sparse counterfactuals.
- Poisoning: backdoor study with an attacker-controllable trigger and a robust-feature kNN
  training-set sanitiser.
- Temporal drift study on CIC-IDS2017 (train Monday-Wednesday, test Thursday-Friday).
- Markdown + PNG reports; FastAPI scoring/explanation service (`feint serve`).
- Real benchmark results in `results/cicids2017/` and `results/unsw_nb15/`.
- LICENSE (MIT), CONTRIBUTING, CHANGELOG, ADRs in `docs/adr/`.

### Changed
- Robustness curves are monotone by construction (an attacker with budget eps may use any
  smaller budget's successful flow).
- Byte bounds follow payload semantics (CIC) and header-inclusive semantics (UNSW).
- CI runs ruff, the test suite, and a quick end-to-end smoke study.

### Removed
- The synthetic-only `results/report.*` from 0.1.0 (superseded by real-data results).

## [0.1.0] - 2026-09-26

### Added
- MVP on synthetic flows: MLP detector with analytic gradients, constrained PGD, adversarial
  training, IsolationForest backstop, base-rate precision, CLI, CI.
