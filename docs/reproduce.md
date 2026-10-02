# Reproduce

Every committed number comes from one of these commands. Heavy studies run as GitHub Actions jobs
(`.github/workflows/bench.yml`, ubuntu-latest, 4 vCPU, 16 GB) and upload their outputs as
artefacts; only the small JSON / Markdown / PNG files are committed under `results/`.

| result | command | where / runtime | expected key number (tolerance) |
|---|---|---|---|
| data | `python scripts/download_unsw_nb15.py`, `download_cicids2017.py`, `download_cicids2017_corrected.py`, `download_cicids2018.py`, `download_ciciot2023.py` (SHA-256 verified; `FEINT_DATA` sets the directory) | network bound | |
| UNSW-NB15 study, seed 0 | `python -m feint run --data unsw_nb15 --out results/unsw_nb15` | laptop ~65 min, or `bench.yml` study `run-unsw` | XGBoost F1 0.888 (±0.002) |
| CIC-IDS2017 study, seed 0 | `python -m feint run --data cicids2017 --out results/cicids2017` | laptop ~60 min, or `run-cic` | XGBoost F1 0.994 (±0.002) |
| corrected CIC-IDS2017 | `python -m feint run --data cicids2017_corrected` | `run-cic-corrected` | XGBoost F1 0.9999 |
| 5-seed CIs incl. adversarial training and poisoning | `python -m feint seeds --data <ds> --seeds 0 1 2 3 4 --adv --poison` | `seeds-unsw`, `seeds-cic`, `seeds-cic-corrected`, `seeds-iot` (one job per seed, then `seeds-merge`) | CIC ensemble+AT eps=2: 0.793 [0.763, 0.823] |
| cross-dataset | `python -m feint xdata --train cicids2017_corrected --test cicids2018 --seeds 0 1 2 3 4` | `xdata` | XGBoost F1 0.000 |
| reproductions | `python -m feint repro --paper moustafa2016` / `--paper sharafaldin2018` | `repro-moustafa` (minutes), `repro-sharafaldin` | DT accuracy 0.865 (±0.005) |
| model stealing | `python -m feint steal --data cicids2017` | `steal-cic` | 2,000-query agreement 0.956 |
| docs | `python scripts/sync_docs.py && mkdocs build --strict` | seconds | |

Seed-0 numbers from a laptop (Windows, Python 3.14) and from Actions runners (Linux, Python 3.12)
differ in the third decimal; every `report.json` and `seeds.json` records the Python, platform,
library versions and git commit under `environment`.
