# Getting started

```bash
git clone https://github.com/rakshit-737/feint && cd feint
pip install -e ".[dev]"                 # numpy, pandas, scikit-learn, xgboost (+ matplotlib, fastapi for dev)
python -m pytest -q                     # 33 tests; real-data tests skip without datasets
python -m feint run --quick --n 3000 --out results/demo   # 1-minute synthetic smoke study
```

Score flows over HTTP with explanations (after a run with `--save-model`):

```bash
python -m feint serve --model results/unsw_nb15/model.joblib
curl -s localhost:8000/score -H 'content-type: application/json' \
  -d '{"explain": true, "flows": [{"dur": 0.00001, "spkts": 2, "dpkts": 0, "sbytes": 114, "sttl": 254, "proto_udp": 1}]}'
```

## Reproducing the benchmarks

`make` is optional; every target is a plain command.

| step | command | time (laptop CPU, shared with other jobs) |
|---|---|---|
| download data | `python scripts/download_unsw_nb15.py && python scripts/download_cicids2017.py` (set `FEINT_DATA` to choose the directory, default `./data`) | network bound |
| UNSW-NB15 study | `python -m feint run --data unsw_nb15 --out results/unsw_nb15 --save-model` | ~20 min |
| CIC-IDS2017 study | `python -m feint run --data cicids2017 --out results/cicids2017` | ~60 min (+7 min first CSV load; cached after) |
| real-data tests | `FEINT_DATA=./data python -m pytest -q -m realdata` | |

Key knobs: `--eps`, `--iters` (black-box queries), `--steps` (PGD), `--adv-rounds`, `--max-eval`,
`--frac` (CIC sampling), `--seed`.

## Multi-seed study

```bash
python -m feint seeds --data unsw_nb15 --seeds 0 1 2 --out results/unsw_nb15
python -m feint seeds --data cicids2017 --seeds 0 1 2 --out results/cicids2017
```

## Docker

```bash
docker run --rm ghcr.io/rakshit-737/feint:latest run --quick --n 2000 --out /tmp/demo
docker compose up api   # serves results/unsw_nb15/model.joblib on :8000 (train it first with --save-model)
```
