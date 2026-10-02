# CLI and API reference

## CLI

| command | purpose |
|---|---|
| `feint run --data {synthetic,cicids2017,unsw_nb15,PATH}\|cicids2017\|unsw_nb15\|<csv> [--quick] [--save-model] --out DIR` | full study: train, attack, harden, explain, poison, drift, report |
| `feint seeds --data ... --seeds 0 1 2 [--adv] --out DIR` | multi-seed robustness with 95 % confidence intervals |
| `feint generate --n N --out flows.csv` | synthetic flows |
| `feint serve --model model.joblib` | FastAPI scoring + explanation service |
| `feint steal --data `feint run --data {synthetic,cicids2017,unsw_nb15,PATH} --budgets 500 2000 10000 --eps 0.5 1 2` | model-stealing study (label-only queries) |

## HTTP API

`GET /health`, `GET /schema`, `POST /score` with `{"explain": true, "flows": [{...}]}`.

## Python API

::: feint.schema
::: feint.pipeline
::: feint.seeds
::: feint.attack
::: feint.harden
::: feint.explain
::: feint.poison
::: feint.metrics
::: feint.api
