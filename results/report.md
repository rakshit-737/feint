# FEINT robustness report

## Clean detection (held-out test set)

| model | acc | prec | recall | F1 | AUC | FPR | precision @0.1% prevalence |
|---|---|---|---|---|---|---|---|
| baseline | 0.993 | 0.997 | 0.981 | 0.989 | 1.000 | 0.0012 | 0.452 |
| adv_trained | 0.988 | 0.965 | 0.994 | 0.979 | 1.000 | 0.0155 | 0.060 |

## Robustness curve: constrained PGD (detection rate on attack flows)

| eps | baseline detect | baseline ASR | hardened detect | hardened ASR | valid flows (baseline atk) |
|---|---|---|---|---|---|
| 0.00 | 0.981 | 0.000 | 0.994 | 0.000 | 1.000 |
| 0.25 | 0.931 | 0.051 | 0.994 | 0.003 | 1.000 |
| 0.50 | 0.764 | 0.221 | 0.983 | 0.014 | 1.000 |
| 1.00 | 0.372 | 0.620 | 0.983 | 0.014 | 1.000 |
| 1.50 | 0.328 | 0.666 | 0.964 | 0.034 | 1.000 |
| 2.00 | 0.328 | 0.666 | 0.964 | 0.036 | 1.000 |

## Robustness curve: unconstrained PGD (detection rate on attack flows)

| eps | baseline detect | baseline ASR | hardened detect | hardened ASR | valid flows (baseline atk) |
|---|---|---|---|---|---|
| 0.00 | 0.981 | 0.000 | 0.994 | 0.000 | 1.000 |
| 0.25 | 0.594 | 0.394 | 0.717 | 0.279 | 0.328 |
| 0.50 | 0.339 | 0.654 | 0.678 | 0.318 | 0.328 |
| 1.00 | 0.328 | 0.666 | 0.664 | 0.332 | 0.328 |
| 1.50 | 0.328 | 0.666 | 0.628 | 0.369 | 0.328 |
| 2.00 | 0.328 | 0.666 | 0.417 | 0.581 | 0.328 |

## Ensemble backstop

At eps=2.0, 242 constrained evasions beat the baseline MLP; IsolationForest flagged 242 of them (IForest FPR on benign test = 0.019).
