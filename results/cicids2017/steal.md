## Model stealing (label-only queries -> transfer attack)

Victim: xgboost; 1000 held-out attack flows; transfer = constrained PGD on the surrogate, no score queries to the victim. Victim detection rate (higher is better for the defender).

| surrogate | test agreement | eps=0.0 | eps=0.5 | eps=1.0 | eps=2.0 |
|---|---|---|---|---|---|
| true labels, full training set | 0.995 | 0.999 | 0.631 | 0.612 | 0.567 |
| stolen, 500 label queries | 0.837 | 0.999 | 0.529 | 0.520 | 0.445 |
| stolen, 2000 label queries | 0.956 | 0.999 | 0.525 | 0.504 | 0.452 |
| stolen, 10000 label queries | 0.989 | 0.999 | 0.547 | 0.518 | 0.478 |
