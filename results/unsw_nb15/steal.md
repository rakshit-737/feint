## Model stealing (label-only queries -> transfer attack)

Victim: xgboost; 1000 held-out attack flows; transfer = constrained PGD on the surrogate, no score queries to the victim. Victim detection rate (higher is better for the defender).

| surrogate | test agreement | eps=0.0 | eps=0.5 | eps=1.0 | eps=2.0 |
|---|---|---|---|---|---|
| true labels, full training set | 0.937 | 0.965 | 0.544 | 0.400 | 0.245 |
| stolen, 500 label queries | 0.785 | 0.965 | 0.568 | 0.329 | 0.178 |
| stolen, 2000 label queries | 0.914 | 0.965 | 0.435 | 0.360 | 0.001 |
| stolen, 10000 label queries | 0.918 | 0.965 | 0.514 | 0.422 | 0.001 |
