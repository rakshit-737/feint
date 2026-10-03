# Reproduction: Moustafa & Slay 2016, Inf. Secur. J. 25(1-3); DT accuracy 85.56 %, FAR 15.78 % (unverified: paper paywalled, no open copy or open secondary source found)

Assumptions:

- official training (175,341) / testing (82,332) partition, binary label
- all 42 published feature columns; proto / service / state one-hot
- scikit-learn defaults (the paper used other tooling)

| model | accuracy | FAR |
|---|---|---|
| DT (paper) | 0.8556 | 0.1578 |
| DT (ours) | 0.8649 | 0.2484 |
| LR (ours) | 0.8123 | 0.3886 |
| NB (ours) | 0.7062 | 0.4748 |
| ANN (ours) | 0.8713 | 0.2595 |
