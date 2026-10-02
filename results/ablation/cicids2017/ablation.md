# Schema ablation: cicids2017

Seeds [0, 1, 2, 3, 4] (n=5); mean [95 % Student-t CI]. Differences are paired per seed (schema arm minus schema-agnostic arm).

## Adversarial training of the MLP: constrained vs unconstrained examples

Both arms are evaluated by the constrained adaptive attack (white-box PGD + black-box search).

| arm | clean F1 | FPR | det eps=0.0 | det eps=0.25 | det eps=0.5 | det eps=1.0 | det eps=1.5 | det eps=2.0 |
|---|---|---|---|---|---|---|---|---|
| constrained_at | 0.982 [0.979, 0.986] | 0.008 [0.006, 0.009] | 0.988 [0.978, 0.997] | 0.849 [0.804, 0.894] | 0.821 [0.779, 0.863] | 0.755 [0.709, 0.801] | 0.719 [0.655, 0.783] | 0.676 [0.583, 0.770] |
| unconstrained_at | 0.985 [0.983, 0.987] | 0.007 [0.006, 0.008] | 0.990 [0.982, 0.998] | 0.760 [0.723, 0.797] | 0.508 [0.398, 0.618] | 0.183 [0.085, 0.280] | 0.076 [0.028, 0.124] | 0.031 [0.004, 0.058] |
| difference | | +0.001 [-0.002, +0.003] | -0.002 [-0.010, +0.006] | +0.089 [+0.035, +0.143] | +0.313 [+0.173, +0.453] | +0.572 [+0.457, +0.687] | +0.643 [+0.534, +0.751] | +0.645 [+0.529, +0.762] |

## kNN poison sanitiser: robust-feature space vs all features

Backdoor success of the poisoned, unsanitised model: 1.000 [1.000, 1.000].

| arm | backdoor success after sanitising | clean accuracy | poison recall | precision | clean benign removed |
|---|---|---|---|---|---|
| robust_features | 0.083 [0.024, 0.142] | 0.985 [0.984, 0.986] | 0.990 [0.988, 0.993] | 0.510 [0.504, 0.516] | 0.026 [0.025, 0.026] |
| all_features | 1.000 [1.000, 1.000] | 0.996 [0.996, 0.997] | 0.090 [0.086, 0.094] | 0.268 [0.264, 0.273] | 0.007 [0.006, 0.007] |
| difference | -0.917 [-0.976, -0.858] | -0.011 [-0.012, -0.010] | +0.900 [+0.895, +0.905] | +0.242 [+0.235, +0.249] | +0.019 [+0.019, +0.019] |
