# Schema ablation: unsw_nb15

Seeds [0, 1, 2, 3, 4] (n=5); mean [95 % Student-t CI]. Differences are paired per seed (schema arm minus schema-agnostic arm).

## Adversarial training of the MLP: constrained vs unconstrained examples

Both arms are evaluated by the constrained adaptive attack (white-box PGD + black-box search).

| arm | clean F1 | FPR | det eps=0.0 | det eps=0.25 | det eps=0.5 | det eps=1.0 | det eps=1.5 | det eps=2.0 |
|---|---|---|---|---|---|---|---|---|
| constrained_at | 0.881 [0.875, 0.887] | 0.276 [0.251, 0.301] | 0.961 [0.952, 0.970] | 0.942 [0.928, 0.957] | 0.927 [0.905, 0.949] | 0.888 [0.832, 0.945] | 0.814 [0.753, 0.875] | 0.808 [0.746, 0.869] |
| unconstrained_at | 0.880 [0.874, 0.886] | 0.280 [0.255, 0.305] | 0.962 [0.949, 0.974] | 0.829 [0.725, 0.934] | 0.574 [0.389, 0.758] | 0.213 [0.110, 0.316] | 0.138 [0.080, 0.196] | 0.080 [0.038, 0.121] |
| difference | | -0.004 [-0.017, +0.010] | -0.001 [-0.012, +0.010] | +0.113 [+0.004, +0.221] | +0.353 [+0.157, +0.550] | +0.675 [+0.587, +0.764] | +0.676 [+0.601, +0.751] | +0.728 [+0.665, +0.792] |

## kNN poison sanitiser: robust-feature space vs all features

Backdoor success of the poisoned, unsanitised model: 1.000 [1.000, 1.000].

| arm | backdoor success after sanitising | clean accuracy | poison recall | precision | clean benign removed |
|---|---|---|---|---|---|
| robust_features | 0.676 [0.616, 0.736] | 0.840 [0.837, 0.843] | 0.949 [0.941, 0.957] | 0.355 [0.350, 0.360] | 0.108 [0.105, 0.111] |
| all_features | 0.903 [0.872, 0.935] | 0.845 [0.843, 0.848] | 0.884 [0.873, 0.894] | 0.403 [0.393, 0.412] | 0.082 [0.079, 0.085] |
| difference | -0.227 [-0.311, -0.144] | -0.006 [-0.007, -0.004] | +0.065 [+0.052, +0.079] | -0.048 [-0.058, -0.038] | +0.026 [+0.022, +0.029] |
