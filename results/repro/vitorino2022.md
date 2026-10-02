# Reproduction: Vitorino, Oliveira & Praca 2022 (A2PM), CIC-IDS2017 Enterprise scenario

1137051 flows (79667 malicious evaluation flows); classes {'BENIGN': 871496, 'DoS GoldenEye': 10293, 'DoS Hulk': 230124, 'DoS Slowhttptest': 5499, 'DoS slowloris': 5796, 'FTP-Patator': 7935, 'Heartbleed': 11, 'SSH-Patator': 5897}.
Paper (Table 2): 1138612 flows, classes {'BENIGN': 873066, 'DoS Hulk': 230124, 'DoS GoldenEye': 10293, 'FTP-Patator': 7926, 'SSH-Patator': 5897, 'DoS slowloris': 5796, 'DoS Slowhttptest': 5499, 'Heartbleed': 11}.

Pattern transforms: vectorised (self-checked); MLP: keras.

Accuracy is on the malicious evaluation flows only (the paper's definition); detection is the share of malicious evaluation flows not classified Benign; macro-F1 is over all evaluation flows. Paper values are the legends of Figures 5-7 (iteration 0 -> 50); ours are iteration 0 -> 1 -> 50.

| model | metric | paper, it 0 -> 50 | ours, it 0 -> 1 -> 50 |
|---|---|---|---|
| RF, regular | targeted accuracy | 0.9993 -> 0.0000 | 0.9994 -> 0.3601 -> 0.0000 |
| RF, regular | targeted detection | - | 0.9997 -> 0.3617 -> 0.0000 |
| RF, regular | untargeted accuracy | 0.9989 -> 0.0001 | 0.9994 -> 0.3607 -> 0.0000 |
| RF, regular | untargeted macro-f1 | 0.9976 -> 0.2087 | 0.9981 -> 0.4789 -> 0.2335 |
| RF, adversarial | targeted accuracy | 0.9991 -> 0.9991 | 0.9994 -> 0.9988 -> 0.9317 |
| RF, adversarial | targeted detection | - | 0.9997 -> 0.9996 -> 0.9399 |
| RF, adversarial | untargeted accuracy | 0.9989 -> 0.8996 | 0.9994 -> 0.9990 -> 0.9006 |
| RF, adversarial | untargeted macro-f1 | 0.9976 -> 0.5426 | 0.9982 -> 0.9978 -> 0.6415 |
| MLP, regular | targeted accuracy | 0.9998 -> 0.1038 | 0.9980 -> 0.8398 -> 0.4043 |
| MLP, regular | targeted detection | - | 0.9995 -> 0.9397 -> 0.4649 |
| MLP, regular | untargeted accuracy | 0.9985 -> 0.0093 | 0.9980 -> 0.8363 -> 0.0777 |
| MLP, regular | untargeted macro-f1 | 0.9691 -> 0.1833 | 0.8796 -> 0.6034 -> 0.1657 |
| MLP, adversarial | targeted accuracy | 0.9998 -> 0.9435 | 0.9970 -> 0.9865 -> 0.9472 |
| MLP, adversarial | targeted detection | - | 0.9987 -> 0.9922 -> 0.9474 |
| MLP, adversarial | untargeted accuracy | 0.9986 -> 0.7888 | 0.9970 -> 0.9878 -> 0.9312 |
| MLP, adversarial | untargeted macro-f1 | 0.9519 -> 0.5095 | 0.8820 -> 0.8469 -> 0.6025 |

Run details:

- RF_regular: trained in 49.7 s; targeted attack ran 50 iterations (119054 examples), untargeted 50 (120177 examples)
- RF_adversarial: trained in 98.2 s; targeted attack ran 50 iterations (3864176 examples), untargeted 50 (3719211 examples)
- MLP_regular: trained in 66.7 s, 31 epochs; targeted attack ran 50 iterations (2533298 examples), untargeted 50 (1140351 examples)
- MLP_adversarial: trained in 115.2 s, 44 epochs; targeted attack ran 50 iterations (3815402 examples), untargeted 50 (3751059 examples)

Self-check on 2408 malicious training rows (7 classes), library vs vectorised patterns (speed-up 224.9x):

| statistic | library | vectorised |
|---|---|---|
| frac numeric values changed | 0.5374 | 0.5363 |
| frac rows combination changed | 0.2413 | 0.2367 |
| mean abs normalised step | 0.0355 | 0.0355 |
| ms per row | 0.6538 | 0.0030 |

KS statistic of the normalised steps: 0.0030 (p = 0.554). Checks: numeric change fraction within 0.01: pass; combination change fraction within 0.06: pass; KS statistic of normalised steps below 0.02: pass; port never changed: pass; integer features stay integral: pass; every new combination recorded for its class: pass.

End-to-end check (targeted attack on the regularly trained RF, 4000 malicious evaluation flows, 4 seeds, 3 iterations), mean accuracy after iterations 0..3: library [0.9992, 0.3588, 0.0957, 0.0223] (sd [0.0, 0.0054, 0.0034, 0.0014], 19.4 s), vectorised [0.9992, 0.3605, 0.0969, 0.0236] (sd [0.0, 0.0028, 0.0024, 0.0029], 2.6 s); differences [0.0, 0.0017, 0.0012, 0.0013] against tolerances [0.02, 0.0215, 0.02, 0.02] (pass).

Assumptions / deviations:

- MachineLearningCVE Tuesday + Wednesday CSVs (78 numerical features), rows with NaN/inf dropped
- Interval pattern on the non-binary features (integer steps where every training value is an integer); Combination pattern on the binary TCP-flag features with Destination Port locked (the paper one-hot encoded its categorical features and locked port and protocol; these CSVs have no protocol column)
- A2PM pattern transforms: vectorised subclasses (same distribution, different random stream), checked against the library on a training sample
- MLP: Keras 64-32 ReLU, dropout 0.1, softmax, Adam 1e-3, batch 512, <= 50 epochs, early stopping (patience 5) on a stratified 20 % validation split, balanced class weights, standardised inputs
- A2PM attacks: 50 iterations, early stopping off, scores recorded after every iteration
- stratified 70/30 split, seed 0

Paper, Section 4.5: accuracy lowered by approximately 15 % (MLP) and 33 % (RF), regular training; generation rate 10 examples per 1.7 ms (16 GB RAM, 8-core CPU, 6 GB GPU).
Total runtime 600.2 s.
