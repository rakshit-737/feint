# A2PM reproduction cross-check: a2pm 1.2.0's own pattern transforms

Same data (CIC-IDS2017 Tuesday + Wednesday, 1137051 flows after dropping NaN/inf rows), split (stratified 70/30, seed 0), A2PM configuration and RF as [vitorino2022.md](vitorino2022.md), but run with the library's unvectorised pattern transforms. It took 4.2 h on a GitHub Actions runner (the vectorised run: 10 min). Differences from the main run: scikit-learn MLPClassifier (64, 32) instead of the paper's Keras MLP (no dropout, no class weights), and attacks of 1 iteration and of at most 50 iterations with a2pm's default early stopping (patience 2) instead of 50 iterations without early stopping.

Provenance: [workflow run 37022412045](https://github.com/rakshit-737/feint-adversarial-ids/actions/runs/37022412045), commit 67d1a90 (script as of c215280); environment python 3.11.16, a2pm 1.2.0, numpy 1.26.4, sklearn 1.5.2.

Accuracy on the malicious evaluation flows / macro-F1 over all evaluation flows:

| model | clean | targeted, 1 it | targeted, <= 50 it | untargeted, 1 it | untargeted, <= 50 it |
|---|---|---|---|---|---|
| RF, regular | 0.9994 / 0.9981 | 0.3592 / 0.4783 | 0.0000 / 0.2334 | 0.3593 / 0.4845 | 0.0000 / 0.2335 |
| RF, adversarial | 0.9994 / 0.9983 | 0.9986 / 0.9972 | 0.9458 / 0.7937 | 0.9988 / 0.9974 | 0.9224 / 0.6826 |
| MLP (scikit-learn), regular | 0.9923 / 0.9635 | 0.7750 / 0.4937 | 0.5464 / 0.2805 | 0.7778 / 0.4911 | 0.1392 / 0.1569 |
| MLP (scikit-learn), adversarial | 0.9915 / 0.9587 | 0.9801 / 0.9268 | 0.9424 / 0.7061 | 0.9867 / 0.9507 | 0.9346 / 0.6293 |

The regularly trained RF is the same model in both runs (same data, split, seed and scikit-learn version; identical clean scores). After one iteration the library run leaves accuracy 0.3592 (targeted) and 0.3593 (untargeted); the vectorised run 0.3601 and 0.3607. After the attack both reach 0.0000 / 0.0000 accuracy and untargeted macro-F1 0.2335 / 0.2335.
