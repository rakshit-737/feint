# ADR 0004: scikit-learn MLP and autoencoder instead of PyTorch

- Status: accepted
- Date: 2026-09-26

## Context

The spec lists PyTorch for the autoencoder and adversarial training. The models here are
tiny (thousands of parameters on 15-22 features); the development machine and CI are
CPU-only; PyTorch adds hundreds of MB to every CI install and lags new Python releases.

## Decision

Use `sklearn.neural_network.MLPClassifier` for the supervised member and `MLPRegressor`
trained X -> X on benign flows as the autoencoder. White-box gradients for the MLP are
computed analytically from `coefs_` / `intercepts_` (`MLPDetector.grad_z`), and a unit test
checks them against central finite differences to 1e-4.

## Consequences

- Fast CI, deterministic seeds, trivial serialisation with joblib.
- No GPU training, which is fine at this scale: the full CIC-IDS2017 study runs on a laptop CPU.
- If larger models are ever needed, only `grad_z` and `fit_z` must be re-implemented behind
  the same interface.
