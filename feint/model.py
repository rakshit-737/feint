"""Detector: log-transform + standardise + small MLP, with analytic input gradients."""
from __future__ import annotations

import warnings

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.exceptions import ConvergenceWarning
from sklearn.neural_network import MLPClassifier


class Preprocessor:
    """x -> z = (log1p(x) - mu) / sigma. Invertible so attacks can be projected in raw space."""

    def fit(self, X):
        L = np.log1p(np.maximum(X, 0))
        self.mu, self.sigma = L.mean(0), L.std(0) + 1e-8
        return self

    def transform(self, X):
        return (np.log1p(np.maximum(X, 0)) - self.mu) / self.sigma

    def inverse(self, Z):
        return np.expm1(Z * self.sigma + self.mu)


class Detector:
    """Supervised member. White-box: gradients are computed analytically from the weights."""

    def __init__(self, hidden=(32, 16), seed=0, max_iter=300):
        self.pre = Preprocessor()
        self.clf = MLPClassifier(hidden_layer_sizes=hidden, activation="relu",
                                 max_iter=max_iter, random_state=seed)

    def fit(self, X, y):
        self.pre.fit(X)
        return self.fit_z(self.pre.transform(X), y)

    def fit_z(self, Z, y):
        """Train on already-transformed inputs (used by adversarial training)."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", ConvergenceWarning)
            self.clf.fit(Z, y)
        return self

    def predict_proba_z(self, Z):
        return self.clf.predict_proba(Z)[:, 1]

    def predict_proba(self, X):
        return self.predict_proba_z(self.pre.transform(X))

    def predict(self, X, thr=0.5):
        return (self.predict_proba(X) >= thr).astype(int)

    def grad_z(self, Z, y):
        """d(BCE loss)/dZ for the sklearn MLP (relu hidden layers, logistic output)."""
        W, b = self.clf.coefs_, self.clf.intercepts_
        acts = [Z]
        for i in range(len(W) - 1):
            acts.append(np.maximum(acts[-1] @ W[i] + b[i], 0))
        logit = (acts[-1] @ W[-1] + b[-1]).ravel()
        p = 1 / (1 + np.exp(-np.clip(logit, -50, 50)))
        g = (p - y)[:, None] @ W[-1].T
        for i in range(len(W) - 2, -1, -1):
            g = (g * (acts[i + 1] > 0)) @ W[i].T
        return g


class AnomalyMember:
    """Unsupervised IsolationForest trained on benign flows only (zero-day-shaped traffic)."""

    def __init__(self, seed=0, contamination=0.02):
        self.iso = IsolationForest(n_estimators=100, random_state=seed, contamination=contamination)

    def fit(self, Z_benign):
        self.iso.fit(Z_benign)
        return self

    def is_anomalous(self, Z):
        return (self.iso.predict(Z) == -1).astype(int)
