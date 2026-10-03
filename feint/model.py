"""Detectors: shared preprocessing, supervised members, unsupervised members, ensemble.

Every detector exposes the same interface so attacks, hardening and metrics are
model-agnostic:

    det.pre                      fitted :class:`Preprocessor` (raw <-> z space)
    det.fit(X, y) / fit_z(Z, y)  train from raw flows / already-transformed inputs
    det.predict_proba(X)         P(malicious) from raw flows
    det.predict_proba_z(Z)       same, from z-space
    det.grad_z(Z, y)             only for differentiable (white-box) members
"""
from __future__ import annotations

import copy
import warnings
from collections.abc import Sequence

import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.exceptions import ConvergenceWarning
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier, MLPRegressor


class Preprocessor:
    """x -> z = (log1p(x) - mu) / sigma. Invertible so attacks can be projected in raw space."""

    def fit(self, X: np.ndarray) -> Preprocessor:
        """Learn the per-feature mean and standard deviation of ``log1p(max(X, 0))``."""
        L = np.log1p(np.maximum(X, 0))
        self.mu, self.sigma = L.mean(0), L.std(0) + 1e-8
        return self

    def transform(self, X: np.ndarray) -> np.ndarray:
        """Raw flows -> standardised log-feature space z."""
        return (np.log1p(np.maximum(X, 0)) - self.mu) / self.sigma

    def inverse(self, Z: np.ndarray) -> np.ndarray:
        """z-space -> raw flows (the exact inverse of :meth:`transform` on non-negative inputs)."""
        return np.expm1(np.clip(Z * self.sigma + self.mu, -50, 50))


class BaseDetector:
    """Common detector interface (see the module docstring).

    Subclasses implement ``fit_z`` and ``predict_proba_z``. ``cols`` restricts the model to a
    feature subset (robust-feature models).
    """

    name = "base"
    differentiable = False

    def __init__(self, cols: Sequence[int] | np.ndarray | None = None) -> None:
        self.pre = Preprocessor()
        self.cols = None if cols is None else np.asarray(cols)  # feature subset (robust-feature models)

    def _sel(self, Z: np.ndarray) -> np.ndarray:
        return Z if self.cols is None else Z[:, self.cols]

    def fit(self, X: np.ndarray, y: np.ndarray, pre: Preprocessor | None = None) -> BaseDetector:
        """Fit (or reuse) the preprocessor, then train on the transformed flows."""
        self.pre = pre if pre is not None else Preprocessor().fit(X)
        return self.fit_z(self.pre.transform(X), y)

    def fit_z(self, Z: np.ndarray, y: np.ndarray) -> BaseDetector:  # pragma: no cover - abstract
        """Train on z-space inputs ``Z`` with binary labels ``y`` (1 = malicious)."""
        raise NotImplementedError

    def predict_proba_z(self, Z: np.ndarray) -> np.ndarray:  # pragma: no cover - abstract
        """P(malicious) for z-space inputs."""
        raise NotImplementedError

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """P(malicious) for raw flows."""
        return self.predict_proba_z(self.pre.transform(X))

    def predict(self, X: np.ndarray, thr: float = 0.5) -> np.ndarray:
        """Binary alerts (1 = malicious) at threshold ``thr``."""
        return (self.predict_proba(X) >= thr).astype(int)

    def clone(self) -> BaseDetector:
        """Deep copy (trained state included)."""
        return copy.deepcopy(self)


class MLPDetector(BaseDetector):
    """Supervised MLP. White-box: input gradients computed analytically from the weights."""

    name = "mlp"
    differentiable = True

    def __init__(self, hidden: tuple[int, ...] = (64, 32), seed: int = 0, max_iter: int = 200,
                 cols: Sequence[int] | np.ndarray | None = None) -> None:
        super().__init__(cols)
        self.clf = MLPClassifier(hidden_layer_sizes=hidden, activation="relu", max_iter=max_iter,
                                 random_state=seed, early_stopping=True, n_iter_no_change=8,
                                 batch_size=512, learning_rate_init=2e-3)

    def fit_z(self, Z: np.ndarray, y: np.ndarray) -> MLPDetector:
        """Train the MLP (early stopping) on z-space inputs."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", ConvergenceWarning)
            self.clf.fit(self._sel(Z), y)
        return self

    def predict_proba_z(self, Z: np.ndarray) -> np.ndarray:
        """P(malicious) for z-space inputs."""
        return self.clf.predict_proba(self._sel(Z))[:, 1]

    def grad_z(self, Z: np.ndarray, y: np.ndarray) -> np.ndarray:
        """d(BCE loss)/dZ for the sklearn MLP (relu hidden layers, logistic output)."""
        W, b = self.clf.coefs_, self.clf.intercepts_
        acts = [self._sel(Z)]
        for i in range(len(W) - 1):
            acts.append(np.maximum(acts[-1] @ W[i] + b[i], 0))
        logit = (acts[-1] @ W[-1] + b[-1]).ravel()
        p = 1 / (1 + np.exp(-np.clip(logit, -50, 50)))
        g = (p - y)[:, None] @ W[-1].T
        for i in range(len(W) - 2, -1, -1):
            g = (g * (acts[i + 1] > 0)) @ W[i].T
        if self.cols is None:
            return g
        full = np.zeros_like(Z)
        full[:, self.cols] = g
        return full


class XGBDetector(BaseDetector):
    """Gradient-boosted trees (the strongest clean detector; attacked black-box / by transfer)."""

    name = "xgboost"

    def __init__(self, seed: int = 0, n_estimators: int = 300, max_depth: int = 8,
                 cols: Sequence[int] | np.ndarray | None = None, n_jobs: int = -1) -> None:
        super().__init__(cols)
        from xgboost import XGBClassifier

        self.clf = XGBClassifier(n_estimators=n_estimators, max_depth=max_depth, learning_rate=0.1,
                                 subsample=0.9, colsample_bytree=0.9, tree_method="hist",
                                 random_state=seed, n_jobs=n_jobs, eval_metric="logloss")

    def fit_z(self, Z: np.ndarray, y: np.ndarray) -> XGBDetector:
        """Train the booster on z-space inputs (then score single-threaded)."""
        self.clf.fit(self._sel(Z), y)
        if hasattr(self.clf, "n_jobs"):  # attacks score tiny batches: threads only add overhead
            self.clf.set_params(n_jobs=1)
        return self

    def predict_proba_z(self, Z: np.ndarray) -> np.ndarray:
        """P(malicious) for z-space inputs."""
        return self.clf.predict_proba(self._sel(Z))[:, 1]

    def contributions_z(self, Z: np.ndarray) -> np.ndarray:
        """Exact TreeSHAP values (log-odds units) via XGBoost's native implementation.

        Returns (n, n_features + 1); the last column is the bias term.
        """
        import xgboost as xgb

        return self.clf.get_booster().predict(xgb.DMatrix(self._sel(Z)), pred_contribs=True)


class SklearnDetector(BaseDetector):
    """Wrapper for classic baselines (logistic regression, random forest)."""

    def __init__(self, kind: str = "rf", seed: int = 0, cols: Sequence[int] | np.ndarray | None = None) -> None:
        super().__init__(cols)
        self.name = kind
        if kind == "rf":
            self.clf = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=seed,
                                              min_samples_leaf=2)
        elif kind == "logreg":
            self.clf = LogisticRegression(max_iter=2000)
        else:
            raise ValueError(kind)

    def fit_z(self, Z: np.ndarray, y: np.ndarray) -> SklearnDetector:
        """Train the wrapped scikit-learn classifier on z-space inputs."""
        self.clf.fit(self._sel(Z), y)
        return self

    def predict_proba_z(self, Z: np.ndarray) -> np.ndarray:
        """P(malicious) for z-space inputs."""
        return self.clf.predict_proba(self._sel(Z))[:, 1]


class AutoencoderDetector(BaseDetector):
    """Unsupervised autoencoder trained on *benign* flows only (zero-day-shaped anomalies).

    Score = mean squared reconstruction error in z-space; the alert threshold is the
    ``1 - target_fpr`` quantile of benign training error. ``predict_proba`` is a
    monotone map with 0.5 exactly at the threshold, so it composes with the others.
    """

    name = "autoencoder"

    def __init__(self, hidden: tuple[int, ...] = (32, 8, 32), seed: int = 0, max_iter: int = 200,
                 target_fpr: float = 0.01, cols: Sequence[int] | np.ndarray | None = None) -> None:
        super().__init__(cols)
        self.target_fpr = target_fpr
        self.ae = MLPRegressor(hidden_layer_sizes=hidden, activation="relu", max_iter=max_iter,
                               random_state=seed, early_stopping=True, n_iter_no_change=8,
                               batch_size=512, learning_rate_init=2e-3)

    def fit_z(self, Z: np.ndarray, y: np.ndarray | None = None) -> AutoencoderDetector:
        """Train on the benign rows of ``Z`` (all rows if ``y`` is None) and set the threshold."""
        Zb = self._sel(Z if y is None else Z[np.asarray(y) == 0])
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", ConvergenceWarning)
            self.ae.fit(Zb, Zb)
        self.thr = float(np.quantile(self.score_z_sel(Zb), 1 - self.target_fpr))
        return self

    def score_z_sel(self, Zs: np.ndarray) -> np.ndarray:
        """Reconstruction error of inputs already restricted to ``cols``."""
        return np.mean((self.ae.predict(Zs) - Zs) ** 2, axis=1)

    def score_z(self, Z: np.ndarray) -> np.ndarray:
        """Reconstruction error (anomaly score) of z-space inputs."""
        return self.score_z_sel(self._sel(Z))

    def predict_proba_z(self, Z: np.ndarray) -> np.ndarray:
        """Monotone map of the anomaly score, 0.5 at the alert threshold."""
        s = self.score_z(Z)
        return s / (s + self.thr)


class IForestDetector(BaseDetector):
    """IsolationForest on benign flows (classic unsupervised baseline)."""

    name = "iforest"

    def __init__(self, seed: int = 0, target_fpr: float = 0.01,
                 cols: Sequence[int] | np.ndarray | None = None) -> None:
        super().__init__(cols)
        self.target_fpr = target_fpr
        self.iso = IsolationForest(n_estimators=200, random_state=seed, n_jobs=-1)

    def fit_z(self, Z: np.ndarray, y: np.ndarray | None = None) -> IForestDetector:
        """Fit on the benign rows of ``Z`` (all rows if ``y`` is None) and set the threshold."""
        Zb = self._sel(Z if y is None else Z[np.asarray(y) == 0])
        self.iso.fit(Zb)
        self.iso.set_params(n_jobs=1)
        self.thr = float(np.quantile(-self.iso.score_samples(Zb), 1 - self.target_fpr))
        return self

    def predict_proba_z(self, Z: np.ndarray) -> np.ndarray:
        """Logistic map of the isolation score, 0.5 at the alert threshold."""
        s = -self.iso.score_samples(self._sel(Z))
        return 1 / (1 + np.exp(-(s - self.thr) * 20))


class EnsembleDetector(BaseDetector):
    """FEINT ensemble: mean of supervised members OR the benign-trained autoencoder.

    ``predict_proba = max(mean(p_supervised), p_autoencoder)``, i.e. an alert is raised
    when the supervised vote says malicious *or* the flow does not look like any
    benign traffic seen in training. All members share one preprocessor.
    """

    name = "ensemble"

    def __init__(self, supervised: list[BaseDetector], anomaly: BaseDetector | None) -> None:
        super().__init__()
        self.supervised = supervised
        self.anomaly = anomaly
        self.pre = supervised[0].pre

    def fit_z(self, Z: np.ndarray, y: np.ndarray) -> EnsembleDetector:
        """Train every member on the same z-space inputs."""
        for m in self.supervised:
            m.fit_z(Z, y)
        if self.anomaly is not None:
            self.anomaly.fit_z(Z, y)
        return self

    def predict_proba_z(self, Z: np.ndarray) -> np.ndarray:
        """``max(mean of supervised members, autoencoder)``."""
        p = np.mean([m.predict_proba_z(Z) for m in self.supervised], axis=0)
        if self.anomaly is not None:
            p = np.maximum(p, self.anomaly.predict_proba_z(Z))
        return p
