"""Domain-constraint schemas for flow features.

A :class:`Schema` states, for every feature of a dataset, what a network
attacker can realistically do to it:

* ``up``      attacker-controllable, may only *increase* (padding, delays, extra packets)
* ``free``    attacker-controllable within a closed range (e.g. TCP window, IP TTL)
* ``integer`` must stay integral (packet counts)
* ``derived`` recomputed from base features, never set directly
* anything else is *fixed*: server replies, protocol-bound flags, destination port,
  host-context counters

``project`` maps an arbitrary perturbed matrix back onto the set of realisable flows
(given the original flows) and ``is_valid`` checks that a matrix is realisable.
Both are dataset-agnostic; dataset-specific cross-feature relations (bytes vs packets
vs max-packet-length) live in ``relations``.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

import numpy as np

MTU = 1500.0  # largest packet an attacker can add/pad to without fragmentation


@dataclass(eq=False)
class Schema:
    name: str
    features: list[str]
    up: list[str] = field(default_factory=list)
    free: dict[str, tuple[float, float]] = field(default_factory=dict)
    integer: list[str] = field(default_factory=list)
    derived: dict[str, Callable[[Schema, np.ndarray], np.ndarray]] = field(default_factory=dict)
    relations: Callable[[Schema, np.ndarray, np.ndarray], np.ndarray] | None = None
    relations_ok: Callable[[Schema, np.ndarray, np.ndarray, float], np.ndarray] | None = None
    notes: dict[str, str] = field(default_factory=dict)

    # ------------------------------------------------------------------ helpers
    def __post_init__(self):
        self.idx = {n: i for i, n in enumerate(self.features)}
        unknown = (set(self.up) | set(self.free) | set(self.integer) | set(self.derived)) - set(self.features)
        if unknown:
            raise ValueError(f"schema {self.name}: unknown features {sorted(unknown)}")

    def col(self, X: np.ndarray, name: str) -> np.ndarray:
        return X[:, self.idx[name]]

    @property
    def controllable(self) -> list[str]:
        return list(self.up) + list(self.free)

    @property
    def fixed(self) -> list[str]:
        c = set(self.controllable) | set(self.derived)
        return [f for f in self.features if f not in c]

    def depends_on_controllable(self) -> list[str]:
        """Derived features whose value moves when a controllable feature moves."""
        X = np.ones((1, len(self.features)))
        base = self.recompute(X)
        moved = set()
        for c in self.controllable:
            X2 = X.copy()
            X2[0, self.idx[c]] = 7.0
            d = self.recompute(X2)
            moved |= {f for f in self.derived if not np.isclose(d[0, self.idx[f]], base[0, self.idx[f]])}
        return sorted(moved)

    def robust_features(self) -> list[str]:
        """Features the modelled attacker cannot move at all."""
        moving = set(self.controllable) | set(self.depends_on_controllable())
        return [f for f in self.features if f not in moving]

    def mask(self) -> np.ndarray:
        """1.0 on controllable columns (where gradient steps are allowed)."""
        m = np.zeros(len(self.features))
        for c in self.controllable:
            m[self.idx[c]] = 1.0
        return m

    # ------------------------------------------------------------ constraints
    def recompute(self, X: np.ndarray) -> np.ndarray:
        X = np.array(X, dtype=float, copy=True)
        for name, fn in self.derived.items():
            X[:, self.idx[name]] = fn(self, X)
        return X

    def project(self, X_adv: np.ndarray, X_orig: np.ndarray) -> np.ndarray:
        """Nearest-ish realisable flow: fixed reset, monotone/range clamps, relations, derived."""
        X = np.array(X_orig, dtype=float, copy=True)
        for n in self.up:
            j = self.idx[n]
            X[:, j] = np.maximum(X_adv[:, j], X_orig[:, j])
        for n, (lo, hi) in self.free.items():
            j = self.idx[n]
            X[:, j] = np.clip(X_adv[:, j], lo, hi)
        for n in self.integer:
            j = self.idx[n]
            if n in self.up:
                X[:, j] = np.maximum(np.ceil(np.round(X[:, j], 6)), X_orig[:, j])
            else:
                X[:, j] = np.round(X[:, j])
        if self.relations is not None:
            X = self.relations(self, X, X_orig)
        return self.recompute(X)

    def is_valid(self, X: np.ndarray, X_orig: np.ndarray, tol: float = 1e-6) -> np.ndarray:
        X = np.asarray(X, dtype=float)
        X_orig = np.asarray(X_orig, dtype=float)

        def close(a, b):
            return np.abs(a - b) <= tol * (1 + np.abs(b)) + 1e-9

        ok = np.all(np.isfinite(X), axis=1) & np.all(X >= -tol, axis=1)
        for n in self.fixed:
            ok &= close(self.col(X, n), self.col(X_orig, n))
        for n in self.up:
            ok &= self.col(X, n) >= self.col(X_orig, n) * (1 - tol) - tol
        for n, (lo, hi) in self.free.items():
            v = self.col(X, n)
            ok &= (v >= lo - tol) & (v <= hi + tol)
        for n in self.integer:
            v = self.col(X, n)
            ok &= np.abs(v - np.round(v)) <= 1e-6
        R = self.recompute(X)
        for n in self.derived:
            ok &= close(self.col(X, n), self.col(R, n))
        if self.relations_ok is not None:
            ok &= self.relations_ok(self, X, X_orig, tol)
        return ok


# ----------------------------------------------------------------------------
# CIC-IDS2017 (CICFlowMeter) schema. Byte counts are *payload* bytes.
# ----------------------------------------------------------------------------
def _cic_relations(s: Schema, X: np.ndarray, X0: np.ndarray) -> np.ndarray:
    fp, fb, mx = s.idx["fwd_pkts"], s.idx["fwd_bytes"], s.idx["fwd_pkt_len_max"]
    cap = np.maximum(MTU, X0[:, mx])  # existing packets may already exceed MTU (offload)
    X[:, fb] = np.clip(X[:, fb], X0[:, fb], np.maximum(X[:, fp] * cap, X0[:, fb]))
    lo = np.maximum(X0[:, mx], np.ceil(np.round(X[:, fb] / np.maximum(X[:, fp], 1.0), 6)))
    hi = np.maximum(np.minimum(X[:, fb], cap), lo)
    X[:, mx] = np.clip(X[:, mx], lo, hi)
    return X


def _cic_relations_ok(s: Schema, X, X0, tol):
    fp, fb, mx = s.col(X, "fwd_pkts"), s.col(X, "fwd_bytes"), s.col(X, "fwd_pkt_len_max")
    cap = np.maximum(MTU, s.col(X0, "fwd_pkt_len_max"))
    ok = fb <= np.maximum(fp * cap, s.col(X0, "fwd_bytes")) * (1 + tol) + tol
    ok &= mx * (1 + tol) + tol >= fb / np.maximum(fp, 1.0)
    ok &= (mx <= np.maximum(fb, s.col(X0, "fwd_pkt_len_max")) * (1 + tol) + tol)
    return ok


def _mean_iat(s, X):
    n = s.col(X, "fwd_pkts") + s.col(X, "bwd_pkts")
    return s.col(X, "duration") / np.maximum(n - 1.0, 1.0)


def _fwd_bpp(s, X):
    return s.col(X, "fwd_bytes") / np.maximum(s.col(X, "fwd_pkts"), 1.0)


def _pkt_ratio(s, X):
    return s.col(X, "fwd_pkts") / (s.col(X, "bwd_pkts") + 1.0)


def _bytes_per_s(s, X):
    tot = s.col(X, "fwd_bytes") + s.col(X, "bwd_bytes")
    return tot / np.maximum(s.col(X, "duration"), 1e-6)


CIC_FEATURES = [
    "duration", "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes", "fwd_pkt_len_max",
    "bwd_pkt_len_max", "syn_count", "dst_port", "init_win_fwd", "init_win_bwd",
    "mean_iat", "fwd_bpp", "pkt_ratio", "bytes_per_s",
]

CIC_SCHEMA = Schema(
    name="cicids2017",
    features=CIC_FEATURES,
    up=["duration", "fwd_pkts", "fwd_bytes", "fwd_pkt_len_max"],
    free={"init_win_fwd": (0.0, 65535.0)},
    integer=["fwd_pkts", "fwd_bytes", "fwd_pkt_len_max", "init_win_fwd"],
    derived={"mean_iat": _mean_iat, "fwd_bpp": _fwd_bpp, "pkt_ratio": _pkt_ratio,
             "bytes_per_s": _bytes_per_s},
    relations=_cic_relations,
    relations_ok=_cic_relations_ok,
    notes={
        "duration": "attacker may delay (only increase)",
        "fwd_pkts": "attacker may add packets (integer, only increase)",
        "fwd_bytes": "attacker may pad payload; <= fwd_pkts * MTU",
        "fwd_pkt_len_max": "may grow by padding one packet; mean <= max <= min(fwd_bytes, MTU)",
        "init_win_fwd": "client TCP initial window: attacker sets any value in [0, 65535]",
        "bwd_*, syn_count, dst_port, init_win_bwd": "server/protocol bound: fixed",
        "mean_iat, fwd_bpp, pkt_ratio, bytes_per_s": "derived from base features",
    },
)


# ----------------------------------------------------------------------------
# UNSW-NB15 (Argus/Bro) schema. Byte counts include headers.
# ----------------------------------------------------------------------------
def _unsw_relations(s: Schema, X: np.ndarray, X0: np.ndarray) -> np.ndarray:
    sp, sb = s.idx["spkts"], s.idx["sbytes"]
    added = X[:, sp] - X0[:, sp]
    # each added packet carries >= 40 B of headers and <= MTU; existing ones pad to MTU
    lo = X0[:, sb] + 40.0 * added
    hi = np.maximum(X[:, sp] * MTU, lo)
    X[:, sb] = np.clip(X[:, sb], lo, hi)
    return X


def _unsw_relations_ok(s: Schema, X, X0, tol):
    added = s.col(X, "spkts") - s.col(X0, "spkts")
    sb = s.col(X, "sbytes")
    lo = s.col(X0, "sbytes") + 40.0 * added
    return (sb >= lo * (1 - tol) - tol) & (sb <= np.maximum(s.col(X, "spkts") * MTU, lo) * (1 + tol) + tol)


def _smean(s, X):
    return s.col(X, "sbytes") / np.maximum(s.col(X, "spkts"), 1.0)


def _dmean(s, X):
    return s.col(X, "dbytes") / np.maximum(s.col(X, "dpkts"), 1.0)


def _sload(s, X):
    return s.col(X, "sbytes") * 8.0 / np.maximum(s.col(X, "dur"), 1e-6)


def _dload(s, X):
    return s.col(X, "dbytes") * 8.0 / np.maximum(s.col(X, "dur"), 1e-6)


def _rate(s, X):
    return (s.col(X, "spkts") + s.col(X, "dpkts") - 1.0).clip(0) / np.maximum(s.col(X, "dur"), 1e-6)


def _sinpkt(s, X):
    return 1000.0 * s.col(X, "dur") / np.maximum(s.col(X, "spkts") - 1.0, 1.0)


UNSW_FEATURES = [
    "dur", "spkts", "dpkts", "sbytes", "dbytes", "sttl", "dttl", "swin", "dwin",
    "trans_depth", "ct_srv_src", "ct_dst_ltm", "ct_src_ltm", "ct_srv_dst",
    "proto_tcp", "proto_udp", "smean", "dmean", "sload", "dload", "rate", "sinpkt",
]

UNSW_SCHEMA = Schema(
    name="unsw_nb15",
    features=UNSW_FEATURES,
    up=["dur", "spkts", "sbytes"],
    free={"sttl": (1.0, 255.0), "swin": (0.0, 255.0)},
    integer=["spkts", "sbytes", "sttl", "swin"],
    derived={"smean": _smean, "dmean": _dmean, "sload": _sload, "dload": _dload,
             "rate": _rate, "sinpkt": _sinpkt},
    relations=_unsw_relations,
    relations_ok=_unsw_relations_ok,
    notes={
        "dur, spkts, sbytes": "attacker may delay / add packets / pad (only increase)",
        "sttl": "source IP TTL: attacker sets any value in [1, 255]",
        "swin": "source TCP window (Argus scaled): attacker sets any value in [0, 255]",
        "dpkts, dbytes, dttl, dwin, trans_depth, ct_*, proto_*": "fixed",
        "smean, dmean, sload, dload, rate, sinpkt": "derived from base features",
    },
)

SCHEMAS = {s.name: s for s in (CIC_SCHEMA, UNSW_SCHEMA)}
