"""Flow-feature schema, synthetic flow generator and optional CSV loader.

Feature schema (raw units):
  duration      flow duration, seconds            (attacker: may increase)
  fwd_pkts      packets client->server             (attacker: may increase, integer)
  bwd_pkts      packets server->client             (NOT attacker-controlled)
  fwd_bytes     bytes client->server               (attacker: may increase)
  bwd_bytes     bytes server->client               (NOT attacker-controlled)
  mean_iat      mean inter-arrival time, seconds   (attacker: may increase)
  syn_count     SYN flags seen                     (NOT controllable: protocol-bound)
  fwd_bpp       derived = fwd_bytes / fwd_pkts     (recomputed, never set directly)
  pkt_ratio     derived = fwd_pkts / (bwd_pkts+1)  (recomputed)
"""
from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

import numpy as np

FEATURES = [
    "duration", "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes",
    "mean_iat", "syn_count", "fwd_bpp", "pkt_ratio",
]
IDX = {n: i for i, n in enumerate(FEATURES)}
CONTROLLABLE = ["duration", "fwd_pkts", "fwd_bytes", "mean_iat"]
DERIVED = ["fwd_bpp", "pkt_ratio"]
MIN_PKT, MAX_PKT = 40.0, 1500.0  # bytes per packet bounds (IP+TCP header .. MTU)


@dataclass
class Dataset:
    X: np.ndarray
    y: np.ndarray  # 1 = malicious
    feature_names: list


def recompute_derived(X: np.ndarray) -> np.ndarray:
    X = X.copy()
    X[:, IDX["fwd_bpp"]] = X[:, IDX["fwd_bytes"]] / np.maximum(X[:, IDX["fwd_pkts"]], 1.0)
    X[:, IDX["pkt_ratio"]] = X[:, IDX["fwd_pkts"]] / (X[:, IDX["bwd_pkts"]] + 1.0)
    return X


def synthetic_flows(n: int = 4000, attack_frac: float = 0.3, seed: int = 0) -> Dataset:
    """Generate labelled benign / attack flows (scan, DoS and brute-force shaped).

    Classes deliberately overlap a little so the detector is not trivially perfect.
    """
    rng = np.random.default_rng(seed)
    n_att = int(n * attack_frac)
    n_ben = n - n_att

    def block(k, dur, fp, bp, fbpp, bbpp, iat, syn):
        fwd_pkts = np.maximum(1, rng.poisson(fp, k)).astype(float)
        bwd_pkts = rng.poisson(bp, k).astype(float)
        return np.column_stack([
            rng.lognormal(np.log(dur), 0.6, k),
            fwd_pkts,
            bwd_pkts,
            fwd_pkts * np.clip(rng.normal(fbpp, fbpp * 0.25, k), MIN_PKT, MAX_PKT),
            bwd_pkts * np.clip(rng.normal(bbpp, bbpp * 0.25, k), MIN_PKT, MAX_PKT),
            rng.lognormal(np.log(iat), 0.5, k),
            rng.poisson(syn, k).astype(float),
            np.zeros(k), np.zeros(k),
        ])

    ben = np.vstack([
        block(n_ben // 2, 8.0, 20, 25, 300, 900, 0.3, 1),            # web browsing
        block(n_ben - n_ben // 2, 30.0, 60, 55, 500, 500, 0.5, 1),   # interactive / bulk
    ])
    k = n_att // 3
    att = np.vstack([
        block(k, 0.05, 2, 1, 60, 60, 0.01, 2),                # port scan
        block(k, 1.0, 120, 3, 80, 60, 0.005, 40),             # SYN / DoS burst
        block(n_att - 2 * k, 5.0, 16, 16, 200, 400, 0.25, 1),  # brute-force login (overlaps web)
    ])
    X = recompute_derived(np.vstack([ben, att]))
    y = np.r_[np.zeros(len(ben)), np.ones(len(att))].astype(int)
    p = rng.permutation(len(y))
    return Dataset(X[p], y[p], list(FEATURES))


# Mapping from CIC-IDS2017 CSV headers (CICFlowMeter output) to the FEINT schema.
CIC_MAP = {
    "Flow Duration": ("duration", 1e-6),
    "Total Fwd Packets": ("fwd_pkts", 1.0),
    "Total Backward Packets": ("bwd_pkts", 1.0),
    "Total Length of Fwd Packets": ("fwd_bytes", 1.0),
    "Total Length of Bwd Packets": ("bwd_bytes", 1.0),
    "Flow IAT Mean": ("mean_iat", 1e-6),
    "SYN Flag Count": ("syn_count", 1.0),
}


def load_cicids_csv(path: str | Path, max_rows: int | None = None) -> Dataset:
    """Load a CIC-IDS2017-style CSV (optional real-data path; nothing is downloaded)."""
    rows, labels = [], []
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        reader.fieldnames = [h.strip() for h in reader.fieldnames or []]
        missing = [c for c in list(CIC_MAP) + ["Label"] if c not in reader.fieldnames]
        if missing:
            raise ValueError(f"CSV missing columns: {missing}")
        for i, r in enumerate(reader):
            if max_rows and i >= max_rows:
                break
            try:
                vec = np.zeros(len(FEATURES))
                for col, (name, scale) in CIC_MAP.items():
                    vec[IDX[name]] = max(0.0, float(r[col]) * scale)
            except (ValueError, TypeError):
                continue
            if not np.all(np.isfinite(vec)):
                continue
            vec[IDX["fwd_pkts"]] = max(vec[IDX["fwd_pkts"]], 1.0)
            rows.append(vec)
            labels.append(0 if r["Label"].strip().upper() == "BENIGN" else 1)
    if not rows:
        raise ValueError("no usable rows")
    return Dataset(recompute_derived(np.array(rows)), np.array(labels), list(FEATURES))
