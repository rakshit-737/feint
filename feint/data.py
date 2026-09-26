"""Datasets: CIC-IDS2017 and UNSW-NB15 loaders plus a synthetic generator for CI.

Every loader returns a :class:`Dataset` whose columns follow a :mod:`feint.schema`
schema. Derived features are always *recomputed* from base features so that clean
flows satisfy the same constraints as adversarial ones.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from .schema import CIC_SCHEMA, MTU, UNSW_SCHEMA, Schema

DATA_ROOT = Path(os.environ.get("FEINT_DATA", Path(__file__).resolve().parents[1] / "data"))


@dataclass
class Dataset:
    X: np.ndarray
    y: np.ndarray  # 1 = malicious
    feature_names: list
    schema: Schema = CIC_SCHEMA
    attack: np.ndarray | None = None  # per-row attack family ("BENIGN" for benign)
    group: np.ndarray | None = None  # e.g. capture day (CIC) or official split (UNSW)
    info: dict = field(default_factory=dict)

    def subset(self, m: np.ndarray) -> Dataset:
        return Dataset(self.X[m], self.y[m], self.feature_names, self.schema,
                       None if self.attack is None else self.attack[m],
                       None if self.group is None else self.group[m], dict(self.info))

    def __len__(self) -> int:
        return len(self.y)


# ----------------------------------------------------------------------------- synthetic
def synthetic_flows(n: int = 4000, attack_frac: float = 0.3, seed: int = 0) -> Dataset:
    """Synthetic CIC-schema flows (benign web/bulk; scan, DoS, brute-force attacks).

    Only used for CI and smoke tests; every published number comes from real data.
    """
    s = CIC_SCHEMA
    rng = np.random.default_rng(seed)
    n_att = int(n * attack_frac)
    n_ben = n - n_att

    def block(k, dur, fp, bp, fbpp, bbpp, syn, ports, win_f, win_b, name):
        X = np.zeros((k, len(s.features)))
        fwd_pkts = np.maximum(1, rng.poisson(fp, k)).astype(float)
        bwd_pkts = rng.poisson(bp, k).astype(float)
        fbpp_ = np.clip(rng.normal(fbpp, fbpp * 0.25, k), 0, MTU)
        bbpp_ = np.clip(rng.normal(bbpp, bbpp * 0.25, k), 0, MTU)
        X[:, s.idx["duration"]] = rng.lognormal(np.log(dur), 0.6, k)
        X[:, s.idx["fwd_pkts"]] = fwd_pkts
        X[:, s.idx["bwd_pkts"]] = bwd_pkts
        X[:, s.idx["fwd_bytes"]] = np.round(fwd_pkts * fbpp_)
        X[:, s.idx["bwd_bytes"]] = np.round(bwd_pkts * bbpp_)
        X[:, s.idx["fwd_pkt_len_max"]] = np.minimum(np.ceil(fbpp_ * rng.uniform(1.0, 2.0, k)),
                                                    np.maximum(X[:, s.idx["fwd_bytes"]], 0))
        X[:, s.idx["fwd_pkt_len_max"]] = np.maximum(X[:, s.idx["fwd_pkt_len_max"]],
                                                    np.ceil(X[:, s.idx["fwd_bytes"]] / fwd_pkts))
        X[:, s.idx["bwd_pkt_len_max"]] = np.ceil(bbpp_ * rng.uniform(1.0, 2.0, k)) * (bwd_pkts > 0)
        X[:, s.idx["syn_count"]] = rng.poisson(syn, k)
        X[:, s.idx["dst_port"]] = rng.choice(ports, k)
        X[:, s.idx["init_win_fwd"]] = rng.choice(win_f, k)
        X[:, s.idx["init_win_bwd"]] = rng.choice(win_b, k)
        return X, [name] * k

    k = n_att // 3
    parts = [
        block(n_ben // 2, 8.0, 20, 25, 300, 900, 1, [80, 443], [8192, 29200, 65535], [28960, 235], "BENIGN"),
        block(n_ben - n_ben // 2, 30.0, 60, 55, 500, 500, 1, [443, 22, 53], [29200, 65535], [28960, 65535],
              "BENIGN"),
        block(k, 0.05, 2, 1, 5, 5, 1, np.arange(1, 1024), [1024, 29200], [0], "PortScan"),
        block(k, 1.0, 120, 3, 80, 60, 3, [80], [29200, 8192], [235], "DoS"),
        block(n_att - 2 * k, 5.0, 16, 16, 200, 400, 1, [21, 22], [29200], [235, 28960], "Patator"),
    ]
    X = s.recompute(np.vstack([p[0] for p in parts]))
    attack = np.array(sum((p[1] for p in parts), []))
    y = (attack != "BENIGN").astype(int)
    p = rng.permutation(len(y))
    return Dataset(X[p], y[p], list(s.features), s, attack[p], np.zeros(len(y), dtype=int),
                   {"name": "synthetic", "n": int(n)})


# ----------------------------------------------------------------------------- CIC-IDS2017
# CICFlowMeter header -> (schema feature, scale to schema units)
CIC_MAP = {
    "Flow Duration": ("duration", 1e-6),  # microseconds -> seconds
    "Total Fwd Packets": ("fwd_pkts", 1.0),
    "Total Backward Packets": ("bwd_pkts", 1.0),
    "Total Length of Fwd Packets": ("fwd_bytes", 1.0),
    "Total Length of Bwd Packets": ("bwd_bytes", 1.0),
    "Fwd Packet Length Max": ("fwd_pkt_len_max", 1.0),
    "Bwd Packet Length Max": ("bwd_pkt_len_max", 1.0),
    "SYN Flag Count": ("syn_count", 1.0),
    "Destination Port": ("dst_port", 1.0),
    "Init_Win_bytes_forward": ("init_win_fwd", 1.0),
    "Init_Win_bytes_backward": ("init_win_bwd", 1.0),
}
CIC_DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]


def _norm_label(s: str) -> str:
    s = re.sub(r"[^\x20-\x7e]+", "-", str(s)).strip()
    return re.sub(r"\s*-+\s*", " - ", s) if "Web Attack" in s else s


def _frame_to_cic(df, source: str = "") -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    import pandas as pd

    df = df.rename(columns=lambda c: c.strip())
    missing = [c for c in list(CIC_MAP) + ["Label"] if c not in df.columns]
    if missing:
        raise ValueError(f"{source}: CSV missing columns {missing}")
    s = CIC_SCHEMA
    X = np.zeros((len(df), len(s.features)))
    ok = np.ones(len(df), dtype=bool)
    for col, (name, scale) in CIC_MAP.items():
        v = pd.to_numeric(df[col], errors="coerce").to_numpy(dtype=float) * scale
        ok &= np.isfinite(v)
        X[:, s.idx[name]] = np.maximum(np.nan_to_num(v), 0.0)  # CIC uses -1 for "no window"
    X[:, s.idx["fwd_pkts"]] = np.maximum(X[:, s.idx["fwd_pkts"]], 1.0)
    # CICFlowMeter occasionally reports max > total (fragment accounting); repair minimally
    fb, mx, fp = s.idx["fwd_bytes"], s.idx["fwd_pkt_len_max"], s.idx["fwd_pkts"]
    X[:, mx] = np.clip(X[:, mx], np.ceil(np.round(X[:, fb] / X[:, fp], 6)), np.maximum(X[:, fb], 0))
    labels = np.array([_norm_label(v) for v in df["Label"].astype(str)])
    return s.recompute(X[ok]), labels[ok], ok


def load_cicids_csv(path: str | Path, max_rows: int | None = None) -> Dataset:
    """Load one CIC-IDS2017 MachineLearningCVE CSV (or any CICFlowMeter CSV with labels)."""
    import pandas as pd

    df = pd.read_csv(path, nrows=max_rows, encoding="latin-1", low_memory=False)
    X, labels, _ = _frame_to_cic(df, str(path))
    if len(X) == 0:
        raise ValueError("no usable rows")
    y = (labels != "BENIGN").astype(int)
    return Dataset(X, y, list(CIC_SCHEMA.features), CIC_SCHEMA, labels,
                   np.zeros(len(y), dtype=int), {"name": "cicids2017-csv", "path": str(path)})


def load_cicids2017(root: str | Path | None = None, frac: float = 0.1, keep_rare: int = 5000,
                    seed: int = 0, dedup: bool = True) -> Dataset:
    """Load CIC-IDS2017 MachineLearningCVE (all 8 day files).

    ``frac`` uniformly subsamples every class, except classes with fewer than
    ``keep_rare`` flows which are kept whole (Heartbleed, Infiltration, SQLi ...).
    Exact duplicate (features, label) rows are dropped *before* splitting so the
    same flow cannot sit in both train and test. ``group`` is the capture-day index.
    """
    import pandas as pd

    root = Path(root) if root else DATA_ROOT / "cicids2017"
    files = sorted(Path(root).rglob("*pcap_ISCX.csv"))
    if not files:
        raise FileNotFoundError(f"no CIC-IDS2017 CSVs under {root}; run scripts/download_cicids2017.py")
    rng = np.random.default_rng(seed)
    Xs, Ls, Gs = [], [], []
    n_raw = 0
    for f in files:
        day = next(i for i, d in enumerate(CIC_DAYS) if f.name.lower().startswith(d.lower()))
        head = pd.read_csv(f, nrows=0, encoding="latin-1").columns
        cols = [c for c in head if c.strip() in CIC_MAP or c.strip() == "Label"]
        df = pd.read_csv(f, usecols=cols, encoding="latin-1", low_memory=False)
        n_raw += len(df)
        X, lab, _ = _frame_to_cic(df, f.name)
        Xs.append(X)
        Ls.append(lab)
        Gs.append(np.full(len(lab), day))
    X, lab, grp = np.vstack(Xs), np.concatenate(Ls), np.concatenate(Gs)
    n_finite = len(lab)
    if dedup:
        key = pd.DataFrame(X).assign(_l=lab)
        keep = ~key.duplicated().to_numpy()
        X, lab, grp = X[keep], lab[keep], grp[keep]
    n_dedup = len(lab)
    classes, counts = np.unique(lab, return_counts=True)
    sel = np.zeros(len(lab), dtype=bool)
    for c, k in zip(classes, counts):
        idx = np.flatnonzero(lab == c)
        take = k if k < keep_rare else max(keep_rare, int(round(k * frac)))
        sel[rng.choice(idx, size=min(take, k), replace=False)] = True
    X, lab, grp = X[sel], lab[sel], grp[sel]
    y = (lab != "BENIGN").astype(int)
    info = {"name": "cicids2017", "files": len(files), "rows_raw": int(n_raw),
            "rows_finite": int(n_finite), "rows_dedup": int(n_dedup), "rows_sampled": int(len(y)),
            "frac": frac, "keep_rare": keep_rare,
            "class_counts": {str(c): int((lab == c).sum()) for c in np.unique(lab)}}
    return Dataset(X, y, list(CIC_SCHEMA.features), CIC_SCHEMA, lab, grp, info)


# ----------------------------------------------------------------------------- UNSW-NB15
UNSW_DIRECT = ["dur", "spkts", "dpkts", "sbytes", "dbytes", "sttl", "dttl", "swin", "dwin",
               "trans_depth", "ct_srv_src", "ct_dst_ltm", "ct_src_ltm", "ct_srv_dst"]


def _frame_to_unsw(df) -> tuple[np.ndarray, np.ndarray]:
    s = UNSW_SCHEMA
    X = np.zeros((len(df), len(s.features)))
    for c in UNSW_DIRECT:
        X[:, s.idx[c]] = np.maximum(df[c].to_numpy(dtype=float), 0.0)
    X[:, s.idx["sttl"]] = np.clip(X[:, s.idx["sttl"]], 1, 255)
    X[:, s.idx["proto_tcp"]] = (df["proto"] == "tcp").to_numpy(dtype=float)
    X[:, s.idx["proto_udp"]] = (df["proto"] == "udp").to_numpy(dtype=float)
    X[:, s.idx["spkts"]] = np.maximum(X[:, s.idx["spkts"]], 1.0)
    labels = df["attack_cat"].fillna("Normal").astype(str).str.strip().to_numpy()
    labels = np.where(labels == "Normal", "BENIGN", labels)
    return s.recompute(X), labels


def load_unsw_nb15(root: str | Path | None = None, split: str | None = None,
                   max_rows: int | None = None) -> Dataset:
    """Load the official UNSW-NB15 partition. ``group`` is 0 = training set, 1 = testing set."""
    import pandas as pd

    root = Path(root) if root else DATA_ROOT / "unsw-nb15"
    parts = {"train": "UNSW_NB15_training-set.csv", "test": "UNSW_NB15_testing-set.csv"}
    names = [split] if split else ["train", "test"]
    Xs, Ls, Gs = [], [], []
    for nm in names:
        p = Path(root) / parts[nm]
        if not p.exists():
            raise FileNotFoundError(f"{p} missing; run scripts/download_unsw_nb15.py")
        df = pd.read_csv(p, nrows=max_rows, encoding="utf-8-sig")
        X, lab = _frame_to_unsw(df)
        Xs.append(X)
        Ls.append(lab)
        Gs.append(np.full(len(lab), 0 if nm == "train" else 1))
    X, lab, grp = np.vstack(Xs), np.concatenate(Ls), np.concatenate(Gs)
    y = (lab != "BENIGN").astype(int)
    info = {"name": "unsw_nb15", "rows": int(len(y)),
            "class_counts": {str(c): int((lab == c).sum()) for c in np.unique(lab)}}
    return Dataset(X, y, list(UNSW_SCHEMA.features), UNSW_SCHEMA, lab, grp, info)
