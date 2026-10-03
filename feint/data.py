"""Datasets: CIC-IDS2017 and UNSW-NB15 loaders plus a synthetic generator for CI.

Every loader returns a :class:`Dataset` whose columns follow a :mod:`feint.schema`
schema. Derived features are always *recomputed* from base features so that clean
flows satisfy the same constraints as adversarial ones.
"""
from __future__ import annotations

import os
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import numpy as np

from .schema import CIC_SCHEMA, IOT_SCHEMA, MTU, UNSW_SCHEMA, Schema

if TYPE_CHECKING:
    import pandas as pd


def data_root() -> Path:
    """Dataset root: ``$FEINT_DATA`` if set, else ``./data`` in the current working directory."""
    return Path(os.environ.get("FEINT_DATA") or Path.cwd() / "data")


DATA_ROOT = data_root()  # kept for backwards compatibility; loaders call data_root() at run time


@dataclass
class Dataset:
    """Flows in schema column order with binary labels, attack families and grouping info."""

    X: np.ndarray
    y: np.ndarray  # 1 = malicious
    feature_names: list
    schema: Schema = CIC_SCHEMA
    attack: np.ndarray | None = None  # per-row attack family ("BENIGN" for benign)
    group: np.ndarray | None = None  # e.g. capture day (CIC) or official split (UNSW)
    info: dict = field(default_factory=dict)

    def subset(self, m: np.ndarray) -> Dataset:
        """Rows selected by the boolean mask or index array ``m`` (``info`` is copied)."""
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

    def block(k: int, dur: float, fp: float, bp: float, fbpp: float, bbpp: float, syn: float,
              ports: Sequence[int] | np.ndarray, win_f: Sequence[int], win_b: Sequence[int],
              name: str) -> tuple[np.ndarray, list[str]]:
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

# The same 11 CICFlowMeter quantities under the header spellings of CSE-CIC-IDS2018
# (CICFlowMeter-V3) and of the corrected CIC-IDS2017 / CIC-IDS2018 re-release of Engelen et al.
# (SPW 2021) and Liu et al. (CNS 2022). Matching is on lower-cased alphanumerics only.
CIC_ALIASES = {
    "Flow Duration": ["Flow Duration"],
    "Total Fwd Packets": ["Total Fwd Packets", "Tot Fwd Pkts", "Total Fwd Packet"],
    "Total Backward Packets": ["Total Backward Packets", "Tot Bwd Pkts", "Total Bwd packets"],
    "Total Length of Fwd Packets": ["Total Length of Fwd Packets", "TotLen Fwd Pkts",
                                    "Total Length of Fwd Packet"],
    "Total Length of Bwd Packets": ["Total Length of Bwd Packets", "TotLen Bwd Pkts",
                                    "Total Length of Bwd Packet"],
    "Fwd Packet Length Max": ["Fwd Packet Length Max", "Fwd Pkt Len Max"],
    "Bwd Packet Length Max": ["Bwd Packet Length Max", "Bwd Pkt Len Max"],
    "SYN Flag Count": ["SYN Flag Count", "SYN Flag Cnt"],
    "Destination Port": ["Destination Port", "Dst Port"],
    "Init_Win_bytes_forward": ["Init_Win_bytes_forward", "Init Fwd Win Byts", "FWD Init Win Bytes"],
    "Init_Win_bytes_backward": ["Init_Win_bytes_backward", "Init Bwd Win Byts", "Bwd Init Win Bytes"],
    "Label": ["Label"],
}


def _key(c: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(c).lower())


def _canonical_columns(columns: Iterable[str]) -> dict:
    """Map raw CSV header names to the canonical CIC-IDS2017 names (only the ones we use)."""
    lookup = {_key(a): canon for canon, al in CIC_ALIASES.items() for a in al}
    out = {}
    for c in columns:
        canon = lookup.get(_key(c))
        if canon and canon not in out.values():
            out[c] = canon
    return out


def _norm_family(label: str, attempted: str = "benign") -> str:
    """Normalise labels across releases: 'Benign' -> 'BENIGN'; '... - Attempted' handling."""
    s = _norm_label(label)
    if s.lower() == "benign":
        return "BENIGN"
    if "attempted" in s.lower():
        # attack flows without attack payload (Engelen et al. 2021): benign by default
        return "BENIGN" if attempted == "benign" else re.sub(r"\s*-\s*Attempted", "", s, flags=re.I)
    return s


# families present in both CIC-IDS2017 and CSE-CIC-IDS2018, for cross-dataset evaluation
SHARED_FAMILIES = {
    "FTP-Patator": "FTP brute force", "FTP-BruteForce": "FTP brute force",
    "SSH-Patator": "SSH brute force", "SSH-Bruteforce": "SSH brute force",
    "DoS GoldenEye": "DoS GoldenEye", "DoS attacks-GoldenEye": "DoS GoldenEye",
    "DoS slowloris": "DoS Slowloris", "DoS attacks-Slowloris": "DoS Slowloris",
    "DoS Hulk": "DoS Hulk", "DoS attacks-Hulk": "DoS Hulk",
    "DoS Slowhttptest": "DoS SlowHTTPTest", "DoS attacks-SlowHTTPTest": "DoS SlowHTTPTest",
    "Bot": "Bot", "BENIGN": "BENIGN",
}


def _norm_label(s: str) -> str:
    s = re.sub(r"[^\x20-\x7e]+", "-", str(s)).strip()
    return re.sub(r"\s*-+\s*", " - ", s) if "Web Attack" in s else s


def _frame_to_cic(df: pd.DataFrame, source: str = "",
                  attempted: str = "benign") -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    import pandas as pd

    df = df.rename(columns=_canonical_columns(df.columns))
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
    raw = df["Label"].astype(str).to_numpy()
    uniq, inv = np.unique(raw, return_inverse=True)
    labels = np.array([_norm_family(v, attempted) for v in uniq], dtype=object)[inv].astype(str)
    ok &= labels != "Label"  # header rows repeated inside some CSE-CIC-IDS2018 day files
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

    ``frac`` uniformly subsamples every class, but every class keeps at least
    ``keep_rare`` flows (classes smaller than that are kept whole: Heartbleed,
    Infiltration, SQLi ...). The sampled matrix is cached next to the CSVs.
    Exact duplicate (features, label) rows are dropped *before* splitting so the
    same flow cannot sit in both train and test. ``group`` is the capture-day index.
    """
    import pandas as pd

    root = Path(root) if root else data_root() / "cicids2017"
    cache = Path(root) / f".feint_cache_f{frac}_k{keep_rare}_s{seed}_d{int(dedup)}.npz"
    if cache.exists():
        c = np.load(cache, allow_pickle=False)
        import json

        return Dataset(c["X"], c["y"], list(CIC_SCHEMA.features), CIC_SCHEMA, c["attack"].astype(str),
                       c["group"], json.loads(str(c["info"])))
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
    try:
        import json

        np.savez_compressed(cache, X=X, y=y, attack=lab.astype("U32"), group=grp, info=json.dumps(info))
    except OSError:  # read-only data dir: caching is best-effort
        pass
    return Dataset(X, y, list(CIC_SCHEMA.features), CIC_SCHEMA, lab, grp, info)


# ------------------------------------------------- CSE-CIC-IDS2018 / corrected CIC-IDS2017
def _read_cic_files(files: Sequence[Path], name: str, per_class: int, seed: int, attempted: str = "benign",
                    chunksize: int = 250_000, info_extra: dict | None = None) -> Dataset:
    """Stream CICFlowMeter CSVs in chunks (12 columns only) with per-class reservoir caps.

    Memory stays at O(per_class x classes) regardless of file size, so the 16 GB laptop and
    the 7 GB Actions runner can both read multi-GB day files. Exact duplicate (features, label)
    rows are dropped within the kept sample.
    """
    import pandas as pd

    rng = np.random.default_rng(seed)
    keep: dict[str, list] = {}
    seen: dict[str, int] = {}
    n_raw = 0
    for gi, f in enumerate(files):
        head = pd.read_csv(f, nrows=0, encoding="latin-1").columns
        cols = list(_canonical_columns(head))
        for df in pd.read_csv(f, usecols=cols, encoding="latin-1", low_memory=False, chunksize=chunksize):
            n_raw += len(df)
            X, lab, _ = _frame_to_cic(df, Path(f).name, attempted)
            for c in np.unique(lab):
                rows = X[lab == c]
                buf = keep.setdefault(c, [])
                for r in rows:  # reservoir sampling per class
                    k = seen.get(c, 0)
                    if k < per_class:
                        buf.append((r, gi))
                    else:
                        j = rng.integers(0, k + 1)
                        if j < per_class:
                            buf[j] = (r, gi)
                    seen[c] = k + 1
    X = np.array([r for c in sorted(keep) for r, _ in keep[c]])
    grp = np.array([g for c in sorted(keep) for _, g in keep[c]], dtype=int)
    lab = np.array([c for c in sorted(keep) for _ in keep[c]])
    key = pd.DataFrame(X).assign(_l=lab)
    m = ~key.duplicated().to_numpy()
    X, lab, grp = X[m], lab[m], grp[m]
    y = (lab != "BENIGN").astype(int)
    info = {"name": name, "files": [Path(f).name for f in files], "rows_raw": int(n_raw),
            "per_class_cap": per_class, "class_counts_seen": {k: int(v) for k, v in seen.items()},
            "class_counts": {str(c): int((lab == c).sum()) for c in np.unique(lab)},
            "attempted": attempted, **(info_extra or {})}
    return Dataset(X, y, list(CIC_SCHEMA.features), CIC_SCHEMA, lab, grp, info)


def load_cicids2018(root: str | Path | None = None, per_class: int = 20_000, seed: int = 0) -> Dataset:
    """CSE-CIC-IDS2018 day CSVs (CICFlowMeter-V3), subsampled to ``per_class`` flows per label."""
    root = Path(root) if root else data_root() / "cicids2018"
    files = sorted(Path(root).glob("*_TrafficForML_CICFlowMeter.csv"))
    if not files:
        raise FileNotFoundError(f"no CSE-CIC-IDS2018 CSVs under {root}; run scripts/download_cicids2018.py "
                                "or set FEINT_DATA / --data-dir")
    return _read_cic_files(files, "cicids2018", per_class, seed)


def load_cicids2017_corrected(root: str | Path | None = None, per_class: int = 20_000, seed: int = 0,
                              attempted: str = "benign") -> Dataset:
    """Corrected CIC-IDS2017 (Engelen et al. 2021 / Liu et al. 2022), per-class subsample.

    ``attempted='benign'`` relabels '... - Attempted' flows (no attack payload) as benign, per the
    authors' guidance; ``'attack'`` keeps them as their parent attack class (sensitivity run).
    """
    root = Path(root) if root else data_root() / "cicids2017-corrected"
    files = sorted(p for p in Path(root).glob("*.csv") if p.stem.lower() in {d.lower() for d in CIC_DAYS})
    if not files:
        raise FileNotFoundError(f"no corrected CIC-IDS2017 CSVs under {root}; run "
                                "scripts/download_cicids2017_corrected.py or set FEINT_DATA / --data-dir")
    return _read_cic_files(files, "cicids2017-corrected", per_class, seed, attempted)


# ----------------------------------------------------------------------------- CICIoT2023
IOT_COLS = ["duration", "packets", "bytes", "packets_rev", "bytes_rev", "dst_port", "protocol", "label_class"]


def _frame_to_iot(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    s = IOT_SCHEMA
    X = np.zeros((len(df), len(s.features)))
    for c in ("duration", "packets", "bytes", "packets_rev", "bytes_rev", "dst_port"):
        X[:, s.idx[c]] = np.maximum(np.nan_to_num(df[c].to_numpy(dtype=float)), 0.0)
    X[:, s.idx["packets"]] = np.maximum(X[:, s.idx["packets"]], 1.0)
    proto = df["protocol"].to_numpy()
    X[:, s.idx["proto_tcp"]] = (proto == 6).astype(float)
    X[:, s.idx["proto_udp"]] = (proto == 17).astype(float)
    lab = df["label_class"].astype(str).to_numpy()
    lab = np.where(np.char.find(np.char.lower(lab.astype(str)), "benign") >= 0, "BENIGN", lab)
    return s.recompute(X), lab


def load_ciciot2023(root: str | Path | None = None, per_class: int = 5_000, seed: int = 0) -> Dataset:
    """CICIoT2023 subsample from the ipfixprobe Parquet re-export (needs the ``data`` extra: pyarrow).

    Labels are the source capture of each file. At most ``per_class`` flows are kept per label
    (16 GB RAM; one Parquet file per attack class, see scripts/download_ciciot2023.py). Results on
    these features are not comparable with the official CSV features of Neto et al. (2023).
    """
    import pandas as pd

    root = Path(root) if root else data_root() / "ciciot2023"
    files = sorted(Path(root).glob("*.parquet"))
    if not files:
        raise FileNotFoundError(f"no CICIoT2023 Parquet files under {root}; run "
                                "scripts/download_ciciot2023.py or set FEINT_DATA / --data-dir")
    rng = np.random.default_rng(seed)
    parts = []
    for f in files:
        df = pd.read_parquet(f, columns=IOT_COLS)
        if len(df) > per_class:
            df = df.iloc[rng.choice(len(df), size=per_class, replace=False)]
        parts.append(df)
    X, lab = _frame_to_iot(pd.concat(parts, ignore_index=True))
    keep = np.zeros(len(lab), dtype=bool)
    for c in np.unique(lab):
        idx = np.flatnonzero(lab == c)
        keep[rng.choice(idx, size=min(per_class, len(idx)), replace=False)] = True
    X, lab = X[keep], lab[keep]
    y = (lab != "BENIGN").astype(int)
    info = {"name": "ciciot2023", "files": len(files), "per_class_cap": per_class,
            "source": "ipfixprobe re-export (Hugging Face Lystea/CICIOT2023-PARQUET)",
            "class_counts": {str(c): int((lab == c).sum()) for c in np.unique(lab)}}
    return Dataset(X, y, list(IOT_SCHEMA.features), IOT_SCHEMA, lab, np.zeros(len(y), dtype=int), info)


# ----------------------------------------------------------------------------- UNSW-NB15
UNSW_DIRECT = ["dur", "spkts", "dpkts", "sbytes", "dbytes", "sttl", "dttl", "swin", "dwin",
               "trans_depth", "ct_srv_src", "ct_dst_ltm", "ct_src_ltm", "ct_srv_dst"]


def _frame_to_unsw(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
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

    root = Path(root) if root else data_root() / "unsw-nb15"
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
