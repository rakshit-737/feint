"""Model-stealing study: a label-only API is enough to build a transfer-attack surrogate.

The attacker queries the deployed detector's *hard verdicts* on flows it can observe or craft
(here: an unlabelled pool drawn from the training distribution), fits an MLP on the stolen
labels, then attacks the victim by pure transfer (constrained PGD on the stolen copy, zero score
queries to the victim). Reported per query budget: agreement with the victim on the test set and
victim detection rate on the transferred adversarial flows.
"""
from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

import numpy as np

from .attack import pgd
from .model import BaseDetector, MLPDetector, Preprocessor, XGBDetector
from .pipeline import StudyConfig, _log, split

if TYPE_CHECKING:
    from .data import Dataset


def steal_study(ds: Dataset, budgets: Sequence[int] = (500, 2000, 10000), eps: Sequence[float] = (0.5, 1.0, 2.0),
                cfg: StudyConfig | None = None) -> dict:
    """Steal an XGBoost victim with ``budgets`` label-only queries and attack it by transfer.

    Returns test-set agreement and victim detection per budget, plus a reference surrogate
    trained on the true labels (see the module docstring).
    """
    cfg = cfg or StudyConfig()
    rng = np.random.default_rng(cfg.seed)
    tr, te, split_desc = split(ds, cfg.seed)
    pre = Preprocessor().fit(tr.X)
    victim = XGBDetector(seed=cfg.seed, n_estimators=cfg.xgb_trees, max_depth=4 if cfg.fast else 8)
    victim.pre = pre
    victim.fit_z(pre.transform(tr.X), tr.y)
    mal = np.flatnonzero(te.y == 1)
    X_mal = te.X[rng.choice(mal, size=min(cfg.max_eval, len(mal)), replace=False)]
    v_te = victim.predict(te.X)

    def transfer(sur: BaseDetector) -> dict:
        evaded = victim.predict(X_mal) == 0
        out = {"0.0": float((~evaded).mean())}
        for e in sorted(eps):  # monotone: a larger budget may reuse a smaller one's evasion
            Xa = pgd(sur, X_mal, ds.schema, eps=e, steps=cfg.steps)
            evaded |= victim.predict(Xa) == 0
            out[str(float(e))] = float((~evaded).mean())
        return out

    res = {"victim": "xgboost", "split": split_desc, "n_eval": int(len(X_mal)), "budgets": {}}
    # reference: surrogate trained on the true labels of the whole training set
    ref = MLPDetector(hidden=cfg.mlp_hidden, seed=cfg.seed, max_iter=60 if cfg.fast else 200)
    ref.pre = pre
    ref.fit_z(pre.transform(tr.X), tr.y)
    res["true_label_surrogate"] = {"agreement": float((ref.predict(te.X) == v_te).mean()),
                                   "victim_detection": transfer(ref)}
    for q in budgets:
        q = int(min(q, len(tr.y)))
        Xq = tr.X[rng.choice(len(tr.y), size=q, replace=False)]
        yq = victim.predict(Xq)  # label-only oracle
        if len(set(yq.tolist())) < 2:
            continue
        pre_q = Preprocessor().fit(Xq)  # the attacker standardises on its own sample
        sur = MLPDetector(hidden=cfg.mlp_hidden, seed=cfg.seed, max_iter=60 if cfg.fast else 200)
        sur.pre = pre_q
        sur.fit_z(pre_q.transform(Xq), yq)
        res["budgets"][str(q)] = {"agreement": float((sur.predict(te.X) == v_te).mean()),
                                  "victim_detection": transfer(sur)}
        _log(f"  stolen with {q} queries: agreement {res['budgets'][str(q)]['agreement']:.3f}")
    return res


def to_markdown(r: dict) -> str:
    """Markdown table of a model-stealing study."""
    eps = list(r["true_label_surrogate"]["victim_detection"])
    L = ["## Model stealing (label-only queries -> transfer attack)", "",
         f"Victim: {r['victim']}; {r['n_eval']} held-out attack flows; transfer = constrained PGD on the "
         "surrogate, no score queries to the victim. "
         "Victim detection rate (higher is better for the defender).", "",
         "| surrogate | test agreement | " + " | ".join(f"eps={e}" for e in eps) + " |",
         "|---|---|" + "---|" * len(eps)]
    rows = [("true labels, full training set", r["true_label_surrogate"])]
    rows += [(f"stolen, {q} label queries", v) for q, v in r["budgets"].items()]
    for name, v in rows:
        L.append(f"| {name} | {v['agreement']:.3f} | "
                 + " | ".join(f"{v['victim_detection'][e]:.3f}" for e in eps) + " |")
    return "\n".join(L) + "\n"
