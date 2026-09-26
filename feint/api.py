"""Minimal scoring + explanation API (optional ``[api]`` extra: fastapi, uvicorn).

    POST /score   {"flows": [{"duration": 0.01, "fwd_pkts": 2, ...}], "explain": true}
    GET  /schema  feature list, attacker-controllable features, constraint notes
    GET  /health

Each verdict comes from the adversarially-trained FEINT ensemble; with ``explain`` the
response adds the top TreeSHAP contributions (baseline XGBoost member) and a
constraint-valid counterfactual ("what would the attacker have to change to evade?").
"""

from pathlib import Path

import numpy as np

from .explain import counterfactual, describe_counterfactual, local_explanation
from .schema import SCHEMAS, Schema


def save_bundle(models: dict, schema: Schema, path: str | Path) -> Path:
    import joblib

    bundle = {"schema": schema.name, "detector": models["ensemble_adv_trained"],
              "explainer": models["xgboost"], "surrogate": models["mlp_adv_trained"]}
    joblib.dump(bundle, path)
    return Path(path)


def load_bundle(path: str | Path) -> dict:
    import joblib

    b = joblib.load(path)
    b["schema"] = SCHEMAS[b["schema"]]
    return b


def score_flows(bundle: dict, flows: list[dict], explain: bool = False) -> list[dict]:
    s: Schema = bundle["schema"]
    X = np.array([[float(f.get(n, 0.0)) for n in s.features] for f in flows])
    X = s.recompute(X)
    det = bundle["detector"]
    p = det.predict_proba(X)
    out = []
    for i in range(len(X)):
        r = {"p_malicious": float(p[i]), "verdict": "malicious" if p[i] >= 0.5 else "benign"}
        if explain:
            r["top_features"] = local_explanation(bundle["explainer"], X[i], s.features)
            if p[i] >= 0.5:
                cf, _ = counterfactual(det, X[i:i + 1], s, surrogate=bundle["surrogate"], iters=40)
                r["counterfactual"] = {**cf[0], "text": describe_counterfactual(cf[0])}
        out.append(r)
    return out


def create_app(model_path: str | Path):
    from fastapi import FastAPI
    from pydantic import BaseModel

    bundle = load_bundle(model_path)
    s: Schema = bundle["schema"]
    app = FastAPI(title="FEINT", version="0.2.0",
                  description="Adversarially-hardened network-flow scoring with explanations")

    class ScoreRequest(BaseModel):
        flows: list[dict[str, float]]
        explain: bool = False

    @app.get("/health")
    def health():
        return {"status": "ok", "schema": s.name}

    @app.get("/schema")
    def schema():
        return {"features": s.features, "controllable": s.controllable,
                "robust": s.robust_features(), "notes": s.notes}

    @app.post("/score")
    def score(req: ScoreRequest):
        return {"results": score_flows(bundle, req.flows, req.explain)}

    return app
