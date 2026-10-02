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


MAX_FLOWS = 1000
MAX_EXPLAIN = 20


def score_flows(bundle: dict, flows: list[dict], explain: bool = False) -> list[dict]:
    """Score flows (feature-name -> value dicts); missing features default to 0."""
    s: Schema = bundle["schema"]
    if not flows:
        raise ValueError("flows must contain at least one flow")
    unknown = sorted({k for f in flows for k in f} - set(s.features))
    if unknown:
        raise ValueError(f"unknown feature names for schema {s.name}: {unknown}")
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
    from fastapi import FastAPI, HTTPException
    from pydantic import BaseModel, Field, field_validator

    from . import __version__

    bundle = load_bundle(model_path)
    s: Schema = bundle["schema"]
    app = FastAPI(title="FEINT", version=__version__,
                  description="Adversarially-hardened network-flow scoring with explanations")

    class ScoreRequest(BaseModel):
        flows: list[dict[str, float]] = Field(min_length=1, max_length=MAX_FLOWS)
        explain: bool = False

        @field_validator("flows")
        @classmethod
        def _finite(cls, v):
            if any(not np.isfinite(x) for f in v for x in f.values()):
                raise ValueError("feature values must be finite numbers")
            return v

    @app.get("/health")
    def health():
        return {"status": "ok", "schema": s.name}

    @app.get("/schema")
    def schema():
        return {"features": s.features, "controllable": s.controllable,
                "robust": s.robust_features(), "notes": s.notes}

    @app.post("/score")
    def score(req: ScoreRequest):
        if req.explain and len(req.flows) > MAX_EXPLAIN:
            raise HTTPException(422, f"explain=true accepts at most {MAX_EXPLAIN} flows")
        try:
            return {"results": score_flows(bundle, req.flows, req.explain)}
        except ValueError as e:
            raise HTTPException(422, str(e)) from e

    return app
