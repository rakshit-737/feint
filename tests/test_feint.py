import json
from pathlib import Path

import numpy as np
import pytest

from feint.attack import adaptive, pgd, random_search
from feint.cli import main
from feint.data import load_unsw_nb15, synthetic_flows
from feint.explain import counterfactual, global_importance, local_explanation
from feint.harden import AdversarialInputDetector, adversarial_training, robust_feature_indices
from feint.metrics import area_under_curve, precision_at_base_rate, robustness_curve
from feint.model import AutoencoderDetector, EnsembleDetector, MLPDetector, Preprocessor, XGBDetector
from feint.pipeline import StudyConfig, restrict, run_study
from feint.poison import backdoor_study, make_poison
from feint.report import to_markdown
from feint.schema import CIC_SCHEMA, UNSW_SCHEMA

FIX = Path(__file__).parent / "fixtures"
S = CIC_SCHEMA


@pytest.fixture(scope="module")
def setup():
    ds = synthetic_flows(1500, seed=1)
    pre = Preprocessor().fit(ds.X)
    mlp = MLPDetector(hidden=(16,), max_iter=200, seed=1).fit(ds.X, ds.y, pre=pre)
    xgb = XGBDetector(seed=1, n_estimators=40, max_depth=4).fit(ds.X, ds.y, pre=pre)
    return ds, mlp, xgb


def test_synthetic_shape_labels_and_validity():
    ds = synthetic_flows(500, seed=0)
    assert ds.X.shape == (500, len(ds.feature_names))
    assert set(np.unique(ds.y)) == {0, 1}
    assert np.all(ds.X >= 0)
    assert S.is_valid(ds.X, ds.X).all()


def test_schema_partitions_features():
    for s in (CIC_SCHEMA, UNSW_SCHEMA):
        ctrl, fixed, der = set(s.controllable), set(s.fixed), set(s.derived)
        assert ctrl | fixed | der == set(s.features)
        assert not (ctrl & fixed) and not (ctrl & der) and not (fixed & der)
        rob = set(s.robust_features())
        assert rob <= fixed | der and not (rob & set(s.depends_on_controllable()))
    assert "mean_iat" in CIC_SCHEMA.depends_on_controllable()
    assert "dst_port" in CIC_SCHEMA.robust_features()


def test_preprocessor_roundtrip(setup):
    ds, mlp, _ = setup
    assert np.allclose(mlp.pre.inverse(mlp.pre.transform(ds.X)), ds.X, rtol=1e-6, atol=1e-6)


def test_gradient_matches_finite_difference(setup):
    ds, det, _ = setup
    Z = det.pre.transform(ds.X[:5])
    y = ds.y[:5].astype(float)
    g = det.grad_z(Z, y)

    def loss(z):
        p = np.clip(det.predict_proba_z(z), 1e-12, 1 - 1e-12)
        return -(y * np.log(p) + (1 - y) * np.log(1 - p))

    h = 1e-5
    for j in range(Z.shape[1]):
        dz = np.zeros_like(Z)
        dz[:, j] = h
        fd = (loss(Z + dz) - loss(Z - dz)) / (2 * h)
        assert np.allclose(fd, g[:, j], atol=1e-4)


@pytest.mark.parametrize("schema_name", ["cic", "unsw"])
def test_projection_enforces_constraints(schema_name):
    if schema_name == "cic":
        s, X = S, synthetic_flows(200, seed=3).X
    else:
        s, X = UNSW_SCHEMA, load_unsw_nb15(FIX).X[:200]
    rng = np.random.default_rng(0)
    noisy = X * rng.uniform(0, 3, X.shape) - rng.uniform(0, 5, X.shape)
    P = s.project(noisy, X)
    assert s.is_valid(P, X).all()
    for f in s.fixed:
        assert np.allclose(P[:, s.idx[f]], X[:, s.idx[f]])
    # an obviously illegal change is rejected
    bad = X.copy()
    bad[:, s.idx[s.fixed[0]]] += 1
    assert not s.is_valid(bad, X).any()


def test_constrained_attacks_always_valid(setup):
    ds, mlp, xgb = setup
    X_mal = ds.X[ds.y == 1][:100]
    for Xa in (pgd(mlp, X_mal, S, eps=1.5, steps=10),
               random_search(xgb, X_mal, S, eps=1.5, iters=20),
               adaptive(xgb, X_mal, S, eps=1.5, surrogate=mlp, steps=5, iters=10)):
        assert S.is_valid(Xa, X_mal).all()


def test_unconstrained_attack_is_stronger_and_invalid(setup):
    ds, mlp, _ = setup
    X_mal = ds.X[ds.y == 1][:100]
    atk_c = lambda d, X, e: pgd(d, X, S, eps=e, steps=10)  # noqa: E731
    atk_u = lambda d, X, e: pgd(d, X, S, eps=e, steps=10, constrained=False)  # noqa: E731
    c = robustness_curve(mlp, X_mal, [1.5], S, atk_c)[0]
    u = robustness_curve(mlp, X_mal, [1.5], S, atk_u)[0]
    assert u["detection_rate"] <= c["detection_rate"]
    assert u["valid_rate"] < 1.0 and c["valid_rate"] == 1.0


def test_curve_is_monotone_and_auc(setup):
    ds, _, xgb = setup
    X_mal = ds.X[ds.y == 1][:80]
    curve = robustness_curve(xgb, X_mal, [0.0, 0.5, 1.0, 2.0], S,
                             lambda d, X, e: random_search(d, X, S, eps=e, iters=20))
    d = [c["detection_rate"] for c in curve]
    assert all(a >= b for a, b in zip(d, d[1:]))
    assert d[-1] < d[0]
    assert 0 <= area_under_curve(curve) <= 1


def test_adversarial_training_improves_robustness(setup):
    ds, mlp, _ = setup
    X_mal = ds.X[ds.y == 1][:150]
    atk = lambda d, X, e: pgd(d, X, S, eps=e, steps=8)  # noqa: E731
    hard = adversarial_training(mlp, ds.X, ds.y, atk, eps=2.0, rounds=2)
    b = robustness_curve(mlp, X_mal, [2.0], S, atk)[0]["detection_rate"]
    h = robustness_curve(hard, X_mal, [2.0], S, atk)[0]["detection_rate"]
    assert h >= b


def test_robust_feature_model_is_immune(setup):
    ds, mlp, _ = setup
    cols = robust_feature_indices(S)
    rob = XGBDetector(seed=0, n_estimators=30, max_depth=3, cols=cols).fit(ds.X, ds.y, pre=mlp.pre)
    X_mal = ds.X[ds.y == 1][:100]
    Xa = adaptive(rob, X_mal, S, eps=3.0, surrogate=mlp, steps=5, iters=20)
    assert np.array_equal(rob.predict(Xa), rob.predict(X_mal))


def test_ensemble_and_autoencoder(setup):
    ds, mlp, xgb = setup
    ae = AutoencoderDetector(hidden=(8, 4, 8), max_iter=80).fit(ds.X, ds.y, pre=mlp.pre)
    ben = ds.X[ds.y == 0]
    assert ae.predict(ben).mean() <= 0.05
    ens = EnsembleDetector([xgb, mlp], ae)
    p = ens.predict_proba(ds.X)
    assert np.all(p >= ae.predict_proba(ds.X) - 1e-12)


def test_shap_and_counterfactuals(setup):
    ds, mlp, xgb = setup
    imp = global_importance(xgb, ds.X[:300], ds.feature_names)
    assert len(imp) == len(ds.feature_names) and imp[0]["mean_abs_shap"] >= imp[-1]["mean_abs_shap"]
    # SHAP values + bias reproduce the model's log-odds
    C = xgb.contributions_z(xgb.pre.transform(ds.X[:20]))
    p = 1 / (1 + np.exp(-C.sum(1)))
    assert np.allclose(p, xgb.predict_proba(ds.X[:20]), atol=1e-4)
    assert len(local_explanation(xgb, ds.X[0], ds.feature_names, top=3)) == 3
    flagged = ds.X[(ds.y == 1) & (xgb.predict(ds.X) == 1)][:15]
    cfs, Xcf = counterfactual(xgb, flagged, S, surrogate=mlp, eps_max=3.0, bisect=3, iters=30)
    assert all(c["valid"] for c in cfs)
    found = np.array([c["found"] for c in cfs])
    assert found.mean() > 0.5
    assert (xgb.predict(Xcf[found]) == 0).all()
    assert all(set(ch["feature"] for ch in c["changes"]) <= set(S.controllable) for c in cfs)


def test_adversarial_input_detector(setup):
    ds, mlp, xgb = setup
    X_mal = ds.X[ds.y == 1]
    Xa = adaptive(xgb, X_mal, S, eps=2.0, surrogate=mlp, steps=5, iters=20)
    ev = xgb.predict(Xa) == 0
    half = len(X_mal) // 2
    aid = AdversarialInputDetector(xgb).fit(np.vstack([ds.X[ds.y == 0][:half], X_mal[:half]]),
                                            Xa[:half][ev[:half]])
    r = aid.evaluate(X_mal[half:], Xa[half:][ev[half:]])
    assert r["auc"] > 0.8


def test_poisoning_backdoor_and_sanitizer(setup):
    ds, mlp, _ = setup
    Xp, yp, flag, (f, v) = make_poison(ds.X, ds.y, S, rate=0.05)
    assert f in S.controllable and flag.sum() == round(0.05 * len(ds.y))
    assert S.is_valid(Xp[flag], Xp[flag]).all()

    def factory(X, y):
        return XGBDetector(seed=0, n_estimators=40, max_depth=4).fit(X, y, pre=mlp.pre)

    n = len(ds.y) * 2 // 3
    r = backdoor_study(factory, ds.X[:n], ds.y[:n], ds.X[n:], ds.y[n:], S, rate=0.05,
                       robust_cols=robust_feature_indices(S))
    assert r["poisoned_model"]["backdoor_success"] > r["clean_model"]["backdoor_success"]
    assert r["sanitizer"]["poison_recall"] > 0.8
    assert r["sanitized_model"]["backdoor_success"] < r["poisoned_model"]["backdoor_success"]


def test_precision_at_base_rate():
    assert precision_at_base_rate(1.0, 0.0, 0.001) == 1.0
    # 99% TPR, 1% FPR at 0.1% prevalence -> ~9% precision (base-rate fallacy)
    assert precision_at_base_rate(0.99, 0.01, 0.001) == pytest.approx(0.0902, abs=1e-3)


def test_cicids_csv_fixture_loader():
    from feint.data import load_cicids_csv

    p = FIX / "cicids2017_sample.csv"
    ds = load_cicids_csv(p)
    assert len(ds) > 100 and set(np.unique(ds.y)) == {0, 1}
    assert S.is_valid(ds.X, ds.X).all()
    assert "BENIGN" in set(ds.attack)
    assert "Web Attack - XSS" in set(ds.attack)  # mojibake dash normalised


def test_unsw_fixture_loader():
    ds = load_unsw_nb15(FIX)
    assert ds.schema is UNSW_SCHEMA
    assert set(np.unique(ds.group)) == {0, 1}
    assert UNSW_SCHEMA.is_valid(ds.X, ds.X).all()
    assert (ds.attack == "BENIGN").sum() == (ds.y == 0).sum()


def test_restrict_schema():
    s = restrict(S, ["duration"])
    assert s.controllable == ["duration"]
    assert "fwd_pkts" in s.fixed


def test_pipeline_and_cli(tmp_path):
    cfg = StudyConfig.quick(eps=[0.0, 1.0])
    rep = run_study(synthetic_flows(900, seed=2), cfg)
    assert {"mlp", "xgboost", "ensemble", "xgboost_adv_trained"} <= set(rep["models"])
    assert {"poisoning", "counterfactuals", "shap_global_xgboost"} <= set(rep)
    md = to_markdown(rep)
    assert "constrained adaptive evasion" in md and "Backdoor" in md
    json.dumps(rep)
    out = tmp_path / "res"
    assert main(["run", "--quick", "--n", "800", "--eps", "0", "1", "--no-figures", "--out", str(out)]) == 0
    assert json.loads((out / "report.json").read_text())["models"]
    assert main(["generate", "--n", "50", "--out", str(tmp_path / "f.csv")]) == 0


def test_pipeline_unsw_fixture(tmp_path):
    rep = run_study(load_unsw_nb15(FIX), StudyConfig.quick(eps=[0.0, 1.0]))
    assert rep["split"].startswith("official")
    assert rep["schema"] == "unsw_nb15"


def test_api_scoring(tmp_path):
    pytest.importorskip("fastapi")
    pytest.importorskip("joblib")
    from fastapi.testclient import TestClient

    from feint.api import create_app

    out = tmp_path / "res"
    assert main(["run", "--quick", "--n", "600", "--eps", "0", "1", "--no-figures", "--save-model",
                 "--out", str(out)]) == 0
    client = TestClient(create_app(out / "model.joblib"))
    assert client.get("/health").json()["status"] == "ok"
    assert "dst_port" in client.get("/schema").json()["robust"]
    ds = synthetic_flows(50, seed=9)
    flows = [dict(zip(ds.feature_names, map(float, x))) for x in ds.X[ds.y == 1][:3]]
    res = client.post("/score", json={"flows": flows, "explain": True}).json()["results"]
    assert len(res) == 3 and all(0 <= r["p_malicious"] <= 1 for r in res)
    assert all("top_features" in r for r in res)
    assert client.post("/score", json={"flows": []}).status_code == 422
    r = client.post("/score", json={"flows": [{"bogus_feature": 1.0}]})
    assert r.status_code == 422 and "bogus_feature" in r.text
    assert client.post("/score", json={"flows": [flows[0]] * 1001}).status_code == 422
    assert client.post("/score", json={"flows": [flows[0]] * 21, "explain": True}).status_code == 422
    import feint
    assert client.get("/openapi.json").json()["info"]["version"] == feint.__version__


realdata = pytest.mark.skipif(
    not (Path(__file__).parents[1] / "data" / "unsw-nb15" / "UNSW_NB15_training-set.csv").exists()
    and not __import__("os").environ.get("FEINT_DATA"),
    reason="real datasets not downloaded (run scripts/download_*.py)")


@pytest.mark.realdata
@realdata
def test_real_unsw_loads():
    try:
        ds = load_unsw_nb15()
    except FileNotFoundError:
        pytest.skip("UNSW-NB15 not downloaded")
    assert len(ds) == 257_673
    assert UNSW_SCHEMA.is_valid(ds.X, ds.X).all()


@pytest.mark.realdata
@realdata
def test_real_cicids2017_loads():
    from feint.data import load_cicids2017

    try:
        ds = load_cicids2017()  # default sampling (cached after the first load)
    except FileNotFoundError:
        pytest.skip("CIC-IDS2017 not downloaded")
    assert ds.info["rows_raw"] == 2_830_743
    assert ds.info["rows_dedup"] < ds.info["rows_raw"]
    assert S.is_valid(ds.X, ds.X).all()


def test_confidence_intervals():
    from feint.seeds import mean_ci, wilson

    lo, hi = wilson(50, 100)
    assert lo < 0.5 < hi and abs((hi - lo) / 2 - 0.096) < 0.005
    assert wilson(0, 10)[0] == 0.0 and wilson(10, 10)[1] == 1.0
    ci = mean_ci([0.8, 0.9, 1.0])
    assert abs(ci["mean"] - 0.9) < 1e-9 and ci["ci95"][0] < 0.9 < ci["ci95"][1]
    assert mean_ci([0.5])["ci95"] == [0.5, 0.5]


def test_seed_study_quick(tmp_path):
    assert main(["seeds", "--quick", "--n", "800", "--seeds", "0", "1", "--eps", "0", "1",
                 "--out", str(tmp_path)]) == 0
    r = json.loads((tmp_path / "seeds.json").read_text())
    assert r["seeds"] == [0, 1]
    agg = r["aggregate"]["xgboost"]["detection"]["1.0"]
    assert agg["n"] == 2 and agg["ci95"][0] <= agg["mean"] <= agg["ci95"][1]
    assert "eps=1.0" in (tmp_path / "seeds.md").read_text()


def test_model_stealing_quick(tmp_path):
    assert main(["steal", "--quick", "--n", "800", "--budgets", "100", "400", "--eps", "1",
                 "--out", str(tmp_path)]) == 0
    r = json.loads((tmp_path / "steal.json").read_text())
    assert set(r["budgets"]) == {"100", "400"}
    for v in r["budgets"].values():
        assert 0.5 <= v["agreement"] <= 1.0
        assert 0.0 <= v["victim_detection"]["1.0"] <= v["victim_detection"]["0.0"] + 1e-9
    assert "label queries" in (tmp_path / "steal.md").read_text()


FIX = Path(__file__).parent / "fixtures"


def test_cicids2018_fixture_loader():
    from feint.data import load_cicids2018

    ds = load_cicids2018(FIX / "cicids2018", per_class=1000)
    assert "Label" not in set(ds.attack)  # repeated header row dropped
    assert {"BENIGN", "FTP-BruteForce", "Bot"} <= set(ds.attack)
    assert ds.X.shape[1] == len(ds.schema.features) and ds.schema.is_valid(ds.X, ds.X).all()


def test_cicids2017_corrected_attempted_relabel():
    from feint.data import load_cicids2017_corrected

    a = load_cicids2017_corrected(FIX / "cicids2017-corrected", attempted="benign")
    b = load_cicids2017_corrected(FIX / "cicids2017-corrected", attempted="attack")
    assert not any("Attempted" in x for x in set(a.attack) | set(b.attack))
    assert a.y.sum() < b.y.sum()


def test_per_class_cap():
    from feint.data import load_cicids2018

    ds = load_cicids2018(FIX / "cicids2018", per_class=5)
    _, counts = np.unique(ds.attack, return_counts=True)
    assert counts.max() <= 5


def test_xdata_quick(tmp_path):
    out = tmp_path / "x"
    assert main(["xdata", "--train", "cicids2017_corrected", "--train-dir", str(FIX / "cicids2017-corrected"),
                 "--test", "cicids2018", "--test-dir", str(FIX / "cicids2018"), "--seeds", "0", "1",
                 "--eps", "0", "1", "--quick", "--out", str(out)]) == 0
    import json

    r = json.loads((out / "xdata.json").read_text())
    assert set(r["aggregate"]) == {"xgboost", "xgboost_adv_trained", "xgboost_robust_features"}
    assert "FTP brute force" in r["test_classes"]


def test_unknown_dataset_name_is_clear():
    with pytest.raises(SystemExit, match="unknown dataset"):
        main(["run", "--data", "no_such_dataset", "--quick", "--out", "unused"])


def test_ciciot2023_fixture_loader():
    pytest.importorskip("pyarrow")
    from feint.data import load_ciciot2023

    ds = load_ciciot2023(FIX / "ciciot2023", per_class=30)
    assert "BENIGN" in set(ds.attack) and ds.y.sum() > 0
    assert ds.schema.name == "ciciot2023" and ds.schema.is_valid(ds.X, ds.X).all()
