import json

import numpy as np
import pytest

from feint.attack import is_valid, pgd, project_constraints
from feint.cli import main
from feint.data import IDX, load_cicids_csv, synthetic_flows
from feint.harden import adversarial_training
from feint.metrics import precision_at_base_rate, robustness_curve
from feint.model import Detector
from feint.pipeline import run_study, to_markdown


@pytest.fixture(scope="module")
def setup():
    ds = synthetic_flows(1200, seed=1)
    det = Detector(hidden=(16,), max_iter=200, seed=1).fit(ds.X, ds.y)
    return ds, det


def test_synthetic_shape_and_labels():
    ds = synthetic_flows(500, seed=0)
    assert ds.X.shape == (500, len(ds.feature_names))
    assert set(np.unique(ds.y)) == {0, 1}
    assert np.all(ds.X >= 0)
    assert is_valid(ds.X, ds.X).all()


def test_preprocessor_roundtrip(setup):
    ds, det = setup
    assert np.allclose(det.pre.inverse(det.pre.transform(ds.X)), ds.X, rtol=1e-6, atol=1e-6)


def test_gradient_matches_finite_difference(setup):
    ds, det = setup
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


def test_projection_enforces_constraints(setup):
    ds, _ = setup
    X = ds.X[:50]
    rng = np.random.default_rng(0)
    noisy = X * rng.uniform(0, 3, X.shape) - 5
    P = project_constraints(noisy, X)
    assert is_valid(P, X).all()
    assert np.array_equal(P[:, IDX["bwd_bytes"]], X[:, IDX["bwd_bytes"]])


def test_constrained_attacks_always_valid(setup):
    ds, det = setup
    X_mal = ds.X[ds.y == 1][:100]
    Xa = pgd(det, X_mal, np.ones(len(X_mal)), eps=1.5, steps=10, constrained=True)
    assert is_valid(Xa, X_mal).all()


def test_unconstrained_attack_is_stronger_and_invalid(setup):
    ds, det = setup
    X_mal = ds.X[ds.y == 1][:100]
    c = robustness_curve(det, X_mal, [1.5], constrained=True, steps=10)[0]
    u = robustness_curve(det, X_mal, [1.5], constrained=False, steps=10)[0]
    assert u["detection_rate"] <= c["detection_rate"]
    assert u["valid_rate"] < 1.0


def test_attack_reduces_detection(setup):
    ds, det = setup
    X_mal = ds.X[ds.y == 1][:100]
    curve = robustness_curve(det, X_mal, [0.0, 2.0], constrained=False, steps=10)
    assert curve[1]["detection_rate"] < curve[0]["detection_rate"]


def test_adversarial_training_improves_robustness(setup):
    ds, det = setup
    X_mal = ds.X[ds.y == 1][:150]
    hard = adversarial_training(det, ds.X, ds.y, eps=2.0, rounds=2, steps=8)
    b = robustness_curve(det, X_mal, [2.0], steps=10)[0]["detection_rate"]
    h = robustness_curve(hard, X_mal, [2.0], steps=10)[0]["detection_rate"]
    assert h >= b


def test_precision_at_base_rate():
    assert precision_at_base_rate(1.0, 0.0, 0.001) == 1.0
    # 99% TPR, 1% FPR at 0.1% prevalence -> ~9% precision (base-rate fallacy)
    assert precision_at_base_rate(0.99, 0.01, 0.001) == pytest.approx(0.0902, abs=1e-3)


def test_cicids_loader(tmp_path):
    p = tmp_path / "cic.csv"
    p.write_text(
        " Flow Duration, Total Fwd Packets, Total Backward Packets,Total Length of Fwd Packets,"
        " Total Length of Bwd Packets, Flow IAT Mean, SYN Flag Count, Label\n"
        "1000000,10,8,4000,9000,50000,1,BENIGN\n"
        "20,2,0,0,0,10,1,PortScan\n"
        "bad,1,1,1,1,1,1,BENIGN\n"
    )
    ds = load_cicids_csv(p)
    assert ds.X.shape[0] == 2
    assert list(ds.y) == [0, 1]
    assert ds.X[0, IDX["duration"]] == pytest.approx(1.0)


def test_pipeline_and_cli(tmp_path):
    rep = run_study(synthetic_flows(900, seed=2), eps_list=[0.0, 1.0], adv_rounds=1, steps=5, max_eval=100)
    assert "baseline" in rep["models"] and "adv_trained" in rep["models"]
    assert "Robustness curve" in to_markdown(rep)
    out = tmp_path / "res"
    assert main(["run", "--n", "800", "--eps", "0", "1", "--adv-rounds", "1", "--steps", "5",
                 "--out", str(out)]) == 0
    assert json.loads((out / "report.json").read_text())["models"]
    assert main(["generate", "--n", "50", "--out", str(tmp_path / "f.csv")]) == 0
