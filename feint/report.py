"""Render a study report (dict) to Markdown tables and PNG figures."""
from __future__ import annotations

from pathlib import Path

PRETTY = {
    "logreg": "Logistic regression", "random_forest": "Random forest", "iforest": "IsolationForest",
    "mlp": "MLP", "xgboost": "XGBoost", "autoencoder": "Autoencoder", "ensemble": "FEINT ensemble",
    "mlp_adv_trained": "MLP + adv. training", "xgboost_adv_trained": "XGBoost + adv. training",
    "ensemble_adv_trained": "FEINT ensemble + adv. training",
    "xgboost_robust_features": "XGBoost, robust features only",
}


def _p(name):
    return PRETTY.get(name, name)


def to_markdown(r: dict) -> str:
    ds = r.get("dataset", {})
    L = [f"# FEINT robustness report: {ds.get('name', '?')}", ""]
    L += [f"- split: {r['split']}; train {r['n_train']:,} / test {r['n_test']:,} flows; "
          f"attack prevalence in test {r['attack_prevalence_test']:.1%}",
          f"- attacker-controllable features: {', '.join(r['controllable'])}",
          f"- robust (attacker-immutable) features: {', '.join(r['robust_features'])}",
          f"- attacked flows per curve point: {r.get('n_eval_attacks', '?')}", ""]

    L += ["## Clean detection (held-out test set)", "",
          "| model | acc | prec | recall | F1 | ROC-AUC | PR-AUC | FPR | prec @1% prev. | prec @0.1% prev. |",
          "|---|---|---|---|---|---|---|---|---|---|"]
    for name, c in r["models"].items():
        L.append(f"| {_p(name)} | {c['accuracy']:.4f} | {c['precision']:.4f} | {c['recall']:.4f} | "
                 f"{c['f1']:.4f} | {c['auc']:.4f} | {c['pr_auc']:.4f} | {c['fpr']:.4f} | "
                 f"{c['precision_at_0.01']:.3f} | {c['precision_at_0.001']:.3f} |")

    rob = r["robustness"]
    eps = [p["eps"] for p in next(iter(rob.values()))["constrained"]]
    for kind in ("constrained", "unconstrained"):
        rows = [(n, v) for n, v in rob.items() if kind in v]
        if not rows:
            continue
        L += ["", f"## Detection rate under {kind} adaptive evasion (attack flows)", "",
              "| model | " + " | ".join(f"eps={e:g}" for e in eps) + " | area | valid flows @max eps |",
              "|---|" + "---|" * (len(eps) + 2)]
        for n, v in rows:
            c = v[kind]
            L.append(f"| {_p(n)} | " + " | ".join(f"{p['detection_rate']:.3f}" for p in c)
                     + f" | {v[kind + '_auc']:.3f} | {c[-1]['valid_rate']:.3f} |")

    if "per_family" in r:
        L += ["", f"## Per attack family (XGBoost, constrained eps={eps[-1]:g})", "",
              "| family | n | clean detection | adversarial detection |", "|---|---|---|---|"]
        for f, v in sorted(r["per_family"].items(), key=lambda kv: -kv[1]["n"]):
            L.append(f"| {f} | {v['n']} | {v['clean_detection']:.3f} | {v['adv_detection']:.3f} |")

    if "single_feature_attack_detection" in r:
        L += ["", f"## Which controllable features are exploitable? (XGBoost, one feature at a time, "
              f"eps={eps[-1]:g})", "", "| attacker controls only | detection rate |", "|---|---|"]
        for f, v in sorted(r["single_feature_attack_detection"].items(), key=lambda kv: kv[1]):
            L.append(f"| {f} | {v:.3f} |")

    if "shap_global_xgboost" in r:
        L += ["", "## Global feature importance (XGBoost, mean |TreeSHAP|, log-odds)", "",
              "| feature | mean abs SHAP | attacker-controllable |", "|---|---|---|"]
        ctrl = set(r["controllable"])
        for e in r["shap_global_xgboost"]:
            L.append(f"| {e['feature']} | {e['mean_abs_shap']:.3f} | {'yes' if e['feature'] in ctrl else ''} |")

    if "counterfactuals" in r:
        c = r["counterfactuals"]
        L += ["", "## Counterfactual explanations (XGBoost alerts)", "",
              f"- {c['n']} flagged attack flows; realisable counterfactual found for "
              f"{c['found_rate']:.1%} (validity under schema: {c['valid_rate']:.1%})",
              f"- mean controllable features changed: {c['mean_features_changed']:.2f}; "
              f"median budget: {c['median_eps']}",
              f"- features used: {c['feature_frequency']}",
              f"- hardened ensemble: counterfactual found for "
              f"{r['counterfactuals_hardened_ensemble']['found_rate']:.1%} of its alerts", "",
              "Examples:", ""]
        L += [f"- {e}" for e in c["examples"]]

    if "adversarial_input_detector" in r:
        a = r["adversarial_input_detector"]
        L += ["", "## Adversarial-input detector", "",
              f"Trained on {a['train_adv']} successful constrained evasions (eps 0.5/1/2) of training flows.", "",
              "| test budget | evasions | ROC-AUC | TPR | FPR on clean |", "|---|---|---|---|---|"]
        for k, v in a.items():
            if k.startswith("eps_"):
                L.append(f"| {k[4:]} | {v['n_evasions']} | {v['auc']:.3f} | {v['tpr']:.3f} | {v['fpr']:.3f} |")
        if "adaptive_vs_guarded" in a:
            g = a["adaptive_vs_guarded"]
            L += ["", f"Detector-aware adaptive attacker (eps={g['eps']:g}) against XGBoost OR adv-input alarm: "
                  f"detection {g['detection_rate']:.3f} (XGBoost alone would miss {g['evade_target_only']:.3f} of "
                  f"these flows); guarded FPR on benign {g['guarded_fpr_benign']:.4f}. The static AUC above "
                  "is therefore optimistic: it only holds against attackers unaware of the alarm."]

    if "poisoning" in r:
        p = r["poisoning"]
        L += ["", "## Backdoor poisoning", "",
              f"{p['n_poison']} poisoned flows ({p['rate']:.0%} of training): malicious flows with "
              f"`{p['trigger_feature']} = {p['trigger_value']:g}`, labelled benign.", "",
              "| model | clean acc. | recall (clean attacks) | recall (triggered attacks) | backdoor success |",
              "|---|---|---|---|---|"]
        for k in ("clean_model", "poisoned_model", "sanitized_model"):
            if k in p:
                v = p[k]
                L.append(f"| {k.replace('_', ' ')} | {v['clean_accuracy']:.4f} | {v['clean_recall']:.4f} | "
                         f"{v['triggered_recall']:.4f} | {v['backdoor_success']:.4f} |")
        if "sanitizer" in p:
            s = p["sanitizer"]
            L += ["", f"Robust-feature kNN sanitiser flagged {s['flagged']} training flows: poison recall "
                  f"{s['poison_recall']:.3f}, precision {s['precision']:.3f}, clean benign removed "
                  f"{s['clean_benign_removed_frac']:.4f}."]

    if "drift" in r:
        d = r["drift"]
        L += ["", "## Temporal drift / unseen attack families", "",
              f"Train on {', '.join(d['train_days'])}; test on {', '.join(d['test_days'])}. "
              f"Families seen in training: {', '.join(d['train_families'])}.", "",
              "| test family | n | XGBoost | Autoencoder | Ensemble |", "|---|---|---|---|---|"]
        for f, v in sorted(d["families"].items(), key=lambda kv: -kv[1]["n"]):
            L.append(f"| {f} | {v['n']} | {v['xgboost']:.3f} | {v['autoencoder']:.3f} | {v['ensemble']:.3f} |")
        L.append(f"| benign FPR | | {d['benign_fpr']['xgboost']:.4f} | {d['benign_fpr']['autoencoder']:.4f} | "
                 f"{d['benign_fpr']['ensemble']:.4f} |")

    L += ["", "## Timings (s)", "", ", ".join(f"{k}: {v}" for k, v in r.get("timings_s", {}).items()), ""]
    return "\n".join(L)


def write_figures(r: dict, out: Path) -> list[Path]:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:  # optional dependency
        return []
    out = Path(out)
    paths = []
    rob = r["robustness"]

    colors = {"mlp": "#1f77b4", "xgboost": "#ff7f0e", "random_forest": "#8c564b", "ensemble": "#2ca02c",
              "mlp_adv_trained": "#1f77b4", "xgboost_adv_trained": "#ff7f0e",
              "ensemble_adv_trained": "#2ca02c", "xgboost_robust_features": "#7f7f7f"}
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.8), sharey=True)
    handles = {}
    for ax, kind in zip(axes, ("constrained", "unconstrained")):
        for n, v in rob.items():
            if kind not in v:
                continue
            e = [p["eps"] for p in v[kind]]
            d = [p["detection_rate"] for p in v[kind]]
            ls = ":" if "robust" in n else "--" if "adv" in n else "-"
            (h,) = ax.plot(e, d, ls, marker="o", ms=3, lw=1.8, color=colors.get(n), label=_p(n))
            handles.setdefault(n, h)
        ax.set_title(f"{kind} adaptive evasion")
        ax.set_xlabel("budget eps (L-inf, standardised log space)")
        ax.grid(alpha=0.3)
    axes[0].set_ylabel("detection rate on attack flows")
    axes[0].set_ylim(-0.02, 1.02)
    fig.legend(list(handles.values()), [_p(n) for n in handles], loc="lower center", ncol=4, fontsize=8,
               frameon=False)
    fig.suptitle(f"FEINT robustness curves: {r['dataset'].get('name')} (solid = undefended, dashed = "
                 "adversarially trained, dotted = robust features)", fontsize=10)
    fig.tight_layout(rect=(0, 0.1, 1, 1))
    p = out / "robustness_curves.png"
    fig.savefig(p, dpi=110)
    plt.close(fig)
    paths.append(p)

    if "shap_global_xgboost" in r:
        imp = r["shap_global_xgboost"][::-1]
        ctrl = set(r["controllable"])
        fig, ax = plt.subplots(figsize=(6, 4.5))
        ax.barh([e["feature"] for e in imp], [e["mean_abs_shap"] for e in imp],
                color=["#c0392b" if e["feature"] in ctrl else "#2c7fb8" for e in imp])
        ax.set_xlabel("mean |SHAP| (log-odds)")
        ax.set_title("XGBoost global importance\n(red = attacker-controllable)")
        fig.tight_layout()
        p = out / "shap_importance.png"
        fig.savefig(p, dpi=110)
        plt.close(fig)
        paths.append(p)

    if "drift" in r:
        fams = sorted(r["drift"]["families"].items(), key=lambda kv: -kv[1]["n"])
        import numpy as np

        x = np.arange(len(fams))
        fig, ax = plt.subplots(figsize=(9, 4))
        for k, (m, c) in enumerate([("xgboost", "#2c7fb8"), ("autoencoder", "#fdae61"), ("ensemble", "#1a9641")]):
            ax.bar(x + (k - 1) * 0.27, [v[m] for _, v in fams], 0.27, label=_p(m), color=c)
        ax.set_xticks(x, [f for f, _ in fams], rotation=30, ha="right", fontsize=8)
        ax.set_ylabel("recall")
        ax.set_title("Train Mon-Wed, test Thu-Fri: recall per (mostly unseen) family")
        ax.legend(fontsize=8)
        fig.tight_layout()
        p = out / "drift_recall.png"
        fig.savefig(p, dpi=110)
        plt.close(fig)
        paths.append(p)
    return paths
