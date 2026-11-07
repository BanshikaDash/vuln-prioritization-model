"""
Train the ML extension (project plan, step 3).

Train on one snapshot's dataset and test on a LATER snapshot, so the test
shows how well the model predicts the future, not how well it memorizes.

    python train_model.py                       # dataset.csv -> dataset_2023.csv
    python train_model.py --train dataset.csv --test dataset_2023.csv --save-dir models

Two models are trained with fixed settings (no tuning on the test set):
  logit  logistic regression on standardized features (easy to explain)
  gbm    gradient boosted trees (usually stronger)
They are compared with CVSS, EPSS, the paper's score and a "count of public
exploits" rule. With few exploited CVEs in the test set the results are noisy,
so 95% bootstrap intervals are printed for AP and recall@5%.
"""
from __future__ import annotations

import argparse
import csv
import os

import numpy as np

NUMERIC = ["cvss_base", "exploitability", "impact", "n_cpe", "n_cwe", "n_adversaries",
           "in_zdi", "epss", "epss_percentile", "n_public_exploits", "age_days"]
LOG1P = {"n_cpe", "n_public_exploits"}
CATEGORICAL = {"av": "NALP", "ac": "LH", "pr": "NLH", "ui": "NR", "s": "UC",
               "c": "HLN", "i": "HLN", "a": "HLN"}
BASELINES = ["cvss_base", "epss", "paper_score", "n_public_exploits"]


def feature_names() -> list[str]:
    names = list(NUMERIC)
    for col, vals in CATEGORICAL.items():
        names += [f"{col}={v}" for v in vals]
    return names


def load(path: str):
    """Returns (rows, X, y). X columns follow feature_names()."""
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    X = np.array([row_to_vector(r) for r in rows]) if rows else np.zeros((0, len(feature_names())))
    y = np.array([int(r["label"]) for r in rows])
    return rows, X, y


def row_to_vector(row) -> np.ndarray:
    """One dataset row (dict) -> model input vector, in feature_names() order.
    Also used by alerts.py to score a live CVE."""
    x = np.zeros(len(feature_names()))
    c = 0
    for col in NUMERIC:
        v = float(row.get(col) or 0)
        x[c] = np.log1p(v) if col in LOG1P else v
        c += 1
    for col, vals in CATEGORICAL.items():
        for v in vals:
            x[c] = 1.0 if row.get(col) == v else 0.0
            c += 1
    return x


# ---- metrics (numpy, fast enough for bootstrapping) ---------------------------
def _ranked(y, s, rng):
    order = np.lexsort((rng.random(len(s)), -s))  # score desc, random tie-break
    return y[order]


def metrics(y, s, seeds=5):
    total = y.sum()
    if total == 0:
        return {k: float("nan") for k in ("AP", "recall@1%", "recall@5%", "recall@10%", "lift@5%")}
    acc = {k: [] for k in ("AP", "recall@1%", "recall@5%", "recall@10%")}
    for seed in range(seeds):
        ranked = _ranked(y, s, np.random.default_rng(seed))
        pos_ranks = np.flatnonzero(ranked) + 1
        acc["AP"].append(np.mean(np.arange(1, total + 1) / pos_ranks))
        for name, frac in (("recall@1%", .01), ("recall@5%", .05), ("recall@10%", .10)):
            k = max(1, int(np.ceil(frac * len(y))))
            acc[name].append(ranked[:k].sum() / total)
    out = {k: float(np.mean(v)) for k, v in acc.items()}
    out["lift@5%"] = out["recall@5%"] / 0.05
    return out


def bootstrap_ci(y, scores: dict, n=100, seed=0):
    rng = np.random.default_rng(seed)
    res = {name: {"AP": [], "recall@5%": []} for name in scores}
    for _ in range(n):
        idx = rng.integers(0, len(y), len(y))
        yb = y[idx]
        if yb.sum() == 0:
            continue
        for name, s in scores.items():
            m = metrics(yb, s[idx], seeds=1)
            res[name]["AP"].append(m["AP"])
            res[name]["recall@5%"].append(m["recall@5%"])
    return {name: {k: (float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5)))
                   for k, v in d.items()} for name, d in res.items()}


def make_models():
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler
    return {
        "logit": make_pipeline(StandardScaler(),
                               LogisticRegression(C=0.1, class_weight="balanced", max_iter=3000)),
        "gbm": HistGradientBoostingClassifier(
            max_depth=3, learning_rate=0.05, max_iter=200, min_samples_leaf=50,
            l2_regularization=1.0, class_weight="balanced", random_state=0),
    }


def run(train_path, test_path, save_dir=None, boot=100, importance=False, log=print):
    _, Xtr, ytr = load(train_path)
    rows_te, Xte, yte = load(test_path)
    log(f"train: {len(ytr)} CVEs, {ytr.sum()} exploited | test: {len(yte)} CVEs, {yte.sum()} exploited")

    scores = {b: np.array([float(r.get(b) or 0) for r in rows_te]) for b in BASELINES}
    models = make_models()
    for name, m in models.items():
        m.fit(Xtr, ytr)
        scores[f"ml_{name}"] = m.predict_proba(Xte)[:, 1]

    table = {name: metrics(yte, s) for name, s in scores.items()}
    ci = bootstrap_ci(yte, scores, n=boot) if boot else {}

    log(f"\n{'score':<20}{'AP':<22}{'recall@1%':<11}{'recall@5%':<22}{'recall@10%':<12}lift@5%")
    for name, m in table.items():
        ap = f"{m['AP']:.3f}"
        r5 = f"{m['recall@5%']:.3f}"
        if name in ci:
            ap += f" [{ci[name]['AP'][0]:.3f}-{ci[name]['AP'][1]:.3f}]"
            r5 += f" [{ci[name]['recall@5%'][0]:.2f}-{ci[name]['recall@5%'][1]:.2f}]"
        log(f"{name:<20}{ap:<22}{m['recall@1%']:<11.3f}{r5:<22}{m['recall@10%']:<12.3f}{m['lift@5%']:.2f}")
    log(f"{'random':<20}{yte.mean():<22.3f}{0.01:<11.3f}{0.05:<22.3f}{0.10:<12.3f}1.00")

    names = feature_names()
    logit = models["logit"]
    coefs = logit[-1].coef_[0]
    log("\nLogistic regression, largest effects (standardized, + = more likely exploited):")
    for i in np.argsort(-np.abs(coefs))[:10]:
        log(f"  {names[i]:<20}{coefs[i]:+.3f}")

    if importance:
        from sklearn.inspection import permutation_importance
        log("\nGBM permutation importance on the test set (drop in AP when shuffled):")
        pi = permutation_importance(models["gbm"], Xte, yte, scoring="average_precision",
                                    n_repeats=3, random_state=0)
        for i in np.argsort(-pi.importances_mean)[:10]:
            log(f"  {names[i]:<20}{pi.importances_mean[i]:+.4f}")

    if save_dir:
        import joblib
        os.makedirs(save_dir, exist_ok=True)
        for name, m in models.items():
            joblib.dump(m, os.path.join(save_dir, f"{name}.joblib"))
        with open(os.path.join(save_dir, "test_predictions.csv"), "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["cve_id", "label", *scores.keys()])
            for i, r in enumerate(rows_te):
                w.writerow([r["cve_id"], int(yte[i]), *[f"{scores[k][i]:.6g}" for k in scores]])
        log(f"\nSaved models and test_predictions.csv to {save_dir}/")
    return table, ci


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--train", default="dataset.csv")
    ap.add_argument("--test", default="dataset_2023.csv")
    ap.add_argument("--save-dir")
    ap.add_argument("--bootstrap", type=int, default=100, help="resamples for intervals (0 = skip)")
    ap.add_argument("--importance", action="store_true", help="also print GBM permutation importance")
    a = ap.parse_args(argv)
    return run(a.train, a.test, a.save_dir, a.bootstrap, a.importance)


if __name__ == "__main__":
    main()
