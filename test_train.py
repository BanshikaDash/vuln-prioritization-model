import csv

import numpy as np
import pytest

pytest.importorskip("sklearn")
import train_model as tm


def test_metrics_perfect_and_random():
    y = np.array([1, 1] + [0] * 98)
    m = tm.metrics(y, np.array([9, 8] + [1] * 98, float))
    assert m["AP"] == pytest.approx(1.0) and m["recall@5%"] == 1.0 and m["lift@5%"] == 20
    tied = tm.metrics(np.array([1] * 10 + [0] * 990), np.ones(1000))
    assert 0.003 < tied["AP"] < 0.03


def test_metrics_no_positives():
    assert np.isnan(tm.metrics(np.zeros(10, int), np.arange(10.0))["AP"])


def _write(path, n, seed):
    rng = np.random.default_rng(seed)
    cols = ["cve_id", "label", "cvss_base", "exploitability", "impact", "n_cpe", "n_cwe",
            "n_adversaries", "in_zdi", "epss", "epss_percentile", "n_public_exploits",
            "age_days", "paper_score", *tm.CATEGORICAL]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for i in range(n):
            exploits = int(rng.poisson(0.3))
            epss = float(rng.beta(0.3, 8))
            p = 0.004 + 0.12 * (exploits > 0) + 0.3 * epss
            w.writerow({
                "cve_id": f"CVE-2020-{i:05d}", "label": int(rng.random() < p),
                "cvss_base": round(float(rng.uniform(2, 10)), 1), "exploitability": 3.9,
                "impact": 5.9, "n_cpe": int(rng.integers(0, 20)), "n_cwe": 1,
                "n_adversaries": int(rng.integers(0, 5)), "in_zdi": 0, "epss": epss,
                "epss_percentile": min(1.0, epss * 3), "n_public_exploits": exploits,
                "age_days": int(rng.integers(100, 3000)), "paper_score": round(epss * 5, 3),
                **{c: tm.CATEGORICAL[c][0] for c in tm.CATEGORICAL}})


def test_end_to_end_beats_random_and_saves(tmp_path):
    _write(tmp_path / "tr.csv", 6000, 1)
    _write(tmp_path / "te.csv", 6000, 2)
    out = []
    table, ci = tm.run(str(tmp_path / "tr.csv"), str(tmp_path / "te.csv"),
                       save_dir=str(tmp_path / "m"), boot=5, importance=True, log=out.append)
    prevalence = np.mean([int(r["label"]) for r in csv.DictReader(open(tmp_path / "te.csv"))])
    for name in ("ml_gbm", "ml_logit"):
        assert table[name]["AP"] > 2 * prevalence
        assert table[name]["AP"] > table["cvss_base"]["AP"]   # cvss_base is pure noise here
    assert (tmp_path / "m" / "gbm.joblib").exists()
    rows = list(csv.DictReader(open(tmp_path / "m" / "test_predictions.csv")))
    assert len(rows) == 6000 and "ml_gbm" in rows[0]
    assert 0 <= ci["ml_gbm"]["AP"][0] <= ci["ml_gbm"]["AP"][1] <= 1
