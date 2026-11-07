import json
import os
from datetime import date

import numpy as np
import pytest

pytest.importorskip("sklearn")
import alerts as al
import train_model as tm
from test_train import _write

VEC = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
TODAY = date(2026, 11, 7)


class FakeMapper:
    def count_for_cwes(self, cwes):
        return 3 if cwes else 0


@pytest.fixture(scope="module")
def models_dir(tmp_path_factory):
    d = tmp_path_factory.mktemp("m")
    _write(d / "tr.csv", 6000, 1)
    _write(d / "te.csv", 6000, 2)
    tm.run(str(d / "tr.csv"), str(d / "te.csv"), save_dir=str(d / "models"), boot=0, log=lambda m: None)
    return str(d / "models")


def rec(cid, vector=VEC, published="2026-11-01T00:00:00.000", cwes=("CWE-79",)):
    return {"cve_id": cid, "published": published, "cvss_vector": vector, "cvss_base": 9.8,
            "n_cpe": 3, "cwes": list(cwes), "in_zdi": False}


# ---- levels ----------------------------------------------------------------------
THR = {"high": 0.8, "medium": 0.5}


def test_classify():
    assert al.classify(True, False, 0.01, THR) == "CRITICAL"
    assert al.classify(False, True, None, THR) == "CRITICAL"
    assert al.classify(False, False, 0.9, THR) == "HIGH"
    assert al.classify(False, False, 0.6, THR) == "MEDIUM"
    assert al.classify(False, False, 0.1, THR) == "LOW"
    assert al.classify(False, False, None, THR) is None


def test_thresholds_and_top_percent(models_dir):
    thr = al.load_thresholds(models_dir)
    assert os.path.exists(os.path.join(models_dir, "thresholds.json"))
    assert thr["high"] > thr["medium"]
    assert al.top_percent(thr["high"], thr["quantiles"]) == pytest.approx(1.0, abs=0.3)
    assert al.top_percent(thr["medium"], thr["quantiles"]) == pytest.approx(5.0, abs=0.6)
    assert al.top_percent(thr["quantiles"][-1] + 1, thr["quantiles"]) == 0.01   # best possible
    assert al.load_thresholds(models_dir) == thr                                # cached read


# ---- assessing -------------------------------------------------------------------
def _model(models_dir):
    import joblib
    return joblib.load(os.path.join(models_dir, "logit.joblib"))


def test_assess_scores_and_explains(models_dir):
    thr = al.load_thresholds(models_dir)
    a = al.assess(rec("CVE-2026-0001"), (0.5, 0.9), set(), {}, {"CVE-2026-0001": 4},
                  FakeMapper(), _model(models_dir), thr, TODAY)
    assert a.ml_score is not None and 0 <= a.ml_score <= 1 and a.top_pct is not None
    assert a.level in al.LEVELS and any("EPSS 0.500" in r for r in a.reasons)
    assert any("4 exploit-tagged" in r for r in a.reasons)


def test_assess_kev_is_critical_even_without_cvss_v3(models_dir):
    thr = al.load_thresholds(models_dir)
    a = al.assess(rec("CVE-2026-0002", vector=None), (0.0, 0.0), {"CVE-2026-0002"}, {}, {},
                  FakeMapper(), _model(models_dir), thr, TODAY)
    assert a.level == "CRITICAL" and a.ml_score is None
    assert any("KEV" in r for r in a.reasons)


def test_assess_unscorable_returns_none(models_dir):
    thr = al.load_thresholds(models_dir)
    assert al.assess(rec("CVE-2026-0003", vector=None), (0.0, 0.0), set(), {}, {},
                     FakeMapper(), _model(models_dir), thr, TODAY) is None


def test_parse_epss_many():
    p = {"data": [{"cve": "CVE-1", "epss": "0.5", "percentile": "0.9"}]}
    assert al.parse_epss_many(p) == {"CVE-1": (0.5, 0.9)}


# ---- emails ----------------------------------------------------------------------
def mk(cid, level, score=0.5):
    a = al.Alert(cid, level, score, 2.0, "2026-11-01", 9.8, 0.4, 0.9,
                 level == "CRITICAL", False, 1, 2)
    a.reasons = al.explain(a)
    return a


def test_compose_critical_separate_and_digest_flagged():
    alerts = [mk("CVE-A", "CRITICAL"), mk("CVE-B", "HIGH", 0.9), mk("CVE-C", "MEDIUM"), mk("CVE-D", "LOW")]
    msgs = al.compose(alerts, "MEDIUM", "from@x.com", ["to@x.com"], TODAY)
    assert len(msgs) == 2
    assert msgs[0]["Subject"].startswith("[CRITICAL] CVE-A")
    assert msgs[1]["Subject"].startswith("[HIGH] Vulnerability digest 2026-11-07: 1 high, 1 medium")
    body = msgs[1].get_body(("plain",)).get_content()
    assert "CVE-B" in body and "CVE-C" in body and "CVE-D" not in body
    assert msgs[1].get_body(("html",)) is not None
    assert msgs[0]["To"] == "to@x.com"


def test_compose_respects_min_level():
    alerts = [mk("CVE-B", "HIGH"), mk("CVE-C", "MEDIUM")]
    msgs = al.compose(alerts, "HIGH", "f@x.com", ["t@x.com"], TODAY)
    assert len(msgs) == 1 and "CVE-C" not in msgs[0].get_body(("plain",)).get_content()
    assert al.compose([mk("CVE-D", "LOW")], "MEDIUM", "f@x.com", ["t@x.com"], TODAY) == []


def test_html_is_escaped():
    a = mk("CVE-X", "HIGH")
    a.reasons = ["<script>alert(1)</script>"]
    m = al.digest_email([a], "f@x.com", ["t@x.com"], TODAY)
    assert "<script>" not in m.get_body(("html",)).get_content()


# ---- do not repeat ----------------------------------------------------------------
def test_only_new_or_escalated():
    state = {"CVE-A": "MEDIUM", "CVE-B": "HIGH"}
    out = al.only_new([mk("CVE-A", "HIGH"), mk("CVE-B", "HIGH"), mk("CVE-C", "MEDIUM")], state)
    assert [a.cve_id for a in out] == ["CVE-A", "CVE-C"]
    al.record_sent(out, state)
    assert state == {"CVE-A": "HIGH", "CVE-B": "HIGH", "CVE-C": "MEDIUM"}


# ---- whole run with the network mocked ------------------------------------------
@pytest.fixture
def run_env(monkeypatch, models_dir, tmp_path):
    monkeypatch.setattr(al, "load_kev", lambda: {"CVE-2026-0100"})
    monkeypatch.setattr(al, "load_inthewild_timeline", lambda p, b: ({}, {"CVE-2026-0200": 6}))
    monkeypatch.setattr(al.AdversaryMapper, "from_cache", classmethod(lambda cls, c, k: FakeMapper()))
    monkeypatch.setattr(al, "fetch_nvd", lambda cid, key=None: rec(cid))
    monkeypatch.setattr(al, "fetch_epss_many", lambda ids: {i: (0.9, 0.99) for i in ids})
    monkeypatch.setattr(al, "date", type("D", (date,), {"today": staticmethod(lambda: TODAY)}))
    sent = []
    monkeypatch.setattr(al, "send_messages", lambda msgs, cfg: sent.extend(msgs))
    monkeypatch.setenv("SMTP_HOST", "smtp.test")
    monkeypatch.setenv("SMTP_USER", "me@test")
    monkeypatch.setenv("SMTP_PASSWORD", "pw")
    monkeypatch.setenv("ALERT_TO", "a@test, b@test")
    args = ["CVE-2026-0100", "CVE-2026-0200", "--models-dir", models_dir,
            "--state", str(tmp_path / "state.json"), "--outbox", str(tmp_path / "out"),
            "--itw-db", "x.db", "--min-level", "LOW"]
    return args, sent, tmp_path


def test_dry_run_writes_eml_and_keeps_state_empty(run_env):
    args, sent, tmp = run_env
    assert al.main(args) == 0
    emls = sorted(os.listdir(tmp / "out"))
    assert emls and all(f.endswith(".eml") for f in emls) and not sent
    assert not os.path.exists(tmp / "state.json")


def test_send_then_second_run_sends_nothing(run_env):
    args, sent, tmp = run_env
    assert al.main(args + ["--send"]) == 0
    assert any(m["Subject"].startswith("[CRITICAL] CVE-2026-0100") for m in sent)
    assert sent[0]["To"] == "a@test, b@test"
    state = json.load(open(tmp / "state.json"))
    assert state["CVE-2026-0100"] == "CRITICAL"
    n = len(sent)
    assert al.main(args + ["--send"]) == 0
    assert len(sent) == n                      # nothing repeated


def test_send_without_email_settings_fails_clearly(run_env, monkeypatch):
    args, _, _ = run_env
    monkeypatch.delenv("SMTP_HOST")
    with pytest.raises(RuntimeError, match="SMTP_HOST"):
        al.main(args + ["--send"])


def test_tiny_percentages_are_not_shown_as_zero():
    assert al.pct_text(0.01) == "<0.1%" and al.pct_text(0.3) == "0.3%" and al.pct_text(4.96) == "5.0%"
    a = mk("CVE-X", "HIGH")
    a.top_pct = 0.01
    assert "top <0.1%" in al._fmt_risk(a)
