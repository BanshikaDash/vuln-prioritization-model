import csv
import gzip
import sqlite3
from datetime import date

import pytest

import build_dataset as bd
import evaluate_baselines as ev
import fetchers

VEC = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
T = date(2022, 1, 1)


class FakeMapper:
    def count_for_cwes(self, cwes):
        return 2 if "CWE-287" in cwes else 0


def rec(cid, published="2020-05-01T10:00:00.000", vector=VEC, cwes=("CWE-287",)):
    return {"cve_id": cid, "published": published, "cvss_vector": vector, "cvss_base": 9.8,
            "n_cpe": 3, "cwes": list(cwes), "in_zdi": False}


def build(records, kev=None, itw=None, counts=None, epss=None):
    return bd.build_rows(records, T, 365, kev or {}, itw or {}, counts or {},
                         epss or {}, FakeMapper())


def test_windows_cover_range_without_gaps():
    w = list(bd.windows(date(2015, 1, 1), date(2016, 1, 1)))
    assert w[0][0] == date(2015, 1, 1) and w[-1][1] == date(2016, 1, 1)
    assert all(b[0] == a[1] for a, b in zip(w, w[1:]))
    assert all((e - s).days <= 120 for s, e in w)


def test_fetch_window_pages_until_done(monkeypatch):
    pages = {0: {"totalResults": 3, "vulnerabilities": [{"cve": {"id": "CVE-1"}}, {"cve": {"id": "CVE-2"}}]},
             2: {"totalResults": 3, "vulnerabilities": [{"cve": {"id": "CVE-3"}}]}}
    monkeypatch.setattr(bd, "_get_json", lambda url, p, h: pages[p["startIndex"]])
    monkeypatch.setattr(bd.time, "sleep", lambda s: None)
    out = bd.fetch_window(date(2020, 1, 1), date(2020, 4, 1))
    assert [r["cve_id"] for r in out] == ["CVE-1", "CVE-2", "CVE-3"]


def test_label_from_kev_inside_window():
    rows, st = build([rec("CVE-2020-1")], kev={"CVE-2020-1": "2022-03-03"})
    assert rows[0]["label"] == 1 and rows[0]["label_source"] == "kev"
    assert rows[0]["exploited_date"] == "2022-03-03"


def test_label_from_inthewild_and_both():
    rows, _ = build([rec("CVE-2020-1")], itw={"CVE-2020-1": "2022-06-01"})
    assert rows[0]["label_source"] == "itw"
    rows, _ = build([rec("CVE-2020-1")], kev={"CVE-2020-1": "2022-09-01"},
                    itw={"CVE-2020-1": "2022-06-01"})
    assert rows[0]["label_source"] == "kev+itw" and rows[0]["exploited_date"] == "2022-06-01"


def test_exploited_after_window_is_negative():
    rows, _ = build([rec("CVE-2020-1")], kev={"CVE-2020-1": "2023-02-01"})
    assert rows[0]["label"] == 0


def test_already_exploited_before_snapshot_is_excluded():
    rows, st = build([rec("CVE-2020-1"), rec("CVE-2020-2")],
                     kev={"CVE-2020-1": "2021-11-03"}, itw={"CVE-2020-2": "2021-05-05"})
    assert rows == [] and st["dropped_already_exploited_at_snapshot"] == 2


def test_filters_v2_only_and_post_snapshot():
    rows, st = build([rec("CVE-2020-1", vector=None), rec("CVE-2020-2", vector="AV:N/AC:L/Au:N/C:P/I:P/A:P"),
                      rec("CVE-2022-9", published="2022-02-01T00:00:00.000")])
    assert rows == []
    assert st["dropped_no_cvss_v3"] == 2 and st["dropped_not_published_before_snapshot"] == 1


def test_features_and_paper_score():
    rows, _ = build([rec("CVE-2020-1")], epss={"CVE-2020-1": (0.5, 0.9)}, counts={"CVE-2020-1": 4})
    r = rows[0]
    assert (r["exploitability"], r["impact"]) == (3.9, 5.9)
    assert r["n_adversaries"] == 2 and r["epss"] == 0.5 and r["n_public_exploits"] == 4
    assert r["age_days"] == (T - date(2020, 5, 1)).days
    assert (r["av"], r["ac"], r["s"]) == ("N", "L", "U")
    # 18*.39 + 15*(1-1/3) + 12*.59 + 10*.5 + 6*.75 + 5*.5 + 4*.9
    assert r["paper_score"] == pytest.approx(
        (18 * .39 + 15 * (2 / 3) + 12 * .59 + 10 * .5 + 6 * .75 + 5 * .5 + 4 * .9) / 10, abs=1e-4)


def test_missing_epss_is_zero():
    rows, _ = build([rec("CVE-2020-1")])
    assert rows[0]["epss"] == 0.0


def test_parse_epss_gz(tmp_path):
    p = tmp_path / "e.csv.gz"
    with gzip.open(p, "wt", encoding="utf-8") as f:
        f.write("#model_version:v2021.03.14,score_date:2022-01-01T00:00:00Z\ncve,epss,percentile\n"
                "CVE-2020-1,0.5,0.9\nCVE-2020-2,0.01,0.2\n")
    with gzip.open(p, "rt", encoding="utf-8") as f:
        assert bd.parse_epss_csv(f) == {"CVE-2020-1": (0.5, 0.9), "CVE-2020-2": (0.01, 0.2)}


def test_timeline_from_db(tmp_path):
    p = str(tmp_path / "i.db")
    con = sqlite3.connect(p)
    con.execute("create table exploits (id text, referenceURL text, timeStamp text, source text, type text)")
    con.executemany("insert into exploits values (?,?,?,?,?)", [
        ("CVE-2020-0001", "u", "2022-05-05T00:00:00.000Z", "s", "exploitation"),
        ("CVE-2020-0001", "u", "2022-02-02T00:00:00.000Z", "s", "exploitation"),
        ("CVE-2020-0001", "u", "2021-01-01T00:00:00.000Z", "s", "exploit"),
        ("CVE-2020-0001", "u", "2023-01-01T00:00:00.000Z", "s", "exploit"),   # after T: not counted
        ("CVE-2020-0002", "u", "2021-12-31T00:00:00.000Z", "s", "exploit"),
    ])
    con.commit(); con.close()
    first, counts = fetchers.load_inthewild_timeline(p, "2022-01-01")
    assert first == {"CVE-2020-0001": "2022-02-02"}
    assert counts == {"CVE-2020-0001": 1, "CVE-2020-0002": 1}


def test_kev_dates():
    assert fetchers.parse_kev_dates({"vulnerabilities": [{"cveID": "CVE-1", "dateAdded": "2022-03-03"}]}) == {"CVE-1": "2022-03-03"}


# ---- evaluation ---------------------------------------------------------------
def test_perfect_score_metrics():
    labels = [1, 1] + [0] * 98
    scores = [10, 9] + [1] * 98
    assert ev.average_precision(labels, scores) == pytest.approx(1.0)
    assert ev.recall_at(labels, scores, 0.05) == 1.0


def test_tied_scores_behave_like_random():
    labels = [1] * 10 + [0] * 990
    ap = ev.average_precision(labels, [1.0] * 1000)
    assert 0.005 < ap < 0.03          # near the 1% base rate, not near 1


def test_evaluate_cli_roundtrip(tmp_path, capsys):
    rows = [{"cve_id": f"C{i}", "label": int(i < 5), "cvss_base": 10 - i * 0.01,
             "epss": 0.5, "paper_score": 5.0} for i in range(100)]
    p = tmp_path / "d.csv"
    bd.COLUMNS  # imported ok
    with open(p, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader(); w.writerows(rows)
    res = ev.main([str(p)])
    assert res["cvss_base"]["AP"] == pytest.approx(1.0)
    assert res["epss"]["AP"] < 0.5
    assert "random" in capsys.readouterr().out
