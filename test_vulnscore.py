import pytest

from vulnscore import (
    WEIGHTS,
    Vulnerability,
    count_impact,
    cvss_subscores,
    prioritize,
    score_vulnerability,
)


def test_weights_sum_to_100():
    assert sum(WEIGHTS.values()) == 100


def test_count_impact_matches_paper():
    # Paper: 4 CPEs -> 0.8, 1 CWE -> 0.5, 0 advisories -> 0
    assert count_impact(4) == pytest.approx(0.8)
    assert count_impact(1) == pytest.approx(0.5)
    assert count_impact(0) == 0


def test_scenario_1_from_paper():
    """CVE-2016-0019: paper reports raw 21.57386, normalized 2.16."""
    v = Vulnerability(
        cve_id="CVE-2016-0019",
        exploitability_subscore=2.2,
        impact_subscore=5.9,
        n_cpe=4,
        n_cwe=1,
        n_adversaries=0,
        epss=0.00643,
        epss_percentile=0.79239,
    )
    r = score_vulnerability(v)
    assert r.raw == pytest.approx(21.57386, abs=1e-5)
    assert round(r.score, 2) == 2.16


def test_vector_gives_paper_subscores_for_scenario_1():
    # CVE-2016-0019 is CVSS 8.1: AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H
    e, i = cvss_subscores("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert (e, i) == (2.2, 5.9)


def test_known_nvd_subscores():
    # 9.8 critical: exploitability 3.9, impact 5.9
    assert cvss_subscores("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == (3.9, 5.9)
    # 6.1 reflected XSS (scope changed): exploitability 2.8, impact 2.7
    assert cvss_subscores("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == (2.8, 2.7)


def test_vector_and_manual_subscores_agree():
    vec = Vulnerability("A", cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        n_cpe=4, n_cwe=1, epss=0.00643, epss_percentile=0.79239)
    man = Vulnerability("A", exploitability_subscore=2.2, impact_subscore=5.9,
                        n_cpe=4, n_cwe=1, epss=0.00643, epss_percentile=0.79239)
    assert score_vulnerability(vec).raw == pytest.approx(score_vulnerability(man).raw)


def test_score_never_exceeds_100():
    v = Vulnerability("MAX", exploitability_subscore=10, impact_subscore=10,
                      n_cpe=10_000, n_cwe=10_000, n_adversaries=10_000,
                      epss=1, epss_percentile=1, in_kev=True, in_zdi=True,
                      exploited_in_wild=True)
    assert score_vulnerability(v).raw <= 100


def test_exploited_in_wild_outranks_high_cvss_alone():
    quiet = Vulnerability("QUIET", cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    hot = Vulnerability("HOT", cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                        exploited_in_wild=True, in_kev=True, epss=0.9, epss_percentile=0.99,
                        n_adversaries=5)
    assert [r.cve_id for r in prioritize([quiet, hot])] == ["HOT", "QUIET"]


def test_missing_cvss_data_raises():
    with pytest.raises(ValueError):
        score_vulnerability(Vulnerability("X"))


def test_rejects_cvss_v2_vector():
    with pytest.raises(ValueError):
        cvss_subscores("AV:N/AC:L/Au:N/C:P/I:P/A:P")
