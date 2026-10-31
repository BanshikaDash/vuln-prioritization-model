import json
import os

import pytest

import fetchers
import pipeline
from mitre import ALL_KINDS, AdversaryMapper

# ---- tiny fake MITRE data ---------------------------------------------------
CAPEC = {"objects": [
    {"type": "attack-pattern", "id": "attack-pattern--c1", "external_references": [
        {"source_name": "capec", "external_id": "CAPEC-1"},
        {"source_name": "cwe", "external_id": "CWE-287"},
        {"source_name": "ATTACK", "external_id": "T1078"},
        {"source_name": "ATTACK", "external_id": "1550.001"}]},   # no leading T
    {"type": "attack-pattern", "id": "attack-pattern--c2", "external_references": [
        {"source_name": "capec", "external_id": "CAPEC-2"},
        {"source_name": "cwe", "external_id": "CWE-287"},
        {"source_name": "cwe", "external_id": "CWE-20"},
        {"source_name": "ATTACK", "external_id": "T1078"}]},      # same technique again
    {"type": "attack-pattern", "id": "attack-pattern--c3", "revoked": True,
     "external_references": [{"source_name": "capec", "external_id": "CAPEC-3"},
                             {"source_name": "cwe", "external_id": "CWE-79"},
                             {"source_name": "ATTACK", "external_id": "T9999"}]},
]}


def _ap(i, tid, **kw):
    return {"type": "attack-pattern", "id": f"attack-pattern--{i}", "external_references": [
        {"source_name": "mitre-attack", "external_id": tid}], **kw}


ATTACK = {"objects": [
    _ap("t1", "T1078"), _ap("t2", "T1550.001"), _ap("t3", "T9999"),
    {"type": "intrusion-set", "id": "intrusion-set--g1", "name": "GroupA"},
    {"type": "intrusion-set", "id": "intrusion-set--g2", "name": "GroupB"},
    {"type": "intrusion-set", "id": "intrusion-set--g3", "name": "OldGroup", "revoked": True},
    {"type": "malware", "id": "malware--m1", "name": "Mal"},
    *[{"type": "relationship", "relationship_type": "uses", "source_ref": s, "target_ref": t}
      for s, t in [("intrusion-set--g1", "attack-pattern--t1"),
                   ("intrusion-set--g2", "attack-pattern--t1"),
                   ("intrusion-set--g2", "attack-pattern--t2"),   # g2 counted once overall
                   ("intrusion-set--g3", "attack-pattern--t1"),   # revoked group ignored
                   ("malware--m1", "attack-pattern--t1")]],
]}


@pytest.fixture
def mapper(tmp_path):
    (tmp_path / "capec.json").write_text(json.dumps(CAPEC))
    (tmp_path / "attack.json").write_text(json.dumps(ATTACK))
    return str(tmp_path / "capec.json"), str(tmp_path / "attack.json")


def test_adversaries_deduplicated_and_revoked_ignored(mapper):
    m = AdversaryMapper(*mapper)
    assert m.techniques_for_cwes(["CWE-287"]) == {"T1078", "T1550.001"}
    assert m.count_for_cwes(["CWE-287"]) == 2          # GroupA, GroupB
    assert m.count_for_cwes(["CWE-287", "CWE-20"]) == 2
    assert m.count_for_cwes(["CWE-79"]) == 0           # revoked CAPEC
    assert m.count_for_cwes(["CWE-000"]) == 0


def test_software_counted_only_when_asked(mapper):
    assert AdversaryMapper(*mapper, kinds=ALL_KINDS).count_for_cwes(["CWE-287"]) == 3


@pytest.mark.skipif(not os.path.exists("/tmp/cache/enterprise-attack.json"),
                    reason="real MITRE files not cached")
def test_real_mitre_data():
    m = AdversaryMapper("/tmp/cache/stix-capec.json", "/tmp/cache/enterprise-attack.json")
    assert m.count_for_cwes(["CWE-287"]) > 0
    assert m.count_for_cwes(["CWE-20"]) > 0


# ---- parsers ----------------------------------------------------------------
NVD = {"vulnerabilities": [{"cve": {
    "metrics": {"cvssMetricV31": [{"cvssData": {
        "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", "baseScore": 8.1}}]},
    "weaknesses": [{"description": [{"value": "CWE-287"}, {"value": "NVD-CWE-Other"}]}],
    "configurations": [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:o:a:1"},
        {"vulnerable": True, "criteria": "cpe:2.3:o:a:1"},      # duplicate
        {"vulnerable": True, "criteria": "cpe:2.3:o:a:2"},
        {"vulnerable": False, "criteria": "cpe:2.3:h:b:1"}]}]}],
    "references": [{"url": "https://www.zerodayinitiative.com/advisories/ZDI-16-1"}],
}}]}


def test_parse_nvd():
    r = fetchers.parse_nvd(NVD, "CVE-X")
    assert r["cvss_vector"].startswith("CVSS:3.1") and r["cvss_base"] == 8.1
    assert r["n_cpe"] == 2 and r["cwes"] == ["CWE-287"] and r["in_zdi"] is True


def test_parse_nvd_missing():
    with pytest.raises(LookupError):
        fetchers.parse_nvd({"vulnerabilities": []}, "CVE-X")


def test_parse_epss():
    p = {"data": [{"cve": "CVE-X", "epss": "0.00643", "percentile": "0.79239"}]}
    assert fetchers.parse_epss(p) == (0.00643, 0.79239)
    assert fetchers.parse_epss({"data": []}) == (0.0, 0.0)


def test_parse_kev():
    assert fetchers.parse_kev({"vulnerabilities": [{"cveID": "CVE-2023-25717"}]}) == {"CVE-2023-25717"}


@pytest.mark.skipif(not os.path.exists("/tmp/data/kev.json"), reason="no KEV sample")
def test_real_kev_file():
    kev = fetchers.parse_kev(json.load(open("/tmp/data/kev.json")))
    assert len(kev) > 1000 and "CVE-2023-25717" in kev


def test_inthewild_shapes_and_ignores_free_text():
    assert fetchers.extract_cve_ids(["CVE-2024-1", "cve-2024-12345"]) == {"CVE-2024-12345"}
    p = {"data": [{"id": "CVE-2024-9474", "description": "see CVE-2024-0012 too"}]}
    assert fetchers.extract_cve_ids(p) == {"CVE-2024-9474"}
    assert fetchers.extract_cve_ids([{"cve": "CVE-2023-28461"}]) == {"CVE-2023-28461"}


# ---- whole pipeline with network mocked --------------------------------------
def test_pipeline_end_to_end(monkeypatch, mapper, tmp_path):
    monkeypatch.setattr(pipeline, "load_kev", lambda: {"CVE-HOT"})
    monkeypatch.setattr(pipeline, "load_inthewild", lambda: {"CVE-HOT"})
    monkeypatch.setattr(pipeline.AdversaryMapper, "from_cache",
                        classmethod(lambda cls, cache, kinds: cls(*mapper, kinds=kinds)))

    def nvd(cve, key=None):
        base = {"cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cvss_base": 8.1, "n_cpe": 4, "cwes": ["CWE-1"], "in_zdi": False}
        if cve == "CVE-HOT":
            base.update(cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                        cvss_base=4.3, cwes=["CWE-287"])
        return base

    monkeypatch.setattr(pipeline, "fetch_nvd", nvd)
    monkeypatch.setattr(pipeline, "fetch_epss",
                        lambda c: (0.9, 0.99) if c == "CVE-HOT" else (0.006, 0.79))
    out = tmp_path / "r.csv"
    assert pipeline.main(["CVE-QUIET", "CVE-HOT", "-o", str(out)]) == 0
    lines = out.read_text().splitlines()
    assert lines[1].split(",")[1] == "CVE-HOT"      # exploited, low CVSS beats quiet 8.1
    assert lines[2].split(",")[1] == "CVE-QUIET"
