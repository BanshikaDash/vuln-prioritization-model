# Vulnerability prioritization model

Implementation of "Vulnerability Weightage and Prioritization Model" (COMPSAC 2025).

    pip install -r requirements.txt
    python pipeline.py CVE-2016-0019 CVE-2014-3566 CVE-2023-25717 -o ranked.csv --nvd-key YOUR_KEY
    python -m pytest

| File | What it does |
|---|---|
| vulnscore.py | The scoring model (weights, CVSS sub-scores, final score, ranking). Also ranks a ready-made CSV. |
| fetchers.py | NVD, EPSS, CISA KEV and inthewild.io data collection |
| mitre.py | CWE -> CAPEC -> ATT&CK -> adversary count |
| inspect_itw.py | Shows the layout of inthewild.db |
| pipeline.py | Runs everything for a list of CVEs |

Score is 0-100 raw, shown as raw / 10 like the paper's case study.
First run downloads about 60 MB of MITRE data into `mitre_cache/`.
## Assumptions (where the paper is unclear)
- Adversaries = ATT&CK groups reached via CWE -> CAPEC -> ATT&CK (software and campaigns optional).
- CPE count = unique vulnerable CPEs listed by NVD.
- ZDI flag = NVD links to a Zero Day Initiative advisory.
- Exploited in the wild = "exploitation" reports in inthewild.db.
- CVSS sub-scores are divided by 10 as the paper states, so exploitability tops out near 0.39.
- CVE-2014-3566 scores about 1 point below the paper: its weakness (CWE-310) has no ATT&CK link in MITRE's data.