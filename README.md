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
| alerts.py | Email alert system: priority levels, subject-line flags, dry-run and send |
| pipeline.py | Runs everything for a list of CVEs |

Score is 0-100 raw, shown as raw / 10 like the paper's case study.
First run downloads about 60 MB of MITRE data into `mitre_cache/`.

## Email alerts
    python alerts.py CVE-2023-25717 CVE-2014-3566          # dry run, writes outbox/*.eml
    python alerts.py --recent-days 7 --min-level MEDIUM --send

Levels: CRITICAL (in KEV or exploited in the wild, one email each), HIGH (top 1% by
learned score), MEDIUM (top 5%), LOW (no email). A CVE is emailed only when new or
when its level goes up. Needs models/ from `python train_model.py --save-dir models`
and inthewild.db in the project folder.
