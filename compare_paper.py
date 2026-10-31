"""Compare ranked.csv with the paper's Table II / III.

    python compare_paper.py ranked.csv
"""
import csv
import sys

# CVE: (CVSS, paper's enhanced score) from Table II
PAPER = {
    "CVE-2016-0019": (8.1, 2.16),
    "CVE-2014-3566": (3.4, 3.81),
    "CVE-2010-0738": (5.3, 5.37),
    "CVE-2020-8195": (6.5, 6.54),
    "CVE-2023-25717": (9.8, 7.30),
}

path = sys.argv[1] if len(sys.argv) > 1 else "ranked.csv"
with open(path, newline="", encoding="utf-8") as f:
    ours = {r["cve_id"]: r for r in csv.DictReader(f)}

paper_rank = {c: i for i, c in enumerate(sorted(PAPER, key=lambda c: -PAPER[c][1]), 1)}
print(f"{'CVE':<16}{'CVSS':<6}{'Paper':<8}{'Ours':<8}{'Diff':<8}{'Rank paper/ours':<16}{'Adversaries'}")
for cve, (cvss, p) in sorted(PAPER.items(), key=lambda kv: -kv[1][1]):
    r = ours.get(cve)
    if not r:
        print(f"{cve:<16}{cvss:<6}{p:<8}{'(not in file)'}")
        continue
    s = float(r["score"])
    print(f"{cve:<16}{cvss:<6}{p:<8.2f}{s:<8.2f}{s - p:<+8.2f}"
          f"{paper_rank[cve]}/{r['rank']:<14}{r['n_adversaries']}")
