"""
Vulnerability weightage and prioritization model.

Implements the scoring method from "Vulnerability Weightage and Prioritization
Model: Derived from Real Data and Community Insights" (COMPSAC 2025).

Final score = sum(weight_i * metric_i), weights add up to 100, so the raw score
is 0-100. The paper's case study then divides by 10 to report a 0-10 score.

Run as a script to rank a CSV:
    python vulnscore.py vulns.csv            # prints ranked table
    python vulnscore.py vulns.csv -o out.csv # also writes a CSV
"""
from __future__ import annotations

import argparse
import csv
import math
from dataclasses import dataclass, field
from typing import Optional

# ---- Table I: weights ------------------------------------------------------
WEIGHTS = {
    "exploited_in_wild": 20,
    "exploitability": 18,
    "adversary_impact": 15,
    "impact": 12,
    "epss": 10,
    "cpe_impact": 6,
    "cwe_impact": 5,
    "epss_percentile": 4,
    "kev": 5,
    "zdi": 5,
}
assert sum(WEIGHTS.values()) == 100

# ---- CVSS v3.x constants (FIRST specification) ------------------------------
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _round1(x: float) -> float:
    """Round half up to 1 decimal (NVD shows sub scores this way)."""
    return math.floor(x * 10 + 0.5) / 10


def parse_vector(vector: str) -> dict:
    """'CVSS:3.1/AV:N/AC:H/...' -> {'AV': 'N', 'AC': 'H', ...}"""
    parts = vector.strip().split("/")
    if not parts[0].startswith("CVSS:3"):
        raise ValueError(f"Only CVSS v3.x vectors are supported: {vector!r}")
    out = {}
    for p in parts[1:]:
        k, _, v = p.partition(":")
        out[k] = v
    needed = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    if not needed <= out.keys():
        raise ValueError(f"Incomplete CVSS vector: {vector!r}")
    return out


def impact_sub_score_raw(c: float, i: float, a: float) -> float:
    """Equation 1 in the paper. Returns a value between 0 and 1."""
    return 1 - (1 - c) * (1 - i) * (1 - a)


def cvss_subscores(vector: str, rounded: bool = True) -> tuple[float, float]:
    """Return (exploitability, impact), each on the CVSS 0-10 style scale.

    Exploitability is equation 2 (8.22 x AV x AC x PR x UI).
    Impact follows the CVSS v3.1 spec (scope aware), which is what the
    paper's case study numbers (e.g. 0.59) are based on.
    """
    m = parse_vector(vector)
    changed = m["S"] == "C"
    pr = (_PR_CHANGED if changed else _PR_UNCHANGED)[m["PR"]]
    expl = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]
    iss = impact_sub_score_raw(_CIA[m["C"]], _CIA[m["I"]], _CIA[m["A"]])
    if changed:
        imp = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        imp = 6.42 * iss
    imp = max(imp, 0.0)
    if rounded:
        return _round1(expl), _round1(imp)
    return expl, imp


# ---- Equations 3-5: saturating counts --------------------------------------
def count_impact(n: int) -> float:
    """1 - 1/(1+n). Used for CPEs, CWEs and adversaries."""
    if n < 0:
        raise ValueError("count cannot be negative")
    return 1 - 1 / (1 + n)


# ---- Data model -------------------------------------------------------------
@dataclass
class Vulnerability:
    cve_id: str
    # Give either a CVSS v3 vector, or the two sub scores (0-10) directly.
    cvss_vector: Optional[str] = None
    exploitability_subscore: Optional[float] = None  # 0-10 scale
    impact_subscore: Optional[float] = None  # 0-10 scale
    cvss_base: Optional[float] = None  # only kept for comparison
    n_cpe: int = 0
    n_cwe: int = 0
    n_adversaries: int = 0
    epss: float = 0.0  # 0-1
    epss_percentile: float = 0.0  # 0-1
    in_kev: bool = False
    in_zdi: bool = False
    exploited_in_wild: bool = False


@dataclass
class ScoreResult:
    cve_id: str
    raw: float  # 0-100
    score: float  # raw / 10, the 0-10 value the paper reports
    terms: dict = field(default_factory=dict)  # contribution of each metric


def score_vulnerability(v: Vulnerability) -> ScoreResult:
    expl, imp = v.exploitability_subscore, v.impact_subscore
    if expl is None or imp is None:
        if not v.cvss_vector:
            raise ValueError(f"{v.cve_id}: need a CVSS vector or both sub scores")
        e2, i2 = cvss_subscores(v.cvss_vector)
        expl = e2 if expl is None else expl
        imp = i2 if imp is None else imp

    metrics = {
        "exploited_in_wild": 1.0 if v.exploited_in_wild else 0.0,
        "exploitability": expl / 10,
        "adversary_impact": count_impact(v.n_adversaries),
        "impact": imp / 10,
        "epss": v.epss,
        "cpe_impact": count_impact(v.n_cpe),
        "cwe_impact": count_impact(v.n_cwe),
        "epss_percentile": v.epss_percentile,
        "kev": 1.0 if v.in_kev else 0.0,
        "zdi": 1.0 if v.in_zdi else 0.0,
    }
    terms = {k: WEIGHTS[k] * metrics[k] for k in WEIGHTS}
    raw = sum(terms.values())
    return ScoreResult(v.cve_id, raw, raw / 10, terms)


def prioritize(vulns: list[Vulnerability]) -> list[ScoreResult]:
    """Score everything and sort highest first (step 5 of the paper)."""
    return sorted((score_vulnerability(v) for v in vulns), key=lambda r: -r.raw)


# ---- CSV helpers ------------------------------------------------------------
def _b(x: str) -> bool:
    return str(x).strip().lower() in {"1", "true", "yes", "y"}


def _opt_float(x: str) -> Optional[float]:
    x = (x or "").strip()
    return float(x) if x else None


def read_csv(path: str) -> list[Vulnerability]:
    """Columns: cve_id, cvss_vector, exploitability_subscore, impact_subscore,
    cvss_base, n_cpe, n_cwe, n_adversaries, epss, epss_percentile, in_kev,
    in_zdi, exploited_in_wild. Missing columns are treated as empty."""
    out = []
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            g = lambda k: row.get(k, "")  # noqa: E731
            out.append(
                Vulnerability(
                    cve_id=g("cve_id"),
                    cvss_vector=g("cvss_vector").strip() or None,
                    exploitability_subscore=_opt_float(g("exploitability_subscore")),
                    impact_subscore=_opt_float(g("impact_subscore")),
                    cvss_base=_opt_float(g("cvss_base")),
                    n_cpe=int(g("n_cpe") or 0),
                    n_cwe=int(g("n_cwe") or 0),
                    n_adversaries=int(g("n_adversaries") or 0),
                    epss=float(g("epss") or 0),
                    epss_percentile=float(g("epss_percentile") or 0),
                    in_kev=_b(g("in_kev")),
                    in_zdi=_b(g("in_zdi")),
                    exploited_in_wild=_b(g("exploited_in_wild")),
                )
            )
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("csv_in")
    ap.add_argument("-o", "--out", help="write ranked results to this CSV")
    args = ap.parse_args()

    results = prioritize(read_csv(args.csv_in))
    print(f"{'Rank':<5}{'CVE':<18}{'Score (0-10)':<14}Raw (0-100)")
    for n, r in enumerate(results, 1):
        print(f"{n:<5}{r.cve_id:<18}{r.score:<14.2f}{r.raw:.3f}")

    if args.out:
        with open(args.out, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["rank", "cve_id", "score", "raw", *WEIGHTS.keys()])
            for n, r in enumerate(results, 1):
                w.writerow([n, r.cve_id, round(r.score, 4), round(r.raw, 5),
                            *[round(r.terms[k], 5) for k in WEIGHTS]])


if __name__ == "__main__":
    main()
