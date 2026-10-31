"""
End to end run of the model.

    python pipeline.py CVE-2016-0019 CVE-2014-3566 CVE-2023-25717
    python pipeline.py --file cves.txt -o ranked.csv --nvd-key YOUR_KEY

Steps (section II-D of the paper): collect data, compute the extra metrics,
normalize, score, rank.
"""
from __future__ import annotations

import argparse
import csv
import os
import sys

from fetchers import fetch_epss, fetch_nvd, load_inthewild, load_inthewild_db, load_inthewild_file, load_kev
from mitre import ALL_KINDS, GROUPS_ONLY, AdversaryMapper
from vulnscore import WEIGHTS, Vulnerability, prioritize


def build_vulnerability(cve_id, kev, itw, mapper, nvd_api_key=None) -> Vulnerability:
    cve_id = cve_id.upper()
    nvd = fetch_nvd(cve_id, nvd_api_key)
    epss, pct = fetch_epss(cve_id)
    return Vulnerability(
        cve_id=cve_id,
        cvss_vector=nvd["cvss_vector"],
        cvss_base=nvd["cvss_base"],
        n_cpe=nvd["n_cpe"],
        n_cwe=len(nvd["cwes"]),
        n_adversaries=mapper.count_for_cwes(nvd["cwes"]),
        epss=epss,
        epss_percentile=pct,
        in_kev=cve_id in kev,
        in_zdi=nvd["in_zdi"],
        exploited_in_wild=cve_id in itw,
    )


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("cves", nargs="*")
    ap.add_argument("--file", help="text file with one CVE id per line")
    ap.add_argument("-o", "--out", help="write ranked results to CSV")
    ap.add_argument("--cache", default="mitre_cache", help="folder for MITRE data")
    ap.add_argument("--itw-db", help="inthewild.db file (default: ./inthewild.db if present)")
    ap.add_argument("--itw-file", help="local file of exploited CVEs (JSON export or one id per line) "
                    "instead of downloading from inthewild.io")
    ap.add_argument("--nvd-key", help="NVD API key (much faster)")
    ap.add_argument("--all-adversary-kinds", action="store_true",
                    help="count software and campaigns as adversaries, not just groups")
    args = ap.parse_args(argv)

    ids = list(args.cves)
    if args.file:
        with open(args.file, encoding="utf-8") as f:
            ids += [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    if not ids:
        ap.error("give at least one CVE id")

    print("Loading CISA KEV...", file=sys.stderr)
    kev = load_kev()
    print("Loading inthewild.io list...", file=sys.stderr)
    try:
        db = args.itw_db or ("inthewild.db" if os.path.exists("inthewild.db") else None)
        if db:
            itw = load_inthewild_db(db)
            print(f"  {len(itw)} CVEs reported as exploited (from {db})", file=sys.stderr)
        elif args.itw_file:
            itw = load_inthewild_file(args.itw_file)
        else:
            itw = load_inthewild()
    except Exception as e:  # keep going, but say so clearly
        print(f"WARNING: inthewild.io failed ({e}); 'exploited in the wild' set to 0 for all.",
              file=sys.stderr)
        itw = set()
    print("Loading MITRE CAPEC and ATT&CK (first run downloads ~60 MB)...", file=sys.stderr)
    mapper = AdversaryMapper.from_cache(
        args.cache, ALL_KINDS if args.all_adversary_kinds else GROUPS_ONLY)

    vulns, inputs = [], {}
    for cid in ids:
        print(f"Fetching {cid}...", file=sys.stderr)
        try:
            v = build_vulnerability(cid, kev, itw, mapper, args.nvd_key)
        except Exception as e:
            print(f"  skipped {cid}: {e}", file=sys.stderr)
            continue
        vulns.append(v)
        inputs[v.cve_id] = v

    results = prioritize(vulns)
    print(f"\n{'Rank':<5}{'CVE':<18}{'Score':<8}{'CVSS':<6}")
    for n, r in enumerate(results, 1):
        base = inputs[r.cve_id].cvss_base
        print(f"{n:<5}{r.cve_id:<18}{r.score:<8.2f}{base if base is not None else '-':<6}")

    if args.out:
        with open(args.out, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["rank", "cve_id", "score", "raw", "cvss_base", "cvss_vector",
                        "n_cpe", "n_cwe", "n_adversaries", "epss", "epss_percentile",
                        "in_kev", "in_zdi", "exploited_in_wild",
                        *[f"term_{k}" for k in WEIGHTS]])
            for n, r in enumerate(results, 1):
                v = inputs[r.cve_id]
                w.writerow([n, r.cve_id, round(r.score, 4), round(r.raw, 5), v.cvss_base,
                            v.cvss_vector, v.n_cpe, v.n_cwe, v.n_adversaries, v.epss,
                            v.epss_percentile, int(v.in_kev), int(v.in_zdi),
                            int(v.exploited_in_wild),
                            *[round(r.terms[k], 5) for k in WEIGHTS]])
        print(f"\nWrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
