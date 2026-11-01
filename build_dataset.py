"""
Build the evaluation dataset (project plan, step 2).

Idea: stand on a past snapshot date T and ask which CVEs get exploited in the
next window (default 365 days). Everything fed to a model is what was known
on T; the label comes from what happened after T.

  population  CVEs published before T, with a CVSS v3 vector, that were NOT
              yet known to be exploited on T (not in KEV, no exploitation
              report before T). Otherwise the answer would be a feature.
  label = 1   added to CISA KEV, or reported as exploited in inthewild.db,
              between T and T + window.
  features    CVSS pieces, CPE/CWE/adversary counts, ZDI link, EPSS on day T,
              public exploits dated before T, age on T.

Quick trial (about 5 minutes, no API key needed):
    python build_dataset.py --start-date 2021-06-01
Full run (several hours without an NVD key, about 15 minutes with one):
    python build_dataset.py --nvd-key YOUR_KEY
"""
from __future__ import annotations

import argparse
import csv
import gzip
import json
import os
import sys
import time
from collections import Counter
from datetime import date, timedelta

import requests

from fetchers import NVD_URL, load_inthewild_timeline, load_kev_dates, parse_cve
from mitre import GROUPS_ONLY, AdversaryMapper
from vulnscore import Vulnerability, cvss_subscores, parse_vector, score_vulnerability

EPSS_HOSTS = ["https://epss.empiricalsecurity.com", "https://epss.cyentia.com"]

COLUMNS = [
    "cve_id", "published", "age_days", "cvss_vector", "cvss_base",
    "exploitability", "impact", "av", "ac", "pr", "ui", "s", "c", "i", "a",
    "n_cpe", "n_cwe", "n_adversaries", "in_zdi", "epss", "epss_percentile",
    "n_public_exploits", "paper_score", "label", "label_source", "exploited_date",
]


# ---- NVD bulk download ------------------------------------------------------
def windows(start: date, end: date, days: int = 120):
    """Split [start, end) into chunks of at most `days` (NVD's limit is 120)."""
    d = start
    while d < end:
        e = min(d + timedelta(days=days), end)
        yield d, e
        d = e


def _get_json(url, params, headers, retries=5):
    for attempt in range(1, retries + 1):
        try:
            r = requests.get(url, params=params, headers=headers, timeout=60)
            if r.status_code in (403, 429, 503):
                raise requests.HTTPError(f"HTTP {r.status_code}")
            r.raise_for_status()
            return r.json()
        except (requests.RequestException, ValueError):
            if attempt == retries:
                raise
            time.sleep(10 * attempt)


def fetch_window(s: date, e: date, api_key=None, delay=6.5) -> list[dict]:
    headers = {"apiKey": api_key} if api_key else {}
    params = {
        "pubStartDate": f"{s.isoformat()}T00:00:00.000",
        "pubEndDate": f"{(e - timedelta(days=1)).isoformat()}T23:59:59.999",
        "resultsPerPage": 2000,
    }
    out, idx = [], 0
    while True:
        payload = _get_json(NVD_URL, {**params, "startIndex": idx}, headers)
        items = payload.get("vulnerabilities", [])
        out += [parse_cve(i["cve"]) for i in items]
        idx += len(items)
        time.sleep(delay)
        if not items or idx >= payload.get("totalResults", 0):
            return out


def download_nvd(start, end, cache_dir, api_key=None, log=print) -> list[dict]:
    """Download in 120-day windows. Finished windows are cached, so a stopped
    run can be restarted and carries on where it left off."""
    os.makedirs(cache_dir, exist_ok=True)
    delay = 0.7 if api_key else 6.5
    records = []
    for s, e in windows(start, end):
        path = os.path.join(cache_dir, f"nvd_{s}_{e}.json")
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                records += json.load(f)
            continue
        log(f"  NVD {s} to {e} ...")
        recs = fetch_window(s, e, api_key, delay)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(recs, f)
        records += recs
    return records


# ---- EPSS on the snapshot day -----------------------------------------------
def parse_epss_csv(lines) -> dict[str, tuple[float, float]]:
    rows = (ln for ln in lines if not ln.startswith("#"))
    return {
        r["cve"].upper(): (float(r["epss"]), float(r["percentile"]))
        for r in csv.DictReader(rows)
    }


def load_epss_snapshot(day: str, cache_dir: str) -> dict[str, tuple[float, float]]:
    os.makedirs(cache_dir, exist_ok=True)
    path = os.path.join(cache_dir, f"epss_scores-{day}.csv.gz")
    if not os.path.exists(path):
        last = None
        for host in EPSS_HOSTS:
            try:
                r = requests.get(f"{host}/epss_scores-{day}.csv.gz", timeout=120)
                r.raise_for_status()
                with open(path, "wb") as f:
                    f.write(r.content)
                break
            except requests.RequestException as err:
                last = err
        else:
            raise RuntimeError(f"Could not download EPSS for {day}: {last}")
    with gzip.open(path, "rt", encoding="utf-8") as f:
        return parse_epss_csv(f)


# ---- rows -------------------------------------------------------------------
def build_rows(records, snapshot: date, window_days, kev_dates, itw_first,
               exploit_counts, epss, mapper):
    T = snapshot.isoformat()
    end = (snapshot + timedelta(days=window_days)).isoformat()
    rows, stats = [], Counter()
    for rec in records:
        stats["nvd_records"] += 1
        vec = rec.get("cvss_vector")
        if not vec or not vec.startswith("CVSS:3"):
            stats["dropped_no_cvss_v3"] += 1
            continue
        cid = rec["cve_id"].upper()
        published = (rec.get("published") or "")[:10]
        if not published or published >= T:
            stats["dropped_not_published_before_snapshot"] += 1
            continue
        kev_d, itw_d = kev_dates.get(cid), itw_first.get(cid)
        if any(d and d < T for d in (kev_d, itw_d)):
            stats["dropped_already_exploited_at_snapshot"] += 1
            continue
        try:
            m = parse_vector(vec)
            expl, imp = cvss_subscores(vec)
        except ValueError:
            stats["dropped_bad_vector"] += 1
            continue

        sources = [k for k, d in (("kev", kev_d), ("itw", itw_d)) if d and T <= d < end]
        label = 1 if sources else 0
        exploited_date = min(d for d in (kev_d, itw_d) if d and T <= d < end) if sources else ""

        e_score, e_pct = epss.get(cid, (0.0, 0.0))
        n_adv = mapper.count_for_cwes(rec["cwes"])
        paper = score_vulnerability(Vulnerability(
            cid, exploitability_subscore=expl, impact_subscore=imp,
            n_cpe=rec["n_cpe"], n_cwe=len(rec["cwes"]), n_adversaries=n_adv,
            epss=e_score, epss_percentile=e_pct, in_zdi=rec["in_zdi"],
        )).score
        rows.append({
            "cve_id": cid, "published": published,
            "age_days": (snapshot - date.fromisoformat(published)).days,
            "cvss_vector": vec, "cvss_base": rec.get("cvss_base"),
            "exploitability": expl, "impact": imp,
            "av": m["AV"], "ac": m["AC"], "pr": m["PR"], "ui": m["UI"], "s": m["S"],
            "c": m["C"], "i": m["I"], "a": m["A"],
            "n_cpe": rec["n_cpe"], "n_cwe": len(rec["cwes"]), "n_adversaries": n_adv,
            "in_zdi": int(rec["in_zdi"]), "epss": e_score, "epss_percentile": e_pct,
            "n_public_exploits": exploit_counts.get(cid, 0),
            "paper_score": round(paper, 5), "label": label,
            "label_source": "+".join(sources), "exploited_date": exploited_date,
        })
        stats["label_1" if label else "label_0"] += 1
    return rows, stats


def write_csv(rows, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--snapshot", default="2022-01-01", help="snapshot date T (needs EPSS data: 2021-04-14 or later)")
    ap.add_argument("--window-days", type=int, default=365)
    ap.add_argument("--start-date", default="2015-01-01", help="earliest CVE publish date")
    ap.add_argument("--nvd-key")
    ap.add_argument("--itw-db", default="inthewild.db")
    ap.add_argument("--cache", default="data_cache")
    ap.add_argument("--mitre-cache", default="mitre_cache")
    ap.add_argument("-o", "--out", default="dataset.csv")
    args = ap.parse_args(argv)

    snapshot = date.fromisoformat(args.snapshot)
    start = date.fromisoformat(args.start_date)
    if snapshot + timedelta(days=args.window_days) > date.today():
        ap.error("the label window ends in the future; use an earlier snapshot or a shorter window")

    print("Loading KEV dates...", file=sys.stderr)
    kev_dates = load_kev_dates()
    print("Loading inthewild.db timeline...", file=sys.stderr)
    itw_first, exploit_counts = load_inthewild_timeline(args.itw_db, snapshot.isoformat())
    print(f"Loading EPSS scores for {snapshot}...", file=sys.stderr)
    epss = load_epss_snapshot(snapshot.isoformat(), args.cache)
    print("Loading MITRE data...", file=sys.stderr)
    mapper = AdversaryMapper.from_cache(args.mitre_cache, GROUPS_ONLY)
    print("Downloading NVD (resumable)...", file=sys.stderr)
    records = download_nvd(start, snapshot, os.path.join(args.cache, "nvd"), args.nvd_key,
                           log=lambda m: print(m, file=sys.stderr))

    rows, stats = build_rows(records, snapshot, args.window_days, kev_dates,
                             itw_first, exploit_counts, epss, mapper)
    write_csv(rows, args.out)
    print(f"\nWrote {args.out}")
    for k, v in stats.items():
        print(f"  {k}: {v}")
    pos = stats["label_1"]
    if rows:
        print(f"  positive rate: {100 * pos / len(rows):.2f}%")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
