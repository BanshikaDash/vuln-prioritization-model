"""
Data collection (step 1 of the paper's method).

Sources
  NVD         CVSS vector, CPE list, CWE list, reference links
  FIRST       EPSS score and percentile
  CISA        Known Exploited Vulnerabilities (KEV) list
  inthewild   "exploited in the wild" list

Tested offline against sample responses and the real KEV file. The live NVD,
FIRST and inthewild.io calls could not be run from my sandbox, so run them
once on your machine. The inthewild.io response shape is the least certain
part: see load_inthewild().
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import time
from typing import Optional

import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_MIRROR = (
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/"
    "known_exploited_vulnerabilities.json"
)
ITW_URL = "https://inthewild.io/api/exploited"

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)


# ---- NVD --------------------------------------------------------------------
def parse_nvd(payload: dict, cve_id: str) -> dict:
    """Pull what the model needs out of an NVD 2.0 API response."""
    items = payload.get("vulnerabilities", [])
    if not items:
        raise LookupError(f"{cve_id} not found in NVD")
    return parse_cve(items[0]["cve"])


def parse_cve(cve: dict) -> dict:
    """Pull what the model needs out of one NVD CVE record."""

    vector = base = None
    for key in ("cvssMetricV31", "cvssMetricV30"):
        metrics = cve.get("metrics", {}).get(key)
        if metrics:
            data = metrics[0]["cvssData"]
            vector, base = data["vectorString"], data.get("baseScore")
            break

    cpes = set()
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if m.get("vulnerable"):
                    cpes.add(m["criteria"])

    cwes = set()
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            val = d.get("value", "")
            if val.startswith("CWE-"):  # skip NVD-CWE-Other / NVD-CWE-noinfo
                cwes.add(val)

    # ZDI flag: NVD links to a Zero Day Initiative advisory
    in_zdi = any(
        "zerodayinitiative.com" in r.get("url", "").lower()
        for r in cve.get("references", [])
    )
    return {
        "cve_id": cve.get("id"),
        "published": cve.get("published"),
        "cvss_vector": vector,
        "cvss_base": base,
        "n_cpe": len(cpes),
        "cwes": sorted(cwes),
        "in_zdi": in_zdi,
    }


def fetch_nvd(cve_id: str, api_key: Optional[str] = None) -> dict:
    headers = {"apiKey": api_key} if api_key else {}
    r = requests.get(NVD_URL, params={"cveId": cve_id}, headers=headers, timeout=30)
    r.raise_for_status()
    out = parse_nvd(r.json(), cve_id)
    time.sleep(0.7 if api_key else 6)  # NVD rate limits
    return out


# ---- EPSS -------------------------------------------------------------------
def parse_epss(payload: dict) -> tuple[float, float]:
    data = payload.get("data", [])
    if not data:
        return 0.0, 0.0
    return float(data[0]["epss"]), float(data[0]["percentile"])


def fetch_epss(cve_id: str) -> tuple[float, float]:
    """Return (epss score, percentile), both 0-1."""
    r = requests.get(EPSS_URL, params={"cve": cve_id}, timeout=30)
    r.raise_for_status()
    return parse_epss(r.json())


# ---- CISA KEV ---------------------------------------------------------------
def parse_kev(payload: dict) -> set[str]:
    return {v["cveID"].upper() for v in payload["vulnerabilities"]}


def load_kev() -> set[str]:
    """CISA KEV ids. Falls back to CISA's GitHub mirror if cisa.gov blocks us."""
    for url in (KEV_URL, KEV_MIRROR):
        try:
            r = requests.get(url, timeout=60, headers={"User-Agent": "vulnscore/1.0"})
            r.raise_for_status()
            return parse_kev(r.json())
        except (requests.RequestException, ValueError):
            continue
    raise RuntimeError("Could not download the CISA KEV list")


# ---- inthewild.io -----------------------------------------------------------
_ID_KEYS = ("id", "cve", "cve_id", "cveId", "vulnerability_id")


def extract_cve_ids(payload) -> set[str]:
    """Collect CVE ids from the inthewild.io export.

    I could not see the live response, so this accepts the likely shapes: a
    list of ids, a list of objects, or an object holding such a list. It only
    reads the id field of each entry, never free text, because descriptions
    mention other CVEs.
    """
    if isinstance(payload, dict):
        entries = []
        for v in payload.values():
            if isinstance(v, list):
                entries.extend(v)
    else:
        entries = list(payload)

    out = set()
    for e in entries:
        if isinstance(e, str) and CVE_RE.match(e):
            out.add(e.upper())
        elif isinstance(e, dict):
            for k in _ID_KEYS:
                if isinstance(e.get(k), str) and CVE_RE.match(e[k]):
                    out.add(e[k].upper())
                    break
    return out


def load_inthewild() -> set[str]:
    r = requests.get(ITW_URL, timeout=20, headers={"User-Agent": "vulnscore/1.0"})
    r.raise_for_status()
    ids = extract_cve_ids(r.json())
    if not ids:
        raise RuntimeError("inthewild.io returned no CVE ids; response format may have changed")
    return ids


def load_inthewild_file(path: str) -> set[str]:
    """Same list from a local file: a JSON export, or one CVE id per line."""
    with open(path, encoding="utf-8") as f:
        text = f.read()
    try:
        ids = extract_cve_ids(json.loads(text))
    except ValueError:
        ids = {ln.strip().upper() for ln in text.splitlines() if CVE_RE.match(ln.strip())}
    if not ids:
        raise RuntimeError(f"no CVE ids found in {path}")
    return ids


def load_inthewild_db(path: str) -> set[str]:
    """CVEs with a report of exploitation in the wild, from inthewild.db.

    The database has an `exploits` table (id = CVE, type = kind of report).
    Rows of type 'exploit' are public exploit code, which is not the same as
    being exploited, so only 'exploitation' rows are counted.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    con = sqlite3.connect(path)
    try:
        wild = _wild_types(con, path)
        marks = ",".join("?" * len(wild))
        rows = con.execute(f"select distinct id from exploits where type in ({marks})", wild)
        return {r[0].upper() for r in rows if r[0] and CVE_RE.match(r[0])}
    finally:
        con.close()


def _wild_types(con, path: str) -> list[str]:
    types = [r[0] for r in con.execute("select distinct type from exploits")]
    wild = [t for t in types if t and ("exploitation" in t.lower() or "wild" in t.lower())]
    if not wild:
        raise RuntimeError(f"no 'exploitation' type in {path}; types found: {types}")
    return wild


def parse_kev_dates(payload: dict) -> dict[str, str]:
    """CVE id -> date it was added to KEV (YYYY-MM-DD)."""
    return {v["cveID"].upper(): v["dateAdded"] for v in payload["vulnerabilities"]}


def load_kev_dates() -> dict[str, str]:
    for url in (KEV_URL, KEV_MIRROR):
        try:
            r = requests.get(url, timeout=60, headers={"User-Agent": "vulnscore/1.0"})
            r.raise_for_status()
            return parse_kev_dates(r.json())
        except (requests.RequestException, ValueError):
            continue
    raise RuntimeError("Could not download the CISA KEV list")


def load_inthewild_timeline(path: str, before: str) -> tuple[dict[str, str], dict[str, int]]:
    """From inthewild.db, return two things:
      first_exploitation: CVE id -> date (YYYY-MM-DD) of its earliest exploitation report
      exploit_counts:     CVE id -> number of public-exploit rows dated before `before`
    """
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    con = sqlite3.connect(path)
    try:
        wild = _wild_types(con, path)
        marks = ",".join("?" * len(wild))
        first = {
            r[0].upper(): r[1][:10]
            for r in con.execute(
                f"select id, min(timeStamp) from exploits where type in ({marks}) "
                "and timeStamp is not null group by id", wild)
            if r[0] and r[1] and CVE_RE.match(r[0])
        }
        counts = {
            r[0].upper(): r[1]
            for r in con.execute(
                "select id, count(*) from exploits where type = 'exploit' "
                "and timeStamp < ? group by id", (before,))
            if r[0] and CVE_RE.match(r[0])
        }
        return first, counts
    finally:
        con.close()
