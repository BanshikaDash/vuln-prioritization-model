"""
Email alert system (project plan: the stage after the learned model).

For each CVE it works out a priority level and emails the security team:

  CRITICAL  in CISA KEV, or reported as exploited in the wild. Exploitation is
            confirmed, so each one gets its own immediate email.
  HIGH      learned score in the top 1% of CVEs
  MEDIUM    learned score in the top 5%
  LOW       everything else (no email by default)

The level is flagged in the email subject, e.g. "[CRITICAL] CVE-2024-1234 ...".
HIGH and MEDIUM CVEs go out together in one digest email. A CVE is only emailed
when it is new or its level goes up, so daily runs do not repeat themselves.
CVEs without a CVSS v3 score cannot be scored by the model and are skipped
unless they are already known to be exploited.

Safe by default: without --send nothing is emailed; the messages are written
to the outbox/ folder as .eml files.

    python alerts.py CVE-2023-25717 CVE-2014-3566
    python alerts.py --recent-days 7 --min-level MEDIUM --send

Email settings for --send (environment variables): SMTP_HOST, SMTP_PORT
(default 587), SMTP_USER, SMTP_PASSWORD, ALERT_TO (comma separated), and
optionally ALERT_FROM.
"""
from __future__ import annotations

import argparse
import csv
import html
import json
import os
import smtplib
import sys
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from email.message import EmailMessage
from email.utils import format_datetime
from typing import Optional

import numpy as np
import requests

import train_model as tm
from build_dataset import fetch_window
from fetchers import EPSS_URL, fetch_nvd, load_inthewild_timeline, load_kev
from mitre import GROUPS_ONLY, AdversaryMapper
from vulnscore import cvss_subscores, parse_vector

LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
TOP_FRACTION = {"high": 0.01, "medium": 0.05}   # share of CVEs in each tier


def rank(level: str) -> int:
    return LEVELS.index(level)


# ---- thresholds from the model's score distribution ---------------------------
def load_thresholds(models_dir: str) -> dict:
    """Score cut-offs for HIGH/MEDIUM plus a quantile table used to say
    'top x%'. Built once from models/test_predictions.csv, then cached."""
    path = os.path.join(models_dir, "thresholds.json")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    pred = os.path.join(models_dir, "test_predictions.csv")
    if not os.path.exists(pred):
        raise FileNotFoundError(f"{pred} not found; run: python train_model.py --save-dir {models_dir}")
    with open(pred, newline="", encoding="utf-8") as f:
        scores = np.array([float(r["ml_logit"]) for r in csv.DictReader(f)])
    thr = {
        "high": float(np.quantile(scores, 1 - TOP_FRACTION["high"])),
        "medium": float(np.quantile(scores, 1 - TOP_FRACTION["medium"])),
        "quantiles": [float(v) for v in np.quantile(scores, np.linspace(0, 1, 1001))],
        "source": "ml_logit scores on the test snapshot",
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(thr, f)
    return thr


def top_percent(score: float, quantiles) -> float:
    """'Top x%': share of reference CVEs that score at least this high."""
    below = float(np.interp(score, quantiles, np.linspace(0, 1, len(quantiles))))
    return max(0.01, 100 * (1 - below))


def classify(in_kev: bool, exploited: bool, score: Optional[float], thr: dict) -> Optional[str]:
    if in_kev or exploited:
        return "CRITICAL"
    if score is None:
        return None
    if score >= thr["high"]:
        return "HIGH"
    if score >= thr["medium"]:
        return "MEDIUM"
    return "LOW"


# ---- assessing one CVE --------------------------------------------------------
@dataclass
class Alert:
    cve_id: str
    level: str
    ml_score: Optional[float]
    top_pct: Optional[float]
    published: str
    cvss_base: Optional[float]
    epss: float
    epss_percentile: float
    in_kev: bool
    exploited_in_wild: bool
    n_public_exploits: int
    n_adversaries: int
    reasons: list = field(default_factory=list)


def explain(a: Alert) -> list[str]:
    r = []
    if a.in_kev:
        r.append("Listed in the CISA KEV catalog: exploitation is confirmed.")
    if a.exploited_in_wild:
        r.append("Reported as exploited in the wild (inthewild.io).")
    if a.top_pct is not None:
        r.append(f"Predicted exploitation risk is in the top {a.top_pct:.1f}% of CVEs.")
    r.append(f"EPSS {a.epss:.3f} ({a.epss_percentile * 100:.0f}th percentile).")
    if a.n_public_exploits:
        r.append(f"{a.n_public_exploits} exploit-tagged public reference(s).")
    if a.n_adversaries:
        r.append(f"Weakness type is linked to {a.n_adversaries} ATT&CK group(s).")
    if a.cvss_base is not None:
        r.append(f"CVSS base score {a.cvss_base}.")
    return r


def assess(rec: dict, epss: tuple, kev: set, itw_first: dict, exploit_counts: dict,
           mapper, model, thr: dict, today: date) -> Optional[Alert]:
    """Turn one NVD record into an Alert (None if it cannot be rated)."""
    cid = rec["cve_id"].upper()
    e_score, e_pct = epss
    in_kev, exploited = cid in kev, cid in itw_first
    n_pub = exploit_counts.get(cid, 0)
    n_adv = mapper.count_for_cwes(rec["cwes"])
    published = (rec.get("published") or "")[:10]

    score = top = None
    vec = rec.get("cvss_vector")
    if vec and vec.startswith("CVSS:3"):
        m = parse_vector(vec)
        expl, imp = cvss_subscores(vec)
        row = {
            "cvss_base": rec.get("cvss_base"), "exploitability": expl, "impact": imp,
            "n_cpe": rec["n_cpe"], "n_cwe": len(rec["cwes"]), "n_adversaries": n_adv,
            "in_zdi": int(rec["in_zdi"]), "epss": e_score, "epss_percentile": e_pct,
            "n_public_exploits": n_pub,
            "age_days": (today - date.fromisoformat(published)).days if published else 0,
            "av": m["AV"], "ac": m["AC"], "pr": m["PR"], "ui": m["UI"], "s": m["S"],
            "c": m["C"], "i": m["I"], "a": m["A"],
        }
        score = float(model.predict_proba(tm.row_to_vector(row).reshape(1, -1))[0, 1])
        top = top_percent(score, thr["quantiles"])

    level = classify(in_kev, exploited, score, thr)
    if level is None:
        return None
    a = Alert(cid, level, score, top, published, rec.get("cvss_base"), e_score, e_pct,
              in_kev, exploited, n_pub, n_adv)
    a.reasons = explain(a)
    return a


# ---- EPSS in batches ----------------------------------------------------------
def parse_epss_many(payload: dict) -> dict[str, tuple[float, float]]:
    return {d["cve"].upper(): (float(d["epss"]), float(d["percentile"]))
            for d in payload.get("data", [])}


def fetch_epss_many(ids: list[str], chunk: int = 50) -> dict[str, tuple[float, float]]:
    out: dict = {}
    for i in range(0, len(ids), chunk):
        r = requests.get(EPSS_URL, params={"cve": ",".join(ids[i:i + chunk])}, timeout=30)
        r.raise_for_status()
        out.update(parse_epss_many(r.json()))
    return out


# ---- state: do not repeat alerts ---------------------------------------------
def load_state(path: str) -> dict:
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_state(path: str, state: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=1, sort_keys=True)


def only_new(alerts: list[Alert], state: dict) -> list[Alert]:
    """Keep CVEs that are new, or whose level has gone up since last alerted."""
    return [a for a in alerts
            if a.cve_id not in state or rank(a.level) > rank(state[a.cve_id])]


def record_sent(alerts: list[Alert], state: dict) -> None:
    for a in alerts:
        state[a.cve_id] = a.level


# ---- composing emails ---------------------------------------------------------
def _nvd_link(cve_id: str) -> str:
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}"


def _fmt_risk(a: Alert) -> str:
    return f"top {a.top_pct:.1f}%" if a.top_pct is not None else "not scored"


def _new_message(subject, sender, recipients, text, html_body) -> EmailMessage:
    m = EmailMessage()
    m["Subject"], m["From"], m["To"] = subject, sender, ", ".join(recipients)
    m["Date"] = format_datetime(datetime.now().astimezone())
    m.set_content(text)
    m.add_alternative(html_body, subtype="html")
    return m


def single_email(a: Alert, sender, recipients) -> EmailMessage:
    subject = f"[{a.level}] {a.cve_id}: exploitation confirmed, act now"
    text = (f"Priority: {a.level}\nCVE: {a.cve_id}\nPublished: {a.published}\n"
            f"Predicted risk: {_fmt_risk(a)}\n\nWhy:\n"
            + "\n".join(f"  - {r}" for r in a.reasons) + f"\n\nDetails: {_nvd_link(a.cve_id)}\n")
    body = (f"<h2>[{a.level}] <a href='{_nvd_link(a.cve_id)}'>{a.cve_id}</a></h2>"
            f"<p>Published {html.escape(a.published)}. Predicted risk: {html.escape(_fmt_risk(a))}.</p><ul>"
            + "".join(f"<li>{html.escape(r)}</li>" for r in a.reasons) + "</ul>")
    return _new_message(subject, sender, recipients, text, body)


def digest_email(alerts: list[Alert], sender, recipients, today: date) -> EmailMessage:
    counts = {lv: sum(a.level == lv for a in alerts) for lv in reversed(LEVELS) if any(a.level == lv for a in alerts)}
    top_level = next(iter(counts))
    summary = ", ".join(f"{n} {lv.lower()}" for lv, n in counts.items())
    subject = f"[{top_level}] Vulnerability digest {today.isoformat()}: {summary}"

    text_parts, html_rows = [f"Vulnerability digest {today.isoformat()}: {summary}\n"], []
    for a in alerts:
        text_parts.append(f"[{a.level}] {a.cve_id}  risk {_fmt_risk(a)}  EPSS {a.epss:.3f}  "
                          f"CVSS {a.cvss_base}\n  {_nvd_link(a.cve_id)}\n"
                          + "\n".join(f"  - {r}" for r in a.reasons) + "\n")
        html_rows.append(
            f"<tr><td><b>{a.level}</b></td><td><a href='{_nvd_link(a.cve_id)}'>{a.cve_id}</a></td>"
            f"<td>{html.escape(_fmt_risk(a))}</td><td>{a.epss:.3f}</td><td>{a.cvss_base}</td>"
            f"<td>{html.escape('; '.join(a.reasons))}</td></tr>")
    body = ("<table border='1' cellpadding='4' cellspacing='0'><tr><th>Level</th><th>CVE</th>"
            "<th>Predicted risk</th><th>EPSS</th><th>CVSS</th><th>Why</th></tr>"
            + "".join(html_rows) + "</table>")
    return _new_message(subject, sender, recipients, "\n".join(text_parts), body)


def compose(alerts: list[Alert], min_level: str, sender, recipients, today: date) -> list[EmailMessage]:
    selected = sorted((a for a in alerts if rank(a.level) >= rank(min_level)),
                      key=lambda a: (-rank(a.level), -(a.ml_score or 0)))
    msgs = [single_email(a, sender, recipients) for a in selected if a.level == "CRITICAL"]
    rest = [a for a in selected if a.level != "CRITICAL"]
    if rest:
        msgs.append(digest_email(rest, sender, recipients, today))
    return msgs


# ---- delivery -----------------------------------------------------------------
def smtp_settings() -> dict:
    cfg = {k: os.environ.get(k, "") for k in ("SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASSWORD", "ALERT_TO", "ALERT_FROM")}
    missing = [k for k in ("SMTP_HOST", "SMTP_USER", "SMTP_PASSWORD", "ALERT_TO") if not cfg[k]]
    if missing:
        raise RuntimeError("Set these environment variables to send email: " + ", ".join(missing))
    cfg["SMTP_PORT"] = int(cfg["SMTP_PORT"] or 587)
    cfg["ALERT_FROM"] = cfg["ALERT_FROM"] or cfg["SMTP_USER"]
    cfg["recipients"] = [x.strip() for x in cfg["ALERT_TO"].split(",") if x.strip()]
    return cfg


def send_messages(msgs: list[EmailMessage], cfg: dict) -> None:
    if cfg["SMTP_PORT"] == 465:
        server = smtplib.SMTP_SSL(cfg["SMTP_HOST"], 465, timeout=30)
    else:
        server = smtplib.SMTP(cfg["SMTP_HOST"], cfg["SMTP_PORT"], timeout=30)
        server.starttls()
    with server:
        server.login(cfg["SMTP_USER"], cfg["SMTP_PASSWORD"])
        for m in msgs:
            server.send_message(m)


def write_outbox(msgs: list[EmailMessage], folder: str) -> list[str]:
    os.makedirs(folder, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    paths = []
    for n, m in enumerate(msgs, 1):
        p = os.path.join(folder, f"{stamp}_{n}.eml")
        with open(p, "wb") as f:
            f.write(bytes(m))
        paths.append(p)
    return paths


# ---- main ---------------------------------------------------------------------
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("cves", nargs="*")
    ap.add_argument("--file", help="text file, one CVE id per line")
    ap.add_argument("--recent-days", type=int, help="also check CVEs published in the last N days")
    ap.add_argument("--min-level", default="MEDIUM", choices=LEVELS)
    ap.add_argument("--send", action="store_true", help="really send email (default: write to outbox/)")
    ap.add_argument("--models-dir", default="models")
    ap.add_argument("--itw-db", default="inthewild.db")
    ap.add_argument("--mitre-cache", default="mitre_cache")
    ap.add_argument("--state", default="alert_state.json")
    ap.add_argument("--outbox", default="outbox")
    ap.add_argument("--nvd-key")
    args = ap.parse_args(argv)

    ids = [c.upper() for c in args.cves]
    if args.file:
        with open(args.file, encoding="utf-8") as f:
            ids += [ln.strip().upper() for ln in f if ln.strip() and not ln.startswith("#")]
    if not ids and not args.recent_days:
        ap.error("give CVE ids, --file, or --recent-days")

    cfg = smtp_settings() if args.send else None
    today = date.today()
    log = lambda m: print(m, file=sys.stderr)  # noqa: E731

    import joblib
    model = joblib.load(os.path.join(args.models_dir, "logit.joblib"))
    thr = load_thresholds(args.models_dir)
    log("Loading KEV, exploit data and MITRE mapping...")
    kev = load_kev()
    try:
        itw_first, exploit_counts = load_inthewild_timeline(args.itw_db, (today + timedelta(days=1)).isoformat())
    except FileNotFoundError:
        log(f"ERROR: {args.itw_db} not found. Download it first (see README); the model relies on it.")
        return 2
    mapper = AdversaryMapper.from_cache(args.mitre_cache, GROUPS_ONLY)

    records: dict[str, dict] = {}
    if args.recent_days:
        log(f"Fetching CVEs published in the last {args.recent_days} days...")
        delay = 0.7 if args.nvd_key else 6.5
        for r in fetch_window(today - timedelta(days=args.recent_days), today + timedelta(days=1), args.nvd_key, delay):
            records[r["cve_id"].upper()] = r
    for cid in ids:
        if cid in records:
            continue
        try:
            records[cid] = fetch_nvd(cid, args.nvd_key)
            records[cid]["cve_id"] = cid
        except Exception as e:
            log(f"  skipped {cid}: {e}")

    log("Fetching EPSS...")
    epss = fetch_epss_many(sorted(records))
    alerts, unscored = [], 0
    for cid, rec in records.items():
        a = assess(rec, epss.get(cid, (0.0, 0.0)), kev, itw_first, exploit_counts, mapper, model, thr, today)
        if a is None:
            unscored += 1
        else:
            alerts.append(a)

    alerts.sort(key=lambda a: (-rank(a.level), -(a.ml_score or 0)))
    print(f"{'Level':<10}{'CVE':<18}{'Predicted risk':<16}{'KEV':<5}{'EPSS':<7}")
    for a in alerts:
        print(f"{a.level:<10}{a.cve_id:<18}{_fmt_risk(a):<16}{'yes' if a.in_kev else '-':<5}{a.epss:<7.3f}")
    if unscored:
        print(f"\n{unscored} CVE(s) skipped: no CVSS v3 score yet and not known to be exploited.")

    state = load_state(args.state)
    candidates = [a for a in alerts if rank(a.level) >= rank(args.min_level)]
    to_send = only_new(candidates, state)
    print(f"\n{len(candidates)} CVE(s) at {args.min_level} or above, {len(to_send)} new or escalated.")
    if not to_send:
        return 0

    sender = cfg["ALERT_FROM"] if cfg else "alerts@example.com"
    recipients = cfg["recipients"] if cfg else ["security-team@example.com"]
    msgs = compose(to_send, args.min_level, sender, recipients, today)
    for m in msgs:
        print(f"  email: {m['Subject']}")
    if args.send:
        send_messages(msgs, cfg)
        record_sent(to_send, state)
        save_state(args.state, state)
        print(f"Sent {len(msgs)} email(s).")
    else:
        for p in write_outbox(msgs, args.outbox):
            print(f"  wrote {p}")
        print("Dry run: nothing sent. Add --send to email the team.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
