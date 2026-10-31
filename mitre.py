"""
Adversary count for a CVE (section II-A9 of the paper).

Chain: CVE -> CWE -> CAPEC attack pattern -> ATT&CK technique -> adversaries
that use that technique ("Procedure Examples" on the ATT&CK page).

Data comes from MITRE's public STIX files on GitHub:
  - CAPEC: mitre/cti  (capec/2.1/stix-capec.json)
  - ATT&CK: mitre-attack/attack-stix-data (enterprise-attack.json, ~55 MB)
Files are downloaded once into a cache folder.

Choice made here: "adversaries" means ATT&CK groups (intrusion sets). The
Procedure Examples table also lists software and campaigns; pass
kinds=("intrusion-set", "malware", "tool", "campaign") to count those too.
"""
from __future__ import annotations

import json
import os
from collections import defaultdict

import requests

CAPEC_URL = "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json"
ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)

GROUPS_ONLY = ("intrusion-set",)
ALL_KINDS = ("intrusion-set", "malware", "tool", "campaign")


def _download(url: str, path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with requests.get(url, stream=True, timeout=120) as r:
        r.raise_for_status()
        with open(path, "wb") as f:
            for chunk in r.iter_content(1 << 20):
                f.write(chunk)


def ensure_data(cache_dir: str = "mitre_cache") -> tuple[str, str]:
    """Download the two STIX files if they are not cached. Returns paths."""
    capec = os.path.join(cache_dir, "stix-capec.json")
    attack = os.path.join(cache_dir, "enterprise-attack.json")
    if not os.path.exists(capec):
        _download(CAPEC_URL, capec)
    if not os.path.exists(attack):
        _download(ATTACK_URL, attack)
    return capec, attack


def _ref_ids(obj: dict, source: str) -> list[str]:
    return [
        r["external_id"]
        for r in obj.get("external_references", [])
        if r.get("source_name") == source and "external_id" in r
    ]


def _inactive(obj: dict) -> bool:
    return bool(obj.get("revoked") or obj.get("x_mitre_deprecated"))


def _norm_technique(tid: str) -> str:
    tid = tid.strip().upper()
    return tid if tid.startswith("T") else "T" + tid


class AdversaryMapper:
    def __init__(self, capec_path: str, attack_path: str, kinds=GROUPS_ONLY):
        self.kinds = tuple(kinds)
        self.cwe_to_capec: dict[str, set[str]] = defaultdict(set)
        self.capec_to_tech: dict[str, set[str]] = defaultdict(set)
        self.tech_to_actors: dict[str, set[str]] = defaultdict(set)
        self._load_capec(capec_path)
        self._load_attack(attack_path)

    @classmethod
    def from_cache(cls, cache_dir: str = "mitre_cache", kinds=GROUPS_ONLY):
        capec, attack = ensure_data(cache_dir)
        return cls(capec, attack, kinds)

    def _load_capec(self, path: str) -> None:
        with open(path) as f:
            data = json.load(f)
        for o in data["objects"]:
            if o.get("type") != "attack-pattern" or _inactive(o):
                continue
            capec_ids = _ref_ids(o, "capec")
            if not capec_ids:
                continue
            capec = capec_ids[0]
            for cwe in _ref_ids(o, "cwe"):
                self.cwe_to_capec[cwe.upper()].add(capec)
            for t in _ref_ids(o, "ATTACK"):
                self.capec_to_tech[capec].add(_norm_technique(t))

    def _load_attack(self, path: str) -> None:
        with open(path) as f:
            data = json.load(f)
        objs = data["objects"]
        tech_id: dict[str, str] = {}
        actor_name: dict[str, str] = {}
        for o in objs:
            if _inactive(o):
                continue
            t = o.get("type")
            if t == "attack-pattern":
                ids = _ref_ids(o, "mitre-attack")
                if ids:
                    tech_id[o["id"]] = ids[0]
            elif t in self.kinds:
                actor_name[o["id"]] = f"{t}:{o.get('name', o['id'])}"
        for o in objs:
            if o.get("type") != "relationship" or o.get("relationship_type") != "uses":
                continue
            if _inactive(o):
                continue
            src, dst = o["source_ref"], o["target_ref"]
            if src in actor_name and dst in tech_id:
                self.tech_to_actors[tech_id[dst]].add(actor_name[src])

    # ---- lookups -----------------------------------------------------------
    def capecs_for_cwes(self, cwes) -> set[str]:
        out: set[str] = set()
        for c in cwes:
            out |= self.cwe_to_capec.get(c.upper(), set())
        return out

    def techniques_for_cwes(self, cwes) -> set[str]:
        out: set[str] = set()
        for capec in self.capecs_for_cwes(cwes):
            out |= self.capec_to_tech.get(capec, set())
        return out

    def adversaries_for_cwes(self, cwes) -> set[str]:
        out: set[str] = set()
        for t in self.techniques_for_cwes(cwes):
            out |= self.tech_to_actors.get(t, set())
        return out

    def count_for_cwes(self, cwes) -> int:
        return len(self.adversaries_for_cwes(cwes))
