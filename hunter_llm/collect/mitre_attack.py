"""MITRE ATT&CK — adversary tactics, techniques, and procedures (TTPs).

Source: https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
License: Apache-2.0 (https://github.com/mitre/cti/blob/master/LICENSE.txt)

The Enterprise STIX bundle contains hundreds of `attack-pattern` objects, each
describing a real-world adversary technique with kill-chain phase, platforms,
detection guidance, and references. This is dense attacker-mindset training data.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx

MITRE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)


def fetch_attack_bundle(timeout: float = 120.0) -> dict[str, Any]:
    headers = {"User-Agent": "hunter-llm-pipeline/0.1"}
    with httpx.Client(timeout=timeout, headers=headers, follow_redirects=True) as c:
        r = c.get(MITRE_ATTACK_URL)
        r.raise_for_status()
        return r.json()


def _technique_id(obj: dict[str, Any]) -> str:
    for ref in obj.get("external_references") or []:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "")
    return ""


def _technique_url(obj: dict[str, Any]) -> str:
    for ref in obj.get("external_references") or []:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url", "")
    return ""


def technique_to_raw_record(obj: dict[str, Any]) -> dict[str, Any] | None:
    if obj.get("type") != "attack-pattern":
        return None
    if obj.get("revoked") or obj.get("x_mitre_deprecated"):
        return None
    tid = _technique_id(obj)
    if not tid:
        return None
    phases = [p.get("phase_name") for p in (obj.get("kill_chain_phases") or [])]
    return {
        "source": "mitre_attack",
        "technique_id": tid,
        "name": obj.get("name", ""),
        "description": obj.get("description", ""),
        "platforms": obj.get("x_mitre_platforms") or [],
        "data_sources": obj.get("x_mitre_data_sources") or [],
        "detection": obj.get("x_mitre_detection", ""),
        "kill_chain_phases": phases,
        "url": _technique_url(obj),
        "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
    }


def ingest_mitre_attack(out_path: Path) -> int:
    bundle = fetch_attack_bundle()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with out_path.open("w", encoding="utf-8") as f:
        for obj in bundle.get("objects") or []:
            rec = technique_to_raw_record(obj)
            if not rec or not rec["description"].strip():
                continue
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            n += 1
    return n
