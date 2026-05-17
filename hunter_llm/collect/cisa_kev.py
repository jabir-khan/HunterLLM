"""CISA Known Exploited Vulnerabilities catalog — official list of CVEs being exploited in the wild.

Source: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
License: U.S. Government work, public domain (https://www.cisa.gov/about/site-notices)

Each KEV entry has: cveID, vendorProject, product, vulnerabilityName, dateAdded,
shortDescription, requiredAction, dueDate, knownRansomwareCampaignUse, notes.
This is a HIGH-priority training signal: anything on this list is provably exploitable.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_kev_catalog(client: httpx.Client | None = None, timeout: float = 60.0) -> dict[str, Any]:
    own = client is None
    if own:
        client = httpx.Client(timeout=timeout, headers={"User-Agent": "hunter-llm-pipeline/0.1"})
    try:
        r = client.get(CISA_KEV_URL)
        r.raise_for_status()
        return r.json()
    finally:
        if own:
            client.close()


def kev_entry_to_raw_record(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "source": "cisa_kev",
        "cve_id": entry.get("cveID", ""),
        "vendor": entry.get("vendorProject", ""),
        "product": entry.get("product", ""),
        "name": entry.get("vulnerabilityName", ""),
        "description": entry.get("shortDescription", ""),
        "required_action": entry.get("requiredAction", ""),
        "date_added": entry.get("dateAdded", ""),
        "due_date": entry.get("dueDate", ""),
        "ransomware": entry.get("knownRansomwareCampaignUse", "Unknown"),
        "notes": entry.get("notes", ""),
        "cwes": entry.get("cwes", []),
    }


def ingest_cisa_kev(out_path: Path) -> int:
    """Fetch the latest KEV catalog and write one JSONL record per entry."""
    catalog = fetch_kev_catalog()
    entries = catalog.get("vulnerabilities") or []
    out_path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with out_path.open("w", encoding="utf-8") as f:
        for entry in entries:
            rec = kev_entry_to_raw_record(entry)
            if not rec["cve_id"] or not rec["description"].strip():
                continue
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            n += 1
    return n
