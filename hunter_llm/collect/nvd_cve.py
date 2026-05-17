"""Fetch CVE metadata and descriptions from NVD API 2.0 (official, license-friendly summaries)."""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx

from hunter_llm.config import settings

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _headers() -> dict[str, str]:
    h = {"User-Agent": "hunter-llm-pipeline/0.1"}
    if settings.nvd_api_key:
        h["apiKey"] = settings.nvd_api_key
    return h


def fetch_cves_for_date_range(
    start: datetime,
    end: datetime,
    client: httpx.Client,
    pause_sec: float = 0.6,
) -> list[dict[str, Any]]:
    """Paginate NVD for publicDate in [start, end). Returns raw API 'vulnerabilities' items."""
    params: dict[str, Any] = {
        "pubStartDate": start.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 2000,
    }
    items: list[dict[str, Any]] = []
    start_index = 0
    while True:
        params["startIndex"] = start_index
        r = client.get(NVD_BASE, params=params, headers=_headers(), timeout=120.0)
        r.raise_for_status()
        data = r.json()
        vulns = data.get("vulnerabilities") or []
        items.extend(vulns)
        total = data.get("totalResults", 0)
        start_index += len(vulns)
        if start_index >= total or not vulns:
            break
        time.sleep(pause_sec)
    return items


def vulnerability_to_raw_record(item: dict[str, Any]) -> dict[str, Any]:
    cve = item.get("cve", {})
    cid = cve.get("id", "")
    desc = ""
    for d in cve.get("descriptions") or []:
        if d.get("lang") == "en":
            desc = d.get("value") or ""
            break
    metrics = cve.get("metrics", {})
    return {
        "source": "nvd",
        "cve_id": cid,
        "description": desc,
        "published": cve.get("published"),
        "metrics": metrics,
        "raw": item,
    }


def ingest_nvd_window(
    days: int,
    out_path: Path,
    end: datetime | None = None,
) -> int:
    """Pull CVEs published in the last `days` days and write JSONL of raw_record summaries."""
    end = end or datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    settings.raw_dir.mkdir(parents=True, exist_ok=True)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with httpx.Client() as client:
        vulns = fetch_cves_for_date_range(start, end, client)
    n = 0
    with out_path.open("w", encoding="utf-8") as f:
        for v in vulns:
            rec = vulnerability_to_raw_record(v)
            if not rec["description"].strip():
                continue
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            n += 1
    return n


def _month_windows(start: datetime, end: datetime) -> list[tuple[datetime, datetime]]:
    """Yield ~monthly (~30 day) [a, b) windows from start to end. NVD enforces a 120-day cap."""
    windows: list[tuple[datetime, datetime]] = []
    cur = start
    step = timedelta(days=30)
    while cur < end:
        nxt = min(cur + step, end)
        windows.append((cur, nxt))
        cur = nxt
    return windows


def ingest_nvd_long_window(
    years: float,
    out_path: Path,
    end: datetime | None = None,
    sleep_between_chunks: float = 1.0,
    progress: bool = True,
) -> int:
    """Fetch the last `years` years of CVEs, paginated into ~30-day chunks (NVD caps at 120d).

    Writes a single JSONL stream to `out_path`. Resilient to transient errors per chunk.
    """
    end = end or datetime.now(timezone.utc)
    start = end - timedelta(days=int(years * 365))
    windows = _month_windows(start, end)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with httpx.Client() as client, out_path.open("w", encoding="utf-8") as f:
        for i, (a, b) in enumerate(windows, 1):
            if progress:
                print(f"  [nvd] {i}/{len(windows)}  {a.date()} -> {b.date()}", flush=True)
            try:
                vulns = fetch_cves_for_date_range(a, b, client)
            except (httpx.HTTPError, httpx.HTTPStatusError) as e:
                print(f"  [nvd] chunk failed ({e}); continuing")
                vulns = []
            for v in vulns:
                rec = vulnerability_to_raw_record(v)
                if not rec["description"].strip():
                    continue
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                n += 1
            time.sleep(sleep_between_chunks)
    return n
