"""Ingest **publicly disclosed** HackerOne reports via::

    GET https://hackerone.com/reports/<id>.json

The HTML shell used by ``collect-urls`` + ``trafilatura`` is effectively empty for
reports rendered in React. The ``.json`` endpoint returns structured fields::

  - vulnerability_information — reporter Markdown body
  - summaries[]               — optional team/researcher narrative blurbs

Be polite with ``--pause`` (default ~0.5s between requests). Use only sources and
rights described in https://www.hackerone.com/terms.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from urllib.parse import urlparse

import httpx

_REPORT_ID_RE = re.compile(r"hackerone\.com/reports/(\d+)", re.I)

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    ),
    "Accept": "application/json,text/html;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


def report_id_from_url(url: str) -> str | None:
    m = _REPORT_ID_RE.search(url.strip())
    return m.group(1) if m else None


def compose_report_text(data: dict) -> str:
    """Merge title, VI, summaries into one training-friendly document."""
    lines: list[str] = []

    title = (data.get("title") or "").strip()
    if title:
        lines.append(f"# {title}")

    team = (data.get("team") or {}) if isinstance(data.get("team"), dict) else {}
    pname = team.get("name")
    if pname:
        lines.append(f"Program: {pname}")

    bounty = data.get("bounty_amount")
    if bounty not in (None, "", [], {}):
        lines.append(f"Disclosed bounty: {bounty}")

    vi = (data.get("vulnerability_information") or "").strip()
    if vi:
        if lines:
            lines.append("")
        lines.append("## Vulnerability information")
        lines.append("")
        lines.append(vi)

    for s in data.get("summaries") or []:
        if not isinstance(s, dict):
            continue
        cat = (s.get("category") or "summary").strip()
        content = (s.get("content") or "").strip()
        if not content:
            continue
        lines.append("")
        lines.append(f"## Disclosure summary ({cat})")
        lines.append("")
        lines.append(content)

    return "\n".join(lines).strip()


def fetch_report_json(report_id: str, client: httpx.Client) -> tuple[dict | None, int]:
    url = f"https://hackerone.com/reports/{report_id}.json"
    r = client.get(url)
    if r.status_code != 200:
        return None, r.status_code
    try:
        return r.json(), r.status_code
    except json.JSONDecodeError:
        return None, r.status_code


def existing_report_ids(out_path: Path) -> set[str]:
    """Report IDs already present in a urls_writeups-style JSONL."""
    ids: set[str] = set()
    if not out_path.is_file():
        return ids
    with out_path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            meta = row.get("meta") or {}
            rid = meta.get("report_id")
            if rid:
                ids.add(str(rid))
                continue
            url = row.get("url") or ""
            parsed = report_id_from_url(url)
            if parsed:
                ids.add(parsed)
    return ids


def ingest_hackerone_url_list(
    urls_file: Path,
    out_path: Path,
    *,
    pause_sec: float = 0.55,
    min_chars: int = 200,
    append: bool = False,
    progress: bool = True,
    limit: int | None = None,
    skip_ids: set[str] | None = None,
) -> dict[str, int]:
    urls: list[str] = []
    for ln in urls_file.read_text(encoding="utf-8").splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        urls.append(s.split()[0])

    if limit is not None:
        urls = urls[: max(0, limit)]

    stats = {
        "urls_total": len(urls),
        "written": 0,
        "skipped_bad_url": 0,
        "skipped_existing": 0,
        "skipped_http": 0,
        "skipped_short": 0,
        "skipped_not_public": 0,
    }
    skip_ids = skip_ids or set()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if append and out_path.exists() else "w"

    with httpx.Client(
        follow_redirects=True,
        headers=_HEADERS,
        timeout=httpx.Timeout(30.0, connect=15.0),
    ) as client, out_path.open(mode, encoding="utf-8") as w:
        for i, url in enumerate(urls, 1):
            rid = report_id_from_url(url)
            if not rid:
                stats["skipped_bad_url"] += 1
                continue
            if rid in skip_ids:
                stats["skipped_existing"] += 1
                if progress:
                    print(f"  [{i}/{len(urls)}] id={rid} already ingested -> skip", flush=True)
                continue

            body_json, http = fetch_report_json(rid, client)
            time.sleep(max(0.0, pause_sec))

            if http != 200 or body_json is None:
                stats["skipped_http"] += 1
                if progress:
                    print(f"  [{i}/{len(urls)}] id={rid} http={http} -> skip", flush=True)
                continue

            pub = body_json.get("public")
            # Some responses omit `public`; treat explicit False as withheld.
            if pub is False:
                stats["skipped_not_public"] += 1
                if progress:
                    print(f"  [{i}/{len(urls)}] id={rid} not_public -> skip", flush=True)
                continue

            text = compose_report_text(body_json)
            if len(text) < min_chars:
                stats["skipped_short"] += 1
                if progress:
                    print(f"  [{i}/{len(urls)}] id={rid} text={len(text)} -> too short", flush=True)
                continue

            canon = body_json.get("url") or f"https://hackerone.com/reports/{rid}"
            host = urlparse(str(canon)).netloc or "hackerone.com"
            row = {
                "source": "url",
                "url": canon,
                "host": host,
                "title": body_json.get("title"),
                "text": text,
                "meta": {"hackerone_json": True, "report_id": rid},
            }
            w.write(json.dumps(row, ensure_ascii=False) + "\n")
            stats["written"] += 1
            if progress:
                print(f"  [{i}/{len(urls)}] id={rid} -> {len(text)} chars ✓", flush=True)

    return stats
