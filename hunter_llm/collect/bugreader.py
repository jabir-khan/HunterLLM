"""Bugreader.com — discover report IDs, resolve real authors, ingest as personal-style JSONL.

Public reports use ``https://bugreader.com/<any_user>@x-<id>`` (username in URL is a
placeholder). The *real* author is the profile link in the report header.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from hunter_llm.collect.web_writeups import fetch_url_text
from hunter_llm.preprocess.taxonomy import infer_tags

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (compatible; HunterLLM/1.0; +https://github.com/jabir-khan/HunterLLM)"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

_AUTHOR_LINK_RE = re.compile(
    r'href="(?:https://bugreader\.com/)?([a-zA-Z0-9_]{3,30})"[^>]*>\s*([^<]{2,60})'
)
_SKIP_USERNAMES = frozenset(
    {"reports", "researchers", "social", "secure", "a", "mo", "data", "i", "www"}
)
_REPORT_ID_RE = re.compile(r"@x-(\d+)$|@(\d+)$")


def report_id_from_url(url: str) -> int | None:
    path = urlparse(url.strip()).path.strip("/")
    m = _REPORT_ID_RE.search(path.replace("@x-", "@"))
    if not m:
        m = re.search(r"@x-(\d+)$", path)
    if m:
        return int(m.group(1) or m.group(2))
    return None


def canonical_report_url(report_id: int, slug: str = "jabir0x0") -> str:
    return f"https://bugreader.com/{slug}@x-{report_id}"


def extract_author_username(html: str) -> str | None:
    for m in _AUTHOR_LINK_RE.finditer(html):
        user = m.group(1).strip()
        if user in _SKIP_USERNAMES:
            continue
        return user
    return None


def discover_valid_report_ids(
    *,
    start_id: int = 1,
    end_id: int = 305,
    url_slug: str = "jabir0x0",
    pause_sec: float = 0.15,
    workers: int = 8,
) -> list[int]:
    """Return numeric IDs that return HTTP 200 report pages (not 404 shell)."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    found: list[int] = []

    def probe(rid: int) -> int | None:
        url = canonical_report_url(rid, url_slug)
        try:
            with httpx.Client(
                follow_redirects=True, headers=_HEADERS, timeout=httpx.Timeout(20.0)
            ) as client:
                r = client.get(url)
            if r.status_code != 200:
                return None
            if "404 Not Found" in r.text:
                return None
            if re.search(r"<title>\s*404", r.text, re.I):
                return None
            return rid
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(probe, i): i for i in range(start_id, end_id + 1)}
        for fut in as_completed(futs):
            rid = fut.result()
            if rid is not None:
                found.append(rid)
    return sorted(found)


def map_report_authors(
    report_ids: list[int],
    *,
    url_slug: str = "jabir0x0",
    pause_sec: float = 0.2,
) -> dict[int, str]:
    """report_id -> bugreader username of the real author."""
    out: dict[int, str] = {}
    with httpx.Client(
        follow_redirects=True, headers=_HEADERS, timeout=httpx.Timeout(25.0)
    ) as client:
        for rid in report_ids:
            url = canonical_report_url(rid, url_slug)
            try:
                r = client.get(url)
                author = extract_author_username(r.text) if r.status_code == 200 else None
                if author:
                    out[rid] = author
            except Exception:
                pass
            time.sleep(pause_sec)
    return out


def load_usernames_file(path: Path) -> list[str]:
    names: list[str] = []
    for ln in path.read_text(encoding="utf-8").splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        names.append(s.split()[0].lstrip("@"))
    return names


def report_to_personal_record(
    *,
    report_id: int,
    author: str,
    url_slug: str = "jabir0x0",
    min_chars: int = 200,
) -> dict[str, Any] | None:
    url = canonical_report_url(report_id, url_slug)
    text, title = fetch_url_text(url, timeout=18.0)
    if len(text) < min_chars:
        return None
    title = (title or "").replace(" | Bugreader", "").strip() or f"Bugreader report {report_id}"
    program = "Facebook" if "facebook" in title.lower() or "facebook" in text.lower()[:500] else ""
    tags = infer_tags(title + " " + text[:2000]) or []
    return {
        "source": "personal_report",
        "title": title,
        "asset": program or "Web application",
        "program": program,
        "severity": "",
        "bug_class": tags[0] if tags else "",
        "bounty_usd": "",
        "date": "",
        "references": [url],
        "sections": {},
        "text": text,
        "path": f"bugreader:{author}@x-{report_id}",
        "meta": {
            "bugreader": True,
            "author": author,
            "report_id": report_id,
            "url": url,
        },
    }


def load_report_ids_from_url_file(path: Path) -> list[int]:
    ids: list[int] = []
    for ln in path.read_text(encoding="utf-8").splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        rid = report_id_from_url(s.split()[0])
        if rid is not None:
            ids.append(rid)
    return sorted(set(ids))


def ingest_bugreader_circle(
    *,
    authors: list[str],
    out_path: Path,
    start_id: int = 1,
    end_id: int = 305,
    url_slug: str = "jabir0x0",
    discover: bool = True,
    report_ids: list[int] | None = None,
    ids_file: Path | None = None,
    pause_sec: float = 0.2,
    min_chars: int = 200,
    append_local_md: Path | None = None,
) -> dict[str, Any]:
    """Ingest Bugreader reports whose *real* author is in ``authors``."""
    from hunter_llm.collect.personal_reports import ingest_personal_reports

    author_set = {a.lower() for a in authors}
    if report_ids is not None:
        ids = report_ids
    elif ids_file and ids_file.is_file():
        ids = load_report_ids_from_url_file(ids_file)
    elif discover:
        ids = discover_valid_report_ids(start_id=start_id, end_id=end_id, url_slug=url_slug)
    else:
        ids = []
    id_to_author = map_report_authors(ids, url_slug=url_slug, pause_sec=pause_sec)
    matched = {rid: user for rid, user in id_to_author.items() if user.lower() in author_set}

    out_path.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    skipped_short = 0
    skipped_author = len(id_to_author) - len(matched)

    with out_path.open("w", encoding="utf-8") as w:
        if append_local_md and append_local_md.is_dir():
            local_stats = ingest_personal_reports(append_local_md, out_path.with_suffix(".local_tmp.jsonl"))
            tmp = out_path.with_suffix(".local_tmp.jsonl")
            if tmp.is_file():
                for line in tmp.read_text(encoding="utf-8").splitlines():
                    if line.strip():
                        w.write(line + "\n")
                        written += 1
                tmp.unlink(missing_ok=True)

        for rid in sorted(matched):
            rec = report_to_personal_record(
                report_id=rid,
                author=matched[rid],
                url_slug=url_slug,
                min_chars=min_chars,
            )
            if not rec:
                skipped_short += 1
                continue
            w.write(json.dumps(rec, ensure_ascii=False) + "\n")
            written += 1
            time.sleep(pause_sec)

    by_author: dict[str, int] = {}
    for rid, user in matched.items():
        by_author[user] = by_author.get(user, 0) + 1

    return {
        "ids_scanned": len(ids),
        "authors_requested": list(authors),
        "matched_reports": len(matched),
        "written": written,
        "skipped_short": skipped_short,
        "skipped_other_author": skipped_author,
        "by_author": by_author,
        "out": str(out_path),
    }


def write_url_list_for_authors(
    report_ids: list[int],
    id_to_author: dict[int, str],
    authors: list[str],
    out_path: Path,
    url_slug: str = "jabir0x0",
) -> int:
    author_set = {a.lower() for a in authors}
    lines: list[str] = [
        "# Bugreader URLs for circle authors (auto-generated)",
        f"# Authors: {', '.join(authors)}",
        "",
    ]
    n = 0
    for rid in sorted(report_ids):
        user = id_to_author.get(rid)
        if not user or user.lower() not in author_set:
            continue
        lines.append(canonical_report_url(rid, url_slug))
        n += 1
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return n
