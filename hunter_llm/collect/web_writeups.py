"""Extract main text from security write-up URLs using trafilatura.

Compatible with trafilatura >=1.9 (no `headers=` kwarg on `fetch_url`). Falls back
to httpx when trafilatura's fetch can't reach a host.
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

import httpx
import trafilatura

_DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (compatible; hunter-llm-pipeline/0.1; +research)"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


def fetch_url_text(url: str, timeout: float = 30.0) -> tuple[str, str | None]:
    """Return (extracted_text, title). Empty string on failure (no swallow-and-hide)."""
    downloaded: str | None = None
    try:
        downloaded = trafilatura.fetch_url(url)
    except Exception:
        downloaded = None

    if not downloaded:
        try:
            with httpx.Client(
                follow_redirects=True,
                headers=_DEFAULT_HEADERS,
                timeout=timeout,
            ) as c:
                r = c.get(url)
                if r.status_code >= 400:
                    return "", None
                downloaded = r.text
        except Exception:
            return "", None

    if not downloaded:
        return "", None

    title: str | None = None
    try:
        meta = trafilatura.extract_metadata(downloaded)
        title = getattr(meta, "title", None) if meta else None
    except Exception:
        title = None

    try:
        text = trafilatura.extract(downloaded, include_comments=False, include_tables=False) or ""
    except Exception:
        text = ""

    return text.strip(), title


def ingest_url_list(urls_file: Path, out_path: Path, *, progress: bool = True) -> int:
    """urls_file: one URL per line. `#` starts a comment, blank lines skipped."""
    urls: list[str] = []
    for ln in urls_file.read_text(encoding="utf-8").splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        urls.append(s)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    skipped: list[tuple[str, str]] = []
    with out_path.open("w", encoding="utf-8") as f:
        for i, url in enumerate(urls, 1):
            host = urlparse(url).netloc
            text, title = fetch_url_text(url)
            if progress:
                print(f"  [{i}/{len(urls)}] {host:35.35} -> {len(text):>6} chars", flush=True)
            if len(text) < 200:
                skipped.append((url, "too-short"))
                continue
            rec = {
                "source": "url",
                "url": url,
                "host": host,
                "title": title,
                "text": text,
            }
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            n += 1
    if progress and skipped:
        print(f"  [skipped {len(skipped)}/{len(urls)} URLs (too-short or fetch failed)]")
    return n
