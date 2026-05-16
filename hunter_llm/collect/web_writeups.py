"""Extract main text from security write-up URLs (blogs, disclosures with permission)."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

import httpx
import trafilatura


def fetch_url_text(url: str, timeout: float = 30.0) -> tuple[str, str | None]:
    """Return (extracted_text, title). Empty string on failure."""
    headers = {"User-Agent": "hunter-llm-pipeline/0.1 (research; contact operator)"}
    try:
        downloaded = trafilatura.fetch_url(url, headers=headers)
        if not downloaded:
            with httpx.Client(follow_redirects=True, headers=headers, timeout=timeout) as c:
                r = c.get(url)
                r.raise_for_status()
                downloaded = r.text
        meta = trafilatura.extract_metadata(downloaded)
        title = meta.title if meta else None
        text = trafilatura.extract(downloaded, include_comments=False, include_tables=False) or ""
        return text.strip(), title
    except Exception:
        return "", None


def ingest_url_list(urls_file: Path, out_path: Path) -> int:
    """
    urls_file: one URL per line. Only use content you have rights to use for training.
    """
    urls = [ln.strip() for ln in urls_file.read_text(encoding="utf-8").splitlines() if ln.strip()]
    out_path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with out_path.open("w", encoding="utf-8") as f:
        for url in urls:
            host = urlparse(url).netloc
            text, title = fetch_url_text(url)
            if len(text) < 200:
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
    return n
