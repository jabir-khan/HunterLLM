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
    # Browser-like UA: some hosts (Cloudflare, HackerOne) return 403 to obvious bot UAs.
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


def _fetch_raw(url: str, timeout: float = 12.0) -> tuple[int | None, str]:
    """Return (HTTP status, response body). Status is None only on transport failure."""
    try:
        with httpx.Client(
            follow_redirects=True,
            headers=_DEFAULT_HEADERS,
            timeout=httpx.Timeout(timeout, connect=min(timeout, 6.0)),
        ) as c:
            r = c.get(url)
            return r.status_code, r.text or ""
    except Exception:
        return None, ""


def fetch_url_text(url: str, timeout: float = 12.0) -> tuple[str, str | None]:
    """Return (extracted_text, title). Empty string on failure (no swallow-and-hide).

    Uses httpx directly (with a strict timeout) and only delegates the HTML
    parsing to trafilatura. trafilatura.fetch_url has been observed to hang
    well past its advertised timeout on some hosts, so we skip it.
    """
    status, downloaded = _fetch_raw(url, timeout=timeout)
    if status is None or status >= 400 or not downloaded:
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


def _skip_hint(status: int | None, html: str, extracted_len: int) -> str:
    low = (html or "").lower()
    parts: list[str] = []
    if status is None:
        parts.append("transport-error")
    elif status == 403:
        parts.append("http-403")
    elif status == 429:
        parts.append("http-429-rate-limit")
    if "just a moment" in low or "cf-browser-verification" in low or "cloudflare" in low[:2000]:
        parts.append("likely-cloudflare-challenge")
    if "challenge-platform" in low:
        parts.append("cf-challenge-js")
    if "sign in" in low or "hackers/sign_in" in low:
        parts.append("likely-login-wall")
    if len(html or "") > 8000 and extracted_len < 200:
        parts.append("spa-shell-big-html-small-extract")
    return "|".join(parts) if parts else "unknown"


def ingest_url_list(
    urls_file: Path,
    out_path: Path,
    *,
    progress: bool = True,
    append: bool = False,
    verbose_skips: int = 0,
) -> int:
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
    mode = "a" if append and out_path.exists() else "w"
    diag_printed = 0
    with out_path.open(mode, encoding="utf-8") as f:
        for i, url in enumerate(urls, 1):
            host = urlparse(url).netloc
            status, downloaded = _fetch_raw(url)
            title: str | None = None
            text = ""
            if status is not None and status < 400 and downloaded:
                try:
                    meta = trafilatura.extract_metadata(downloaded)
                    title = getattr(meta, "title", None) if meta else None
                except Exception:
                    title = None
                try:
                    text = (
                        trafilatura.extract(downloaded, include_comments=False, include_tables=False)
                        or ""
                    ).strip()
                except Exception:
                    text = ""
            if progress:
                print(f"  [{i}/{len(urls)}] {host:35.35} -> {len(text):>6} chars", flush=True)
            if len(text) < 200:
                skipped.append((url, "too-short"))
                if verbose_skips > diag_printed:
                    hint = _skip_hint(status, downloaded, len(text))
                    ts = downloaded if downloaded else "(empty body)"
                    print(
                        f"    [skip-diag #{diag_printed + 1}] status={status} "
                        f"raw_html={len(downloaded)} extract={len(text)} hint={hint}\n"
                        f"       url={url}\n"
                        f"       body_sample={repr(ts[:200])}",
                        flush=True,
                    )
                    diag_printed += 1
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
        print(f"  [skipped {len(skipped)}/{len(urls)} URLs (too-short or fetch failed)]", flush=True)
        if n == 0 and len(skipped) == len(urls) and any("hackerone.com" in u for u in urls):
            print(
                "  [hint] All HackerOne URLs failed: see data/urls/HACKERONE.md — "
                "plain HTTP + trafilatura cannot read disclosed report bodies (Cloudflare / SPA).",
                flush=True,
            )
    return n
