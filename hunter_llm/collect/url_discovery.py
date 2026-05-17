"""Discover public write-up URLs from RSS/Atom feeds and static blog index pages."""

from __future__ import annotations

import re
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urljoin, urlparse

import httpx

_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; hunter-llm-pipeline/0.1; +research)", "Accept": "*/*"}


def _strip_ns(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def normalize_trackable_url(url: str, *, strip_query: bool = True) -> str:
    u = url.strip()
    if strip_query:
        u = urlparse(u)._replace(fragment="", query="").geturl().rstrip("/")
    return u


def urls_from_feed_xml(xml_text: str) -> list[str]:
    """Pull article links from RSS 2.0 or Atom feeds (Medium-compatible)."""
    try:
        root = ET.fromstring(xml_text.encode("utf-8") if isinstance(xml_text, str) else xml_text)
    except ET.ParseError:
        return _urls_from_feed_regex(xml_text)

    out: list[str] = []

    ns_atom = "{http://www.w3.org/2005/Atom}"
    rss_tag = _strip_ns(root.tag)
    if rss_tag == "rss":
        for item in root.iter():
            if _strip_ns(item.tag) != "item":
                continue
            chosen: str | None = None
            for child in item:
                ct = _strip_ns(child.tag)
                txt = (child.text or "").strip()
                if ct == "guid" and txt.startswith(("http://", "https://")):
                    chosen = txt
                    break
                if ct == "link" and txt.startswith(("http://", "https://")):
                    chosen = txt
                    break
                if ct == "link" and txt and not txt.startswith(("http://", "https://")):
                    href = child.attrib.get("href") if hasattr(child, "attrib") else None
                    if href and href.startswith(("http://", "https://")):
                        chosen = href
                        break
                if ct == "{http://rssnamespace.org/feed/extensions/v1}link":
                    continue
            if chosen:
                out.append(normalize_trackable_url(chosen))
        return _dedupe_ordered(out)

    if rss_tag == "feed":
        for entry in root.findall(f".//{ns_atom}entry"):
            link_candidates: list[str] = []
            for child in entry:
                ct = child.tag if child.tag.startswith(ns_atom) else _strip_ns(child.tag)
                if ct == f"{ns_atom}link":
                    href = child.attrib.get("href", "")
                    rel = child.attrib.get("rel", "alternate")
                    if href.startswith(("http://", "https://")) and rel in ("alternate", ""):
                        link_candidates.insert(0, href)
                    elif href.startswith(("http://", "https://")):
                        link_candidates.append(href)
                elif ct.replace(ns_atom, "link") == "link":
                    txt = (child.text or "").strip()
                    if txt.startswith(("http://", "https://")):
                        link_candidates.append(txt)
                elif _strip_ns(child.tag) == "id":
                    txt = (child.text or "").strip()
                    if txt.startswith(("http://", "https://")):
                        link_candidates.append(txt)
            if link_candidates:
                out.append(normalize_trackable_url(link_candidates[0]))
        return _dedupe_ordered(out)

    return _urls_from_feed_regex(xml_text)


_ITEM_RE = re.compile(r"<item[^>]*>(.*?)</item>", re.IGNORECASE | re.DOTALL)
_LINKTEXT_RE = re.compile(r"<link[^>]*>(https?://[^<]+)</link>", re.IGNORECASE)
_LINKHREF_RE = re.compile(r'<link[^>]+href=["\'](https?://[^"\']+)["\']', re.IGNORECASE)


def _urls_from_feed_regex(xml_text: str) -> list[str]:
    out: list[str] = []
    for m in _ITEM_RE.finditer(xml_text):
        block = m.group(1)
        hit = _LINKTEXT_RE.search(block)
        if hit:
            out.append(normalize_trackable_url(hit.group(1)))
        else:
            h2 = _LINKHREF_RE.search(block)
            if h2:
                out.append(normalize_trackable_url(h2.group(1)))
    return _dedupe_ordered(out)


def _dedupe_ordered(urls: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for u in urls:
        key = normalize_trackable_url(u)
        if key not in seen:
            seen.add(key)
            out.append(u)
    return out


def filter_urls_by_hostname(urls: list[str], allowed_suffixes: tuple[str, ...] | None) -> list[str]:
    """Keep URLs whose hostname is `suffix` or `*.suffix` (e.g. medium.com matches foo.medium.com)."""
    if not allowed_suffixes:
        return urls
    rules = tuple(s.strip().lower().lstrip(".") for s in allowed_suffixes if s.strip())

    def ok(hostname: str) -> bool:
        h = (hostname or "").lower()
        for r in rules:
            if h == r or h.endswith("." + r):
                return True
        return False

    return [u for u in urls if ok(urlparse(u).hostname or "")]


def discover_urls_from_feed_url(
    feed_url: str,
    *,
    client: httpx.Client | None = None,
    pause_sec: float = 0.35,
) -> list[str]:
    own = False
    if client is None:
        client = httpx.Client(headers=_HEADERS, follow_redirects=True, timeout=60.0)
        own = True
    try:
        r = client.get(feed_url)
        r.raise_for_status()
        if pause_sec > 0:
            time.sleep(pause_sec)
        return urls_from_feed_xml(r.text)
    finally:
        if own:
            client.close()


def discover_urls_from_feed_file(
    feeds_file: str | Path,
    *,
    pause_sec: float = 0.35,
    rss_host_suffixes: tuple[str, ...] | None = None,
) -> list[str]:
    p = Path(feeds_file)
    lines = [ln.strip() for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip() and not ln.startswith("#")]
    out: list[str] = []
    with httpx.Client(headers=_HEADERS, follow_redirects=True, timeout=60.0) as c:
        for feed in lines:
            out.extend(discover_urls_from_feed_url(feed, client=c, pause_sec=pause_sec))
    return filter_urls_by_hostname(_dedupe_ordered(out), rss_host_suffixes)


def harvest_html_post_urls(
    page_url: str,
    *,
    host_must_contain: str,
    url_regex: re.Pattern[str],
    client: httpx.Client | None = None,
    pause_sec: float = 0.25,
) -> list[str]:
    """Fetch one HTML page, collect absolute URLs matching regex (e.g. blog permalinks)."""
    parsed = urlparse(page_url)
    base_root = f"{parsed.scheme}://{parsed.netloc}/"
    host_must_contain = host_must_contain.lower()

    own = False
    if client is None:
        client = httpx.Client(headers=_HEADERS, follow_redirects=True, timeout=45.0)
        own = True
    try:
        r = client.get(page_url)
        r.raise_for_status()
        if pause_sec > 0:
            time.sleep(pause_sec)
        texts = set(re.findall(r'href=["\']([^"\']+)["\']', r.text, flags=re.I))
        out: list[str] = []
        for t in texts:
            u = urljoin(base_root, t.strip()).split("#", 1)[0]
            if host_must_contain not in urlparse(u).netloc.lower():
                continue
            if not url_regex.search(u):
                continue
            out.append(normalize_trackable_url(u))
        return _dedupe_ordered(out)
    finally:
        if own:
            client.close()


def discover_ysamm_post_urls() -> list[str]:
    """Harvest public write-up permalinks from https://ysamm.com/ homepage HTML."""
    return harvest_html_post_urls(
        "https://ysamm.com/",
        host_must_contain="ysamm.com",
        url_regex=re.compile(r"https?://ysamm\.com/.+\.html$"),
    )


def merge_url_files(paths: list[Path], *, out_path: Path) -> int:
    merged: list[str] = []
    op = Path(out_path)
    for p in paths:
        pp = Path(p)
        if not pp.is_file():
            continue
        for ln in pp.read_text(encoding="utf-8").splitlines():
            s = ln.strip()
            if not s or s.startswith("#"):
                continue
            if s.startswith(("http://", "https://")):
                merged.append(normalize_trackable_url(s))
    uniq = _dedupe_ordered(merged)
    op.parent.mkdir(parents=True, exist_ok=True)
    op.write_text("\n".join(uniq) + ("\n" if uniq else ""), encoding="utf-8")
    return len(uniq)


dedupe_urls = _dedupe_ordered
