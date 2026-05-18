"""Ingest the user's own bug bounty reports (`data/personal/reports/*.md`).

Each report is one Markdown file with YAML front-matter and a small set of
expected H2 sections (Summary / Reconnaissance / Steps / Exploit / Impact /
…). We parse them into raw JSONL records that look like::

    {
      "source": "personal_report",
      "title": "...",
      "asset": "...",
      "program": "...",
      "severity": "...",
      "bug_class": "...",
      "bounty_usd": "...",
      "date": "...",
      "references": [...],
      "sections": {"summary": "...", "steps": "...", ...},
      "text": "<full markdown body>",
      "path": "data/personal/reports/foo.md"
    }

The v3 dataset builder consumes this source and emits task-shaped pairs:
"write the report", "walk through methodology", "given fragment X what's
the next probe?", etc. The report body is the gold output.

We deliberately do NOT try to be clever with parsing — we trust the
template the user follows. Anything that can't be parsed cleanly is still
emitted with `text` set to the raw body so v3 has a fallback.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

_FRONT_MATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)
_H2_RE = re.compile(r"^##\s+(.+?)\s*$", re.MULTILINE)

_SECTION_ALIASES = {
    "summary": ("summary",),
    "recon": ("reconnaissance / discovery", "reconnaissance", "discovery", "recon"),
    "steps": ("steps to reproduce", "reproduction", "steps", "repro"),
    "exploit": ("exploit / poc", "exploit", "poc", "proof of concept", "proof-of-concept"),
    "impact": ("impact",),
    "negative": ("what i tried that didn't work", "negative results", "dead ends"),
    "remediation": ("suggested remediation", "remediation", "fix"),
    "outcome": ("outcome", "result", "triage outcome"),
}


def _try_yaml_load(block: str) -> dict[str, Any]:
    try:
        import yaml  # type: ignore

        data = yaml.safe_load(block) or {}
        return data if isinstance(data, dict) else {}
    except Exception:
        # Minimal fallback: parse `key: value` lines, lists not supported.
        out: dict[str, Any] = {}
        for line in block.splitlines():
            if ":" not in line or line.lstrip().startswith("#"):
                continue
            k, _, v = line.partition(":")
            out[k.strip()] = v.strip().strip("\"'") or ""
        return out


def _split_sections(body: str) -> dict[str, str]:
    """Return canonical_name -> section body for every H2 we recognize."""
    matches = list(_H2_RE.finditer(body))
    if not matches:
        return {}
    sections: dict[str, str] = {}
    for i, m in enumerate(matches):
        heading = m.group(1).strip().lower()
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(body)
        chunk = body[start:end].strip()
        for canonical, aliases in _SECTION_ALIASES.items():
            if any(heading == a or heading.startswith(a) for a in aliases):
                sections[canonical] = chunk
                break
    return sections


_SECRET_PATTERNS = [
    (re.compile(r"\bhf_[A-Za-z0-9]{20,}\b"), "HF token"),
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "OpenAI-style key"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key id"),
    (re.compile(r"\bxox[abp]-[A-Za-z0-9-]{10,}\b"), "Slack token"),
    (re.compile(r"\bghp_[A-Za-z0-9]{30,}\b"), "GitHub PAT"),
    (re.compile(r"eyJ[A-Za-z0-9_=/+\-]{20,}\.[A-Za-z0-9_=/+\-]{20,}\.[A-Za-z0-9_=/+\-]{20,}"), "JWT-shaped string"),
]


def scan_for_secrets(text: str) -> list[str]:
    hits: list[str] = []
    for rx, label in _SECRET_PATTERNS:
        if rx.search(text):
            hits.append(label)
    return hits


def parse_report(path: Path) -> dict[str, Any] | None:
    raw = path.read_text(encoding="utf-8")
    front: dict[str, Any] = {}
    body = raw
    m = _FRONT_MATTER_RE.match(raw)
    if m:
        front = _try_yaml_load(m.group(1))
        body = raw[m.end() :]
    title = (front.get("title") or "").strip()
    if not title:
        first_h1 = re.search(r"^#\s+(.+)$", body, re.MULTILINE)
        if first_h1:
            title = first_h1.group(1).strip()
    if not title:
        title = path.stem.replace("_", " ").title()
    sections = _split_sections(body)
    record: dict[str, Any] = {
        "source": "personal_report",
        "title": title,
        "asset": (front.get("asset") or "").strip(),
        "program": (front.get("program") or "").strip(),
        "severity": (front.get("severity") or "").strip(),
        "bug_class": (front.get("bug_class") or "").strip(),
        "bounty_usd": str(front.get("bounty_usd") or "").strip(),
        "date": str(front.get("date") or "").strip(),
        "references": front.get("references") or [],
        "sections": sections,
        "text": body.strip(),
        "path": str(path),
    }
    return record


def ingest_personal_reports(reports_dir: Path, out_jsonl: Path) -> dict[str, Any]:
    out_jsonl.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    skipped: list[str] = []
    secret_warnings: list[tuple[str, list[str]]] = []
    with out_jsonl.open("w", encoding="utf-8") as w:
        for path in sorted(reports_dir.glob("*.md")):
            if path.name.startswith("_"):
                continue
            try:
                rec = parse_report(path)
            except Exception as e:
                skipped.append(f"{path.name}: {type(e).__name__}: {e}")
                continue
            if not rec or len((rec.get("text") or "").strip()) < 200:
                skipped.append(f"{path.name}: body shorter than 200 chars")
                continue
            hits = scan_for_secrets(rec["text"])
            if hits:
                secret_warnings.append((path.name, hits))
            w.write(json.dumps(rec, ensure_ascii=False) + "\n")
            n += 1
    return {
        "written": n,
        "skipped": skipped,
        "secret_warnings": secret_warnings,
        "out": str(out_jsonl),
    }
