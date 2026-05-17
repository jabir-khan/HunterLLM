"""Heuristic quality filters for instruction rows."""

from __future__ import annotations

import re
from typing import Any


_NOISY_PATH_SUFFIXES = (
    "mkdocs.yml",
    "mkdocs.yaml",
    ".gitignore",
    ".gitattributes",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pyproject.toml",
    "setup.cfg",
    "setup.py",
    "Gemfile",
    "Gemfile.lock",
    "requirements.txt",
    "Makefile",
    "Dockerfile",
    "tox.ini",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "SECURITY.md",
    "ISSUE_TEMPLATE.md",
    "PULL_REQUEST_TEMPLATE.md",
    "LICENSE",
    "LICENSE.md",
)

_NOISY_PATH_FRAGMENTS = (
    "/.github/",
    "/_includes/",
    "/_layouts/",
    "/_sass/",
    "/site/",
    "/docs/_static/",
    "/overrides/",
)


def _is_noisy_github_path(path: str) -> bool:
    p = (path or "").lower()
    if any(p.endswith(suf.lower()) for suf in _NOISY_PATH_SUFFIXES):
        return True
    if any(frag in p for frag in _NOISY_PATH_FRAGMENTS):
        return True
    return False


def _input_looks_like_config(inp: str) -> bool:
    """Crude detector: many lines of `key: value` or markdown without prose."""
    if not inp:
        return False
    lines = [ln for ln in inp.splitlines() if ln.strip()]
    if len(lines) < 8:
        return False
    yaml_like = sum(1 for ln in lines if re.match(r"^\s*[A-Za-z0-9_.-]+\s*:\s*\S", ln))
    if yaml_like > len(lines) * 0.5:
        return True
    return False


def score_row(row: dict[str, Any]) -> float:
    """Higher is better; used to drop low-signal samples."""
    score = 0.0
    out = row.get("output") or ""
    inp = row.get("input") or ""
    ins = row.get("instruction") or ""
    meta = row.get("meta") or {}

    if meta.get("source") == "github":
        path = meta.get("path") or ""
        if _is_noisy_github_path(path):
            score -= 3.0
        if _input_looks_like_config(inp):
            score -= 1.5

    score += min(len(out) / 800.0, 2.0)
    score += min(len(inp) / 1200.0, 1.5)
    if len(ins) < 40:
        score -= 0.5
    if len(inp) < 80:
        score -= 1.0
    if len(out) < 120:
        score -= 1.5
    tags = row.get("tags") or []
    score += min(len(tags) * 0.15, 0.6)
    return score


def passes_quality(row: dict[str, Any], min_score: float = 0.8) -> bool:
    return score_row(row) >= min_score
