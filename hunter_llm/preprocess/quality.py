"""Heuristic quality filters for instruction rows."""

from __future__ import annotations

from typing import Any


def score_row(row: dict[str, Any]) -> float:
    """Higher is better; used to drop low-signal samples."""
    score = 0.0
    out = row.get("output") or ""
    inp = row.get("input") or ""
    ins = row.get("instruction") or ""
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
