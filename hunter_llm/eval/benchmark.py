"""Minimal CTF / vuln-style benchmark loader and optional ROUGE-L scoring."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


def load_benchmark(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return list(data.get("tasks") or data)


def rouge_l_f1(candidate: str, reference: str) -> float:
    """Token-level ROUGE-L F1 (longest common subsequence)."""
    c = candidate.lower().split()
    r = reference.lower().split()
    if not c or not r:
        return 0.0
    m, n = len(c), len(r)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m):
        for j in range(n):
            dp[i + 1][j + 1] = dp[i][j] + 1 if c[i] == r[j] else max(dp[i][j + 1], dp[i + 1][j])
    lcs = dp[m][n]
    prec = lcs / len(c)
    rec = lcs / len(r)
    if prec + rec == 0:
        return 0.0
    return 2 * prec * rec / (prec + rec)


_keyword_hints = [
    ("authorization", ["idor", "access control", "privilege"]),
    ("injection", ["sqli", "xss", "command injection", "template"]),
    ("ssrf", ["ssrf", "internal", "metadata"]),
]


def heuristic_score(answer: str, task: dict[str, Any]) -> float:
    """Cheap keyword overlap vs references + category hints."""
    ref = " ".join(task.get("references") or [])
    cat = (task.get("category") or "").lower()
    blob = (answer + " " + cat).lower()
    score = rouge_l_f1(answer, ref) if ref.strip() else 0.0
    hints = []
    for tag, words in _keyword_hints:
        if tag in cat:
            hints.extend(words)
    hits = sum(1 for w in hints if re.search(rf"\b{re.escape(w)}\b", blob))
    score += min(0.35, 0.07 * hits)
    return min(1.0, score)


def summarize_scores(rows: list[tuple[str, float]]) -> dict[str, float]:
    if not rows:
        return {"mean": 0.0, "count": 0}
    vals = [v for _, v in rows]
    return {"mean": sum(vals) / len(vals), "count": len(vals), "min": min(vals), "max": max(vals)}


def score_tasks_with_reference(tasks_path: Path, answers_jsonl: Path) -> dict[str, Any]:
    """answers_jsonl: lines {task_id, answer}"""
    tasks = {t["id"]: t for t in load_benchmark(tasks_path)}
    pairs: list[tuple[str, float]] = []
    with answers_jsonl.open(encoding="utf-8") as f:
        for line in f:
            row = json.loads(line)
            tid = row["task_id"]
            task = tasks.get(tid)
            if not task:
                continue
            ans = row.get("answer") or ""
            ref = " ".join(task.get("references") or [])
            pairs.append((tid, rouge_l_f1(ans, ref) if ref else heuristic_score(ans, task)))
    return {"per_task": pairs, **summarize_scores(pairs)}
