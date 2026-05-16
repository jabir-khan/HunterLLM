"""Near-duplicate detection with MinHash LSH (datasketch)."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from datasketch import MinHash, MinHashLSH


def _tokens(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]{3,}", text.lower())


def minhash_from_text(text: str, num_perm: int = 128) -> MinHash:
    mh = MinHash(num_perm=num_perm)
    for t in _tokens(text):
        mh.update(t.encode("utf-8"))
    return mh


def dedup_rows_jsonl(
    in_path: Path,
    out_path: Path,
    *,
    num_perm: int = 128,
    threshold: float = 0.85,
    key_fn: Any | None = None,
) -> tuple[int, int]:
    """
    Streaming-ish dedup: build LSH on composite instruction+input+output text.
    Returns (kept_count, skipped_count).
    """
    key_fn = key_fn or (lambda r: f"{r.get('instruction','')}\n{r.get('input','')}\n{r.get('output','')}")

    lsh = MinHashLSH(threshold=threshold, num_perm=num_perm)

    kept = 0
    skipped = 0

    def uid(row: dict[str, Any]) -> str:
        raw = key_fn(row).encode("utf-8", errors="ignore")
        return hashlib.sha256(raw).hexdigest()[:24]

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with in_path.open(encoding="utf-8") as f, out_path.open("w", encoding="utf-8") as w:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            text_key = key_fn(row)
            mh = minhash_from_text(text_key, num_perm=num_perm)
            dup_neighbors = lsh.query(mh)
            if dup_neighbors:
                skipped += 1
                continue
            i = uid(row)
            lsh.insert(i, mh)
            w.write(json.dumps(row, ensure_ascii=False) + "\n")
            kept += 1

    return kept, skipped


def dedup_iterable(rows: Iterable[dict[str, Any]], threshold: float = 0.9) -> list[dict[str, Any]]:
    lsh = MinHashLSH(threshold=threshold, num_perm=128)
    out: list[dict[str, Any]] = []
    for row in rows:
        key = f"{row.get('instruction','')}\n{row.get('input','')}\n{row.get('output','')}"
        mh = minhash_from_text(key)
        if lsh.query(mh):
            continue
        rid = hashlib.md5(key.encode()).hexdigest()
        lsh.insert(rid, mh)
        out.append(row)
    return out
