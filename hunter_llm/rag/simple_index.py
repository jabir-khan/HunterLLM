"""Lightweight embedding index over JSONL chunks (sentence-transformers + numpy).

Install RAG extras: pip install sentence-transformers numpy
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np


def _require_st():
    try:
        from sentence_transformers import SentenceTransformer  # noqa: PLC0415
    except ImportError as e:
        raise ImportError(
            "RAG requires sentence-transformers. Install with: pip install sentence-transformers numpy"
        ) from e
    return SentenceTransformer


def chunk_jsonl_records(
    jsonl_path: Path,
    *,
    text_keys: tuple[str, ...] = ("instruction", "input", "output"),
    max_chars: int = 1200,
    stride: int = 900,
) -> list[dict[str, Any]]:
    chunks: list[dict[str, Any]] = []
    with jsonl_path.open(encoding="utf-8") as f:
        for line_no, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            blob = "\n".join(str(row.get(k) or "") for k in text_keys).strip()
            if len(blob) <= max_chars:
                chunks.append({"line": line_no, "offset": 0, "text": blob, "meta": {"tags": row.get("tags")}})
                continue
            for off in range(0, len(blob), stride):
                piece = blob[off : off + max_chars]
                if len(piece) < 80:
                    continue
                chunks.append({"line": line_no, "offset": off, "text": piece, "meta": {}})
    return chunks


def build_index(
    jsonl_path: Path,
    out_dir: Path,
    *,
    model_name: str = "sentence-transformers/all-MiniLM-L6-v2",
) -> int:
    SentenceTransformer = _require_st()
    out_dir.mkdir(parents=True, exist_ok=True)
    chunks = chunk_jsonl_records(jsonl_path)
    texts = [c["text"] for c in chunks]
    model = SentenceTransformer(model_name)
    emb = model.encode(texts, batch_size=32, normalize_embeddings=True, show_progress_bar=True)
    np.save(out_dir / "embeddings.npy", emb.astype(np.float32))
    (out_dir / "chunks.jsonl").write_text(
        "\n".join(json.dumps(c, ensure_ascii=False) for c in chunks),
        encoding="utf-8",
    )
    (out_dir / "model_name.txt").write_text(model_name, encoding="utf-8")
    return len(chunks)


def query_index(out_dir: Path, query: str, *, top_k: int = 5) -> list[tuple[float, dict[str, Any]]]:
    SentenceTransformer = _require_st()
    emb_path = out_dir / "embeddings.npy"
    chunks_path = out_dir / "chunks.jsonl"
    model_name = (out_dir / "model_name.txt").read_text(encoding="utf-8").strip()
    matrix = np.load(emb_path)
    chunks = [json.loads(ln) for ln in chunks_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    model = SentenceTransformer(model_name)
    q = model.encode([query], normalize_embeddings=True)[0].astype(np.float32)
    scores = matrix @ q
    idx = np.argsort(-scores)[:top_k]
    return [(float(scores[i]), chunks[i]) for i in idx]
