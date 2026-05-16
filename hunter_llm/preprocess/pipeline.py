"""End-to-end: quality filter + optional dedup → training JSONL."""

from __future__ import annotations

import json
from pathlib import Path

from hunter_llm.preprocess.dedup import dedup_rows_jsonl
from hunter_llm.preprocess.instructions import write_instruction_dataset
from hunter_llm.preprocess.quality import passes_quality


def build_curated_dataset(
    raw_paths: list[Path],
    out_jsonl: Path,
    *,
    min_quality: float = 0.8,
    dedup: bool = True,
    dedup_threshold: float = 0.88,
) -> dict[str, int]:
    settings_dir = out_jsonl.parent
    settings_dir.mkdir(parents=True, exist_ok=True)
    interim = settings_dir / "_interim_instructions.jsonl"
    total_written = write_instruction_dataset(raw_paths, interim)

    filtered_path = settings_dir / "_filtered.jsonl"
    kept = 0
    with interim.open(encoding="utf-8") as r, filtered_path.open("w", encoding="utf-8") as w:
        for line in r:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if passes_quality(row, min_quality):
                w.write(json.dumps(row, ensure_ascii=False) + "\n")
                kept += 1

    if dedup:
        dk, sk = dedup_rows_jsonl(filtered_path, out_jsonl, threshold=dedup_threshold)
        interim.unlink(missing_ok=True)
        filtered_path.unlink(missing_ok=True)
        return {
            "instructions_generated": total_written,
            "after_quality": kept,
            "after_dedup_kept": dk,
            "after_dedup_skipped": sk,
        }

    filtered_path.replace(out_jsonl)
    interim.unlink(missing_ok=True)
    return {"instructions_generated": total_written, "after_quality": kept, "after_dedup_kept": kept, "after_dedup_skipped": 0}
