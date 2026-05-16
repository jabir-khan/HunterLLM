"""Build TRL-style DPO pairs (prompt, chosen, rejected) from curated SFT JSONL."""

from __future__ import annotations

import json
import re
from pathlib import Path


def _prompt_from_row(row: dict) -> str:
    instr = (row.get("instruction") or "").strip()
    inp = (row.get("input") or "").strip()
    return f"{instr}\n\n### Context\n{inp}".strip()


def _strip_impact_sections(text: str) -> str:
    """Remove exploitation / impact sections to synthesize a weaker `rejected` answer."""
    lines = text.splitlines()
    out: list[str] = []
    skip = False
    impact_headers = re.compile(
        r"^##\s*(impact|exploitation|proof of impact|attack(er)? narrative|severity|bounty narrative)",
        re.IGNORECASE,
    )
    for ln in lines:
        if impact_headers.match(ln.strip()):
            skip = True
            continue
        if ln.startswith("## ") and skip:
            skip = False
        if not skip:
            out.append(ln)
    return "\n".join(out).strip()


def synthetic_rejected(chosen: str) -> str:
    weakened = _strip_impact_sections(chosen)
    if len(weakened) < 120:
        weakened = (
            "## Notes\nPossible security issue—needs manual review.\n"
            "Verify in-scope before testing further.\n"
        )
    # Generic vague ending vs concrete chain
    if "Proof-of-impact" not in weakened and "## " in chosen:
        weakened += (
            "\n\n(No concrete exploitation chain or severity justification provided—too weak for bounty submission.)"
        )
    return weakened


def sft_jsonl_to_dpo_jsonl(in_path: Path, out_path: Path, *, limit: int | None = None) -> int:
    """
    Each input row: instruction, input, output[, tags, meta].
    Output JSONL: {"prompt": ..., "chosen": ..., "rejected": ...}
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with in_path.open(encoding="utf-8") as fin, out_path.open("w", encoding="utf-8") as fout:
        for line in fin:
            if limit is not None and n >= limit:
                break
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            chosen = (row.get("output") or "").strip()
            if len(chosen) < 160:
                continue
            prompt = _prompt_from_row(row)
            rejected = synthetic_rejected(chosen)
            if rejected.strip() == chosen.strip():
                continue
            fout.write(
                json.dumps(
                    {"prompt": prompt, "chosen": chosen, "rejected": rejected},
                    ensure_ascii=False,
                )
                + "\n"
            )
            n += 1
    return n
