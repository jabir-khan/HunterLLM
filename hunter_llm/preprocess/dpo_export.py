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


def iter_curated_pairs(curated_path: Path) -> "list[dict]":
    """Load hand-authored {prompt, chosen, rejected} pairs (meta ignored for TRL).

    These teach judgment the synthetic weakening cannot: rejecting false
    positives, lectures, unverified claims, fabrication, and under-escalation.
    """
    rows: list[dict] = []
    if not curated_path or not curated_path.is_file():
        return rows
    with curated_path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            prompt = (r.get("prompt") or "").strip()
            chosen = (r.get("chosen") or "").strip()
            rejected = (r.get("rejected") or "").strip()
            if not prompt or not chosen or not rejected or chosen == rejected:
                continue
            rows.append({"prompt": prompt, "chosen": chosen, "rejected": rejected})
    return rows


def sft_jsonl_to_dpo_jsonl(
    in_path: Path,
    out_path: Path,
    *,
    limit: int | None = None,
    curated_path: Path | None = None,
) -> int:
    """
    Each SFT input row: instruction, input, output[, tags, meta].
    Output JSONL: {"prompt": ..., "chosen": ..., "rejected": ...}

    Curated hand-authored pairs (``curated_path``) are written first so the
    highest-signal judgment examples are always present regardless of ``limit``.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with out_path.open("w", encoding="utf-8") as fout:
        for pair in iter_curated_pairs(curated_path) if curated_path else []:
            fout.write(json.dumps(pair, ensure_ascii=False) + "\n")
            n += 1
        with in_path.open(encoding="utf-8") as fin:
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
