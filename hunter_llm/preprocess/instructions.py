"""Convert raw JSONL records into instruction-style rows for SFT (red-team / impact bias, in-scope only)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterator

from hunter_llm.preprocess.taxonomy import infer_tags
from hunter_llm.prompts import AUTHORIZATION_NOTE


def _chunk_text(text: str, max_chars: int = 6000, overlap: int = 400) -> list[str]:
    text = text.strip()
    if len(text) <= max_chars:
        return [text]
    chunks: list[str] = []
    start = 0
    while start < len(text):
        chunks.append(text[start : start + max_chars])
        start += max_chars - overlap
    return chunks


def _cve_output(record: dict[str, Any]) -> str:
    desc = record.get("description") or ""
    raw = record.get("raw") or {}
    cve = raw.get("cve") if isinstance(raw, dict) else {}
    cwes: list[str] = []
    for w in (cve.get("weaknesses") or [])[:5]:
        for d in w.get("description") or []:
            if d.get("lang") == "en":
                cwes.append(d.get("value") or "")
    lines = [
        "## Summary",
        desc.strip(),
        "",
        "## Attacker primitives",
        "- Map the fault to concrete attacker-controlled inputs and trust boundaries.",
        "- List preconditions (auth level, networking, config) an adversary needs.",
        "",
        "## Exploitation narrative (lab / in-scope only)",
        "- Sketch a minimal chain from entry to impact (read, write, code execution, lateral movement) grounded in the CVE text.",
        "- Call out stable signals a triager can verify (crashes, parse errors, unexpected responses, sandbox escapes if applicable).",
        "",
        "## Proof-of-impact angles for bounty-style reports",
        "- What data or capability is gained per user role?",
        "- What would elevate severity: scope expansion, persistence, mass exploitability?",
        "",
        "## Weakness taxonomy",
    ]
    if cwes:
        lines.extend(f"- {c}" for c in cwes if c)
    else:
        lines.append("- Map CWE from vendor advisory / NVD enrichment when available.")
    lines.extend(
        [
            "",
            "## What to patch / verify (still red-team minded)",
            "- Fixed versions and config toggles from the vendor advisory.",
            "- Fuzz/regress the same input class; add guardrails only after root-cause fix.",
        ]
    )
    return "\n".join(lines)


def iter_github_instructions(record: dict[str, Any]) -> Iterator[dict[str, Any]]:
    text = record.get("text") or ""
    repo = record.get("repo", "")
    path = record.get("path", "")
    tags = infer_tags(text + " " + path)
    for i, chunk in enumerate(_chunk_text(text)):
        instr = (
            "You are mentoring an authorized bug bounty hunter. For this reference material, explain how an attacker "
            "would operationalize it during in-scope testing: entry points, prerequisite conditions, "
            "likely impact classes, and how to document a convincing proof-of-impact. "
            f"{AUTHORIZATION_NOTE}"
        )
        yield {
            "instruction": instr,
            "input": f"Repository file: {repo}/{path} (chunk {i + 1})\n\n---\n{chunk}",
            "output": _payload_redteam(chunk, tags),
            "tags": tags,
            "meta": {"source": "github", "repo": repo, "path": path},
        }


def _payload_redteam(chunk: str, tags: list[str]) -> str:
    header = "## Red-team reading of the snippet\n"
    body: list[str] = []
    if tags:
        body.append("Hypothesized bug classes from context: " + ", ".join(tags) + ".")
    lowered = chunk.lower()
    if "select " in lowered and ("union" in lowered or "where" in lowered):
        body.append(
            "SQLi-style patterns: identify parameter surface, DB error channels, UNION/BLIND pivoting, "
            "and exfil proofs that demonstrate data sensitivity without destructive writes unless explicitly allowed."
        )
    if "<script" in lowered or "javascript:" in lowered or "onerror=" in lowered:
        body.append(
            "XSS-style patterns: execution context (reflected/stored/DOM), high-value sinks (admin panels, exports), "
            "and escalation ideas (cookie theft vs internal actions) tailored to impact narrative."
        )
    if "${jndi:" in lowered or "ldap://" in lowered:
        body.append(
            "Lookup gadget patterns: outbound constraints, gadget chains, and how you'd prove RCE or secret access in a lab."
        )
    if not body:
        body.append(
            "Extract TTP-relevant notes: what to fuzz next, trust boundaries crossed, and how this helps build a bounty-grade impact story."
        )
    body.append(
        "\n## How to phrase this in a report\n"
        "- Repro steps, scoped curl/PoC skeleton, blast radius, and why the program should care."
    )
    return header + "\n\n".join(body) + "\n\n## Reference excerpt\n```\n" + chunk[:2000] + "\n```\n"


def iter_nvd_instructions(record: dict[str, Any]) -> Iterator[dict[str, Any]]:
    desc = record.get("description") or ""
    cid = record.get("cve_id") or ""
    tags = infer_tags(desc + " " + cid)
    instr = (
        "Break this CVE down for offensive triage: root cause, realistic attacker path, maximal defensible impact, "
        "and what a strong proof looks like in a pentest/bounty setting. Stay faithful to the text. "
        f"{AUTHORIZATION_NOTE}"
    )
    yield {
        "instruction": instr,
        "input": f"{cid}\n\n{desc}".strip(),
        "output": _cve_output(record),
        "tags": tags,
        "meta": {"source": "nvd", "cve_id": cid},
    }


def iter_url_instructions(record: dict[str, Any]) -> Iterator[dict[str, Any]]:
    text = record.get("text") or ""
    url = record.get("url", "")
    title = record.get("title") or ""
    tags = infer_tags(text)
    for i, chunk in enumerate(_chunk_text(text)):
        yield {
            "instruction": (
                "Distill this write-up into attacker takeaways: discovery moves, exploitation chain, impact framing, "
                "and how to replay the methodology ethically on authorized targets. "
                f"{AUTHORIZATION_NOTE}"
            ),
            "input": f"Title: {title}\nURL: {url}\n\n---\n{chunk}",
            "output": _writeup_redteam(chunk, tags),
            "tags": tags,
            "meta": {"source": "url", "url": url, "chunk": i},
        }


def _writeup_redteam(chunk: str, tags: list[str]) -> str:
    paras = [p.strip() for p in re.split(r"\n{2,}", chunk) if p.strip()]
    lead = paras[0][:900] if paras else ""
    out = [
        "## Mission summary",
        lead if lead else "(See input.)",
        "",
        "## Attacker playbook (abstracted)",
        "- Recon pivot(s) implied by the author.",
        "- Vuln class and why it maps to bounty impact.",
        "",
        "## Impact stack",
    ]
    out.extend(f"- {t}" for t in tags[:12])
    out.extend(
        [
            "",
            "## What to replicate in-scope",
            "- Instrumented tests, minimal PoC, evidence collection, responsible disclosure tone.",
        ]
    )
    return "\n".join(out)


def raw_jsonl_to_instructions(raw_path: Path) -> Iterator[dict[str, Any]]:
    with raw_path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            src = record.get("source")
            if src == "github":
                yield from iter_github_instructions(record)
            elif src == "nvd":
                yield from iter_nvd_instructions(record)
            elif src == "url":
                yield from iter_url_instructions(record)


def write_instruction_dataset(raw_paths: list[Path], out_jsonl: Path) -> int:
    out_jsonl.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with out_jsonl.open("w", encoding="utf-8") as w:
        for rp in raw_paths:
            if not rp.exists():
                continue
            for row in raw_jsonl_to_instructions(rp):
                w.write(json.dumps(row, ensure_ascii=False) + "\n")
                n += 1
    return n
