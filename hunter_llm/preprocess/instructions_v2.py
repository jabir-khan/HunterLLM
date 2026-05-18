"""Dataset builder v2 — pair every prompt with the **real source text** as the output.

The v1 builder synthesized a generic ~7-line template for every record and put
the real article body in the *input*. The model learned to emit platitudes and
ignore the source. v2 reverses this: each instruction's `output` is the actual
write-up / CVE description / technique description, so the model learns to
*generate* real domain content when asked.

Design rules (v2):
- Inputs are minimal (title + URL + a short framing line). Outputs are 500–6000
  chars of real content.
- Multiple prompts per source = data augmentation, but the same body is reused
  as the gold output (different framings teach the model to surface the same
  content for different question shapes).
- Source-specific structure is preserved (CVE → CVSS/CWE block; KEV → KEV
  badge; ATT&CK → kill-chain phases) so the model picks up real metadata, not
  fake "Impact stack" headers.
- Sources with no useful free text (raw wordlists, payload dumps) are skipped.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterator

from hunter_llm.preprocess.taxonomy import infer_tags
from hunter_llm.prompts import AUTHORIZATION_NOTE

MIN_OUTPUT_CHARS = 400
MAX_OUTPUT_CHARS = 6000


def _trim(text: str, limit: int = MAX_OUTPUT_CHARS) -> str:
    text = text.strip()
    if len(text) <= limit:
        return text
    cut = text[:limit]
    last_para = cut.rfind("\n\n")
    if last_para > limit * 0.6:
        cut = cut[:last_para]
    return cut.rstrip() + "\n\n[... write-up continues; truncated for training ...]"


_WHITESPACE_RE = re.compile(r"\n{3,}")


def _clean_body(text: str) -> str:
    text = (text or "").strip()
    text = _WHITESPACE_RE.sub("\n\n", text)
    return text


def iter_url_v2(record: dict[str, Any]) -> Iterator[dict[str, Any]]:
    body = _clean_body(record.get("text") or "")
    if len(body) < MIN_OUTPUT_CHARS:
        return
    url = record.get("url") or ""
    title = (record.get("title") or "").strip() or "Untitled write-up"
    host = record.get("host") or ""
    tags = infer_tags(body) or []

    framings = [
        (
            "writeup",
            f"Write a detailed bug-bounty write-up titled \"{title}\". "
            f"Cover the discovery, exploitation, impact, and remediation. {AUTHORIZATION_NOTE}",
        ),
        (
            "methodology",
            f"Explain the methodology used in the write-up \"{title}\" — discovery steps, "
            f"tooling/requests, exploitation chain, and how to reproduce ethically on an "
            f"authorized target. {AUTHORIZATION_NOTE}",
        ),
        (
            "report",
            f"Produce a HackerOne-style report based on the bug described in \"{title}\". "
            f"Include Title, Summary, Steps to reproduce, Impact, and Suggested remediation. "
            f"{AUTHORIZATION_NOTE}",
        ),
    ]
    out = _trim(body)
    inp = (
        f"Source title: {title}\n"
        f"Source host: {host}\n"
        f"Source URL: {url}\n"
        f"Tags (auto): {', '.join(tags) if tags else 'general web'}\n"
    )
    for tname, instr in framings:
        yield {
            "instruction": instr,
            "input": inp,
            "output": out,
            "tags": tags or ["writeup"],
            "meta": {"source": "url", "url": url, "title": title, "template": tname, "kind": "writeup_v2"},
        }


def iter_nvd_v2(record: dict[str, Any]) -> Iterator[dict[str, Any]]:
    desc = (record.get("description") or "").strip()
    cid = record.get("cve_id") or ""
    if not desc or len(desc) < 100:
        return
    raw = record.get("raw") or {}
    cve = raw.get("cve") if isinstance(raw, dict) else {}
    cwes: list[str] = []
    for w in (cve.get("weaknesses") or [])[:5] if isinstance(cve, dict) else []:
        for d in w.get("description") or []:
            if d.get("lang") == "en":
                v = (d.get("value") or "").strip()
                if v:
                    cwes.append(v)
    metrics = (cve.get("metrics") or {}) if isinstance(cve, dict) else {}
    cvss_lines: list[str] = []
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key) or []
        if arr:
            m = arr[0].get("cvssData") or {}
            vec = m.get("vectorString") or ""
            base = m.get("baseScore")
            sev = m.get("baseSeverity") or ""
            cvss_lines.append(f"{key}: {base} {sev} ({vec})".strip())
            break

    out_lines = [
        f"# {cid}",
        "",
        "## Description",
        desc,
    ]
    if cvss_lines:
        out_lines += ["", "## Severity", *cvss_lines]
    if cwes:
        out_lines += ["", "## Weaknesses (CWE)"] + [f"- {c}" for c in cwes]
    out_lines += [
        "",
        "## What an offensive analyst should take away",
        "- Identify the attacker primitive named in the description (input that reaches a sensitive sink, auth boundary crossed, etc.).",
        "- The strongest in-scope proof is the smallest reliable trigger that surfaces a non-default capability (read a protected file, run a benign command, exfil a flag), not destructive impact.",
        "- Tie the finding back to the CWE class so triagers can map it to their threat model.",
    ]
    out = "\n".join(out_lines)
    if len(out) < MIN_OUTPUT_CHARS:
        return

    inp = f"CVE: {cid}\n"
    framings = [
        (
            "explain",
            f"Explain {cid} as an offensive-security analyst would — root cause, attacker "
            f"primitive, realistic impact, and severity. {AUTHORIZATION_NOTE}",
        ),
        (
            "hunt",
            f"Outline a hunting plan for {cid} on an authorized program: fingerprinting the "
            f"affected product, request shape to probe, and evidence to collect for a high-"
            f"severity report. {AUTHORIZATION_NOTE}",
        ),
    ]
    for tname, instr in framings:
        yield {
            "instruction": instr,
            "input": inp,
            "output": out,
            "tags": infer_tags(desc) or ["CVE"],
            "meta": {"source": "nvd", "cve_id": cid, "template": tname, "kind": "nvd_v2"},
        }


def iter_cisa_kev_v2(record: dict[str, Any]) -> Iterator[dict[str, Any]]:
    cid = record.get("cve_id") or ""
    vendor = record.get("vendor") or ""
    product = record.get("product") or ""
    name = record.get("name") or ""
    desc = (record.get("description") or "").strip()
    required = (record.get("required_action") or "").strip()
    date_added = record.get("date_added") or ""
    ransomware = record.get("ransomware") or "Unknown"
    cwes = record.get("cwes") or []
    if not desc or len(desc) < 80:
        return

    out_lines = [
        f"# {cid} — {name}",
        "",
        f"**Vendor / product:** {vendor} / {product}",
        f"**Added to CISA KEV:** {date_added}",
        f"**Known ransomware use:** {ransomware}",
    ]
    if cwes:
        out_lines.append(f"**CWEs:** {', '.join(cwes)}")
    out_lines += [
        "",
        "## What the bug is",
        desc,
    ]
    if required:
        out_lines += [
            "",
            "## Defender's required mitigation (for context)",
            required,
        ]
    out_lines += [
        "",
        "## Why this matters on a live program",
        f"- CISA KEV means real adversaries are exploiting {cid} in the wild — a triager will weight "
        "in-scope evidence accordingly.",
        f"- Fingerprint `{product}` on the program's surface (banner / endpoint / JS bundle / favicon hash).",
        "- A working minimal probe + version proof is usually enough for a high-severity submission; "
        "do not pivot beyond what the program authorises.",
    ]
    out = "\n".join(out_lines)
    if len(out) < MIN_OUTPUT_CHARS:
        return

    inp = f"CVE: {cid}\nProduct: {vendor} {product}\n"
    yield {
        "instruction": (
            f"Brief an authorized bug-bounty hunter on {cid}, a CVE confirmed by CISA KEV as actively "
            f"exploited. Cover what the bug is, how to fingerprint affected assets, and how to frame "
            f"impact responsibly. {AUTHORIZATION_NOTE}"
        ),
        "input": inp,
        "output": out,
        "tags": infer_tags(desc + " " + product) or ["KEV"],
        "meta": {"source": "cisa_kev", "cve_id": cid, "vendor": vendor, "product": product, "kind": "kev_v2"},
    }


def iter_mitre_attack_v2(record: dict[str, Any]) -> Iterator[dict[str, Any]]:
    tid = record.get("technique_id") or ""
    name = record.get("name") or ""
    desc = (record.get("description") or "").strip()
    platforms = record.get("platforms") or []
    detection = (record.get("detection") or "").strip()
    phases = record.get("kill_chain_phases") or []
    url = record.get("url") or ""
    if not desc or len(desc) < 120:
        return

    out_lines = [
        f"# {tid} — {name}",
        "",
        f"**Kill-chain phases:** {', '.join(phases) if phases else 'multiple'}",
        f"**Platforms:** {', '.join(platforms) if platforms else 'any'}",
        f"**MITRE URL:** {url}",
        "",
        "## Technique",
        desc,
    ]
    if detection:
        out_lines += [
            "",
            "## Defender detection guidance",
            detection,
        ]
    out_lines += [
        "",
        "## How an offensive operator uses it in scope",
        "- Reframe the description as the attacker's question: *what does this primitive let me do that I couldn't do before?*",
        f"- Identify the smallest action that demonstrates {tid} on an authorized target (one command, one log line, one network packet).",
        "- Tie the evidence back to ATT&CK ID so the report triager immediately understands the impact class.",
    ]
    out = "\n".join(out_lines)
    if len(out) < MIN_OUTPUT_CHARS:
        return

    yield {
        "instruction": (
            f"Translate MITRE ATT&CK technique {tid} ({name}) into actionable offensive guidance for "
            f"an authorized engagement: where it fits in the kill chain, the smallest demonstrable "
            f"action, and what defender telemetry to expect. {AUTHORIZATION_NOTE}"
        ),
        "input": f"Technique: {tid}\nName: {name}\nURL: {url}\n",
        "output": out,
        "tags": infer_tags(name + " " + desc) or [tid.split(".")[0] if "." in tid else tid],
        "meta": {"source": "mitre_attack", "technique_id": tid, "name": name, "url": url, "kind": "attack_v2"},
    }


# GitHub repo files are intentionally NOT routed through v2 by default —
# most of the value already lives in the URL write-ups + CVE catalogues, and
# raw repo text (wordlists, payload dumps) was the main source of v1's
# generic-content problem. Re-enable per-kind below if needed.
def iter_github_v2(record: dict[str, Any]) -> Iterator[dict[str, Any]]:
    text = (record.get("text") or "").strip()
    path = (record.get("path") or "").lower()
    repo = (record.get("repo") or "").lower()
    if len(text) < 600:
        return
    # OWASP cheatsheets / WSTG / ASVS — real prose, keep.
    if any(kw in path for kw in ("cheatsheets", "wstg", "asvs")):
        out = _trim(text)
        if len(out) < MIN_OUTPUT_CHARS:
            return
        title = path.split("/")[-1].replace(".md", "").replace("-", " ").title()
        yield {
            "instruction": (
                f"Reproduce the OWASP guidance on \"{title}\" — keep its structure and concrete "
                f"checks; do not summarise away the specifics. {AUTHORIZATION_NOTE}"
            ),
            "input": f"OWASP source: {path}\n",
            "output": out,
            "tags": infer_tags(text) or ["OWASP"],
            "meta": {"source": "github", "repo": repo, "path": path, "kind": "owasp_v2"},
        }
        return
    # Metasploit module docs — real attacker prose, keep.
    if "documentation/modules" in path and "metasploit" in repo:
        out = _trim(text)
        if len(out) < MIN_OUTPUT_CHARS:
            return
        yield {
            "instruction": (
                "Reproduce this Metasploit module's documentation as if briefing an authorized red "
                f"teamer — preserve module name, targets, options, and references. {AUTHORIZATION_NOTE}"
            ),
            "input": f"Module path: {path}\n",
            "output": out,
            "tags": infer_tags(text) or ["Metasploit"],
            "meta": {"source": "github", "repo": repo, "path": path, "kind": "metasploit_v2"},
        }
        return
    # Skip everything else: PayloadsAllTheThings raw payloads, SecLists wordlists,
    # nuclei templates etc. add token volume but little structured prose.


def raw_jsonl_to_v2(raw_path: Path) -> Iterator[dict[str, Any]]:
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
            if src == "url":
                yield from iter_url_v2(record)
            elif src == "nvd":
                yield from iter_nvd_v2(record)
            elif src == "cisa_kev":
                yield from iter_cisa_kev_v2(record)
            elif src == "mitre_attack":
                yield from iter_mitre_attack_v2(record)
            elif src == "github":
                yield from iter_github_v2(record)


def write_v2_dataset(raw_paths: list[Path], out_jsonl: Path) -> dict[str, int]:
    out_jsonl.parent.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = {}
    n = 0
    with out_jsonl.open("w", encoding="utf-8") as w:
        for rp in raw_paths:
            if not rp.exists():
                continue
            for row in raw_jsonl_to_v2(rp):
                w.write(json.dumps(row, ensure_ascii=False) + "\n")
                n += 1
                kind = (row.get("meta") or {}).get("kind", "?")
                counts[kind] = counts.get(kind, 0) + 1
    counts["_total"] = n
    return counts
