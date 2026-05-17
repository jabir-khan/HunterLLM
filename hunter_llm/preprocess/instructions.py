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


_GITHUB_INSTRUCTION_TEMPLATES = [
    (
        "hunt_plan",
        "You are mentoring an authorized bug bounty hunter. For this reference material, explain how an attacker "
        "would operationalize it during in-scope testing: entry points, prerequisite conditions, "
        "likely impact classes, and how to document a convincing proof-of-impact.",
    ),
    (
        "code_review",
        "Imagine you are doing an offensive code review of an in-scope target where this reference material applies. "
        "Identify the source/sink patterns to look for, the function names worth grepping, and the kind of taint flow "
        "that would yield bounty-worthy impact.",
    ),
    (
        "report_draft",
        "Draft a bug bounty report skeleton that someone could fill in if they discovered an instance of the issue "
        "this reference material describes on an in-scope target. Include sections: Title, Summary, Impact, "
        "Reproduction steps, Suggested remediation.",
    ),
]


def _detect_github_kind(path: str, repo: str = "") -> str:
    p = (path or "").lower()
    r = (repo or "").lower()
    if "documentation/modules" in p or r.endswith("/metasploit-framework"):
        if "documentation/modules" in p:
            return "metasploit_module"
    if "tops_by_bug_type" in p:
        return "hackerone_index"
    if "cheatsheets" in p or "wstg" in p or "asvs" in p:
        return "owasp_doc"
    if r.endswith("/nuclei-templates") and p.endswith((".yaml", ".yml")):
        return "nuclei_template"
    return "generic"


def iter_github_instructions(record: dict[str, Any]) -> Iterator[dict[str, Any]]:
    text = record.get("text") or ""
    repo = record.get("repo", "")
    path = record.get("path", "")
    tags = infer_tags(text + " " + path)
    kind = _detect_github_kind(path, repo)
    if kind == "metasploit_module":
        yield from _iter_metasploit_instructions(record, tags)
        return
    if kind == "hackerone_index":
        yield from _iter_hackerone_index_instructions(record, tags)
        return
    if kind == "nuclei_template":
        yield from _iter_nuclei_instructions(record, tags)
        return

    chunks = _chunk_text(text)
    templates = _GITHUB_INSTRUCTION_TEMPLATES if len(chunks) == 1 else _GITHUB_INSTRUCTION_TEMPLATES[:1]
    for i, chunk in enumerate(chunks):
        for tname, body in templates:
            instr = body + f" {AUTHORIZATION_NOTE}"
            yield {
                "instruction": instr,
                "input": f"Repository file: {repo}/{path} (chunk {i + 1})\n\n---\n{chunk}",
                "output": _payload_redteam(chunk, tags, template=tname),
                "tags": tags,
                "meta": {"source": "github", "repo": repo, "path": path, "template": tname, "kind": kind},
            }


def _iter_metasploit_instructions(record: dict[str, Any], tags: list[str]) -> Iterator[dict[str, Any]]:
    text = record.get("text") or ""
    repo = record.get("repo", "")
    path = record.get("path", "")
    title = _extract_first_heading(text) or Path(path).stem
    description = _extract_section(text, ("description",)) or ""
    targets = _extract_section(text, ("targets", "target", "verification steps")) or ""
    refs = _extract_section(text, ("references", "ref")) or ""
    inp_lines = [f"Module: {title}", f"Path: {path}", ""]
    if description:
        inp_lines.append(f"Description:\n{description}\n")
    if targets:
        inp_lines.append(f"Targets / verification:\n{targets}\n")
    if refs:
        inp_lines.append(f"References:\n{refs}\n")
    inp = "\n".join(inp_lines).strip() or text[:3000]
    out = (
        "## What this exploits\n"
        f"{description.strip() or '(See module description.)'}\n\n"
        "## Attacker primitives\n"
        "- Identify the vulnerable component(s), version range, and default config required.\n"
        "- Confirm the network position / authentication context the module assumes.\n"
        "- Note any payload constraints (architecture, language, callback type).\n\n"
        "## Bounty-grade proof-of-impact narrative (in-scope only)\n"
        "- Demonstrate code execution / data access on a lab instance; do not pivot to systems outside the scope.\n"
        "- Capture artifacts: process listing, file write, OOB callback, or read of a non-default file.\n"
        "- Tie outcome to a business-impact statement the program will value (RCE on bastion = full env compromise, etc.).\n\n"
        "## How to discover similar issues on adjacent targets\n"
        "- Fingerprint the same product/family on the program's perimeter (Shodan, ASN sweep, JS bundles).\n"
        "- Look for unauth-reachable management endpoints, default creds, or known CVE recurrence.\n"
    )
    yield {
        "instruction": (
            "You are an offensive security mentor. Explain how to use the Metasploit module described below "
            "responsibly in an authorized engagement: what it exploits, attacker prerequisites, what counts as "
            "a strong proof-of-impact, and how to find similar issues on in-scope adjacent targets. "
            f"{AUTHORIZATION_NOTE}"
        ),
        "input": inp,
        "output": out,
        "tags": tags,
        "meta": {"source": "github", "repo": repo, "path": path, "kind": "metasploit_module"},
    }


_HACKERONE_LINE_RE = re.compile(
    r"""^\s*\d+\.\s*           # 1.
        \[(?P<title>[^\]]+)\]  # [Title]
        \((?P<url>https?://[^\)]+)\) # (url)
        \s*to\s*(?P<program>.+?)     # to Program
        \s*-\s*(?P<upvotes>\d+)\s*upvotes
        ,\s*\$(?P<bounty>[\d,]+)     # , $1234
    """,
    re.VERBOSE,
)


def _parse_hackerone_numbered_list(text: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line in text.splitlines():
        m = _HACKERONE_LINE_RE.match(line)
        if not m:
            continue
        rows.append({
            "title": m.group("title").strip(),
            "url": m.group("url").strip(),
            "program": m.group("program").strip(),
            "upvotes": m.group("upvotes").strip(),
            "bounty": m.group("bounty").strip(),
        })
    return rows


def _iter_hackerone_index_instructions(record: dict[str, Any], tags: list[str]) -> Iterator[dict[str, Any]]:
    text = record.get("text") or ""
    repo = record.get("repo", "")
    path = record.get("path", "")
    bug_class = Path(path).stem.lstrip("TOP").replace("_", " ").lower() or "vuln"
    rows = _parse_hackerone_numbered_list(text)
    if not rows:
        rows = _parse_markdown_table_rows(text)
    if not rows:
        return
    for row in rows[:30]:
        title = (row.get("title") or row.get("report") or "").strip()
        program = (row.get("program") or row.get("target") or "").strip()
        bounty = (row.get("bounty") or row.get("amount") or "").strip()
        if not title:
            continue
        inp = f"Bug class: {bug_class}\nProgram: {program}\nReport title: {title}\nBounty: {bounty}"
        out = (
            f"## Why this title attracts severity\n"
            f"- The title implies a {bug_class}-class issue; severity hinges on what the reporter could access or change.\n"
            "- Bounty triagers reward concrete impact on confidentiality/integrity/availability over abstract bug presence.\n\n"
            "## Hunting strategy on adjacent programs\n"
            "- Map the program's surface (subdomains, mobile/API endpoints, third-party integrations).\n"
            f"- Probe the surfaces most prone to {bug_class}: where user-controlled input meets sensitive sinks.\n"
            "- Reproduce minimally; collect HTTP requests, responses, and a one-line risk statement.\n\n"
            "## Report skeleton (fill in once you have a finding)\n"
            "- Title: succinct, names the asset and the bug class.\n"
            "- Summary: one paragraph an L1 triager can grasp in 30s.\n"
            "- Steps to reproduce: numbered, idempotent, copy-pasteable.\n"
            "- Impact: tie to data sensitivity, user count, or revenue exposure.\n"
            "- Remediation suggestion: short, constructive.\n"
        )
        yield {
            "instruction": (
                "From the following disclosed HackerOne report index entry, infer the likely attacker primitive, "
                "outline a hunting strategy you could replay on adjacent in-scope programs, and draft a report skeleton. "
                "Do not invent details not implied by the title. "
                f"{AUTHORIZATION_NOTE}"
            ),
            "input": inp,
            "output": out,
            "tags": tags or [bug_class],
            "meta": {"source": "github", "repo": repo, "path": path, "kind": "hackerone_index", "title": title},
        }


def _iter_nuclei_instructions(record: dict[str, Any], tags: list[str]) -> Iterator[dict[str, Any]]:
    text = record.get("text") or ""
    repo = record.get("repo", "")
    path = record.get("path", "")
    inp = f"Nuclei template path: {path}\n\n```yaml\n{text[:3500]}\n```"
    out = (
        "## What this template detects\n"
        "- Read the `id`, `info.name`, and `info.tags` to confirm the bug class.\n"
        "- Inspect the matcher conditions: what response/header/body signal does it depend on?\n\n"
        "## How to weaponize the finding into bounty impact\n"
        "- A template match alone is a signal, not a vulnerability — verify reachability and access required.\n"
        "- Craft a minimal request that reproduces the matcher conditions without destructive side effects.\n"
        "- Escalate: data read, account takeover path, or pivot to a more impactful primitive on the same host.\n\n"
        "## Adjacent template ideas\n"
        "- If the matcher hinges on a vendor/version string, write companion templates for sibling endpoints.\n"
        "- If it hinges on a default credential or path, sweep related ports/services on the same ASN (in-scope).\n"
    )
    yield {
        "instruction": (
            "Explain the following Nuclei template like a bug-bounty mentor: what it detects, the request pattern "
            "and matcher, how to validate findings without harm, and how to convert a hit into a bounty-grade "
            "impact narrative. "
            f"{AUTHORIZATION_NOTE}"
        ),
        "input": inp,
        "output": out,
        "tags": tags,
        "meta": {"source": "github", "repo": repo, "path": path, "kind": "nuclei_template"},
    }


def _extract_first_heading(text: str) -> str | None:
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("#"):
            return s.lstrip("#").strip() or None
    return None


def _extract_section(text: str, headings: tuple[str, ...]) -> str | None:
    """Return the markdown section body under any of the given case-insensitive headings."""
    lower_headings = {h.lower() for h in headings}
    lines = text.splitlines()
    in_section = False
    body: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#"):
            heading = stripped.lstrip("#").strip().lower().rstrip(":")
            if heading in lower_headings:
                in_section = True
                continue
            if in_section:
                break
        elif in_section:
            body.append(line)
    out = "\n".join(body).strip()
    return out or None


def _parse_markdown_table_rows(text: str) -> list[dict[str, str]]:
    """Parse the first markdown table in `text` into list of dicts keyed by header."""
    rows: list[dict[str, str]] = []
    lines = [ln for ln in text.splitlines() if ln.strip()]
    headers: list[str] | None = None
    for ln in lines:
        if "|" not in ln:
            if headers is not None:
                break
            continue
        cells = [c.strip() for c in ln.strip().strip("|").split("|")]
        if all(set(c) <= {"-", ":", " "} for c in cells):
            continue
        if headers is None:
            headers = [c.lower() for c in cells]
            continue
        if len(cells) != len(headers):
            continue
        rows.append(dict(zip(headers, cells)))
    return rows


def _payload_redteam(chunk: str, tags: list[str], template: str = "hunt_plan") -> str:
    header_map = {
        "hunt_plan": "## Red-team reading of the snippet\n",
        "code_review": "## Offensive code-review checklist\n",
        "report_draft": "## Report skeleton\n",
    }
    header = header_map.get(template, "## Notes\n")
    if template == "report_draft":
        return (
            header
            + "- **Title:** concise, names asset + bug class\n"
            "- **Summary:** one-paragraph triager-friendly overview\n"
            "- **Reproduction steps:** numbered, copy-pasteable, idempotent\n"
            "- **Impact:** confidentiality / integrity / availability with concrete data or capability\n"
            "- **Suggested remediation:** terse, constructive\n\n"
            f"Themes from snippet: {', '.join(tags) if tags else 'see input'}.\n\n"
            "## Reference excerpt\n```\n" + chunk[:2000] + "\n```\n"
        )
    if template == "code_review":
        return (
            header
            + (f"Likely sinks/patterns: {', '.join(tags)}.\n\n" if tags else "")
            + "- Grep for user-controlled inputs reaching sensitive sinks (DB queries, command exec, HTTP fetch, file read).\n"
            "- Trace authentication and authorization boundaries crossed by each candidate flow.\n"
            "- Note any framework helpers that *look* safe but accept raw input (string concat, eval-like calls).\n\n"
            "## Reference excerpt\n```\n" + chunk[:2000] + "\n```\n"
        )
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
    base_input = f"{cid}\n\n{desc}".strip()

    yield {
        "instruction": (
            "Break this CVE down for offensive triage: root cause, realistic attacker path, maximal defensible impact, "
            "and what a strong proof looks like in a pentest/bounty setting. Stay faithful to the text. "
            f"{AUTHORIZATION_NOTE}"
        ),
        "input": base_input,
        "output": _cve_output(record),
        "tags": tags,
        "meta": {"source": "nvd", "cve_id": cid, "template": "triage"},
    }

    yield {
        "instruction": (
            "You are advising a bug bounty hunter who suspects this CVE class may exist on an in-scope program. "
            "Outline a hunting strategy: how to fingerprint affected versions, where to look in the program's surface, "
            "and what evidence to collect for a high-severity report. "
            f"{AUTHORIZATION_NOTE}"
        ),
        "input": base_input,
        "output": _cve_hunt_output(record),
        "tags": tags,
        "meta": {"source": "nvd", "cve_id": cid, "template": "hunt"},
    }

    yield {
        "instruction": (
            "Draft a bug bounty report skeleton describing a hypothetical in-scope finding of this CVE class. "
            "Include Title, Summary, Reproduction steps (placeholders), Impact, Severity rationale, and Suggested "
            f"remediation. Stay faithful to the CVE text. {AUTHORIZATION_NOTE}"
        ),
        "input": base_input,
        "output": _cve_report_output(record),
        "tags": tags,
        "meta": {"source": "nvd", "cve_id": cid, "template": "report"},
    }


def _cve_hunt_output(record: dict[str, Any]) -> str:
    desc = record.get("description") or ""
    cid = record.get("cve_id") or ""
    return (
        "## Fingerprint the affected component\n"
        f"- Identify product/version range named in the CVE text: `{cid}`.\n"
        "- Use targeted requests/banner grabs (HTTP headers, favicon hash, JS bundle names) to find candidates.\n"
        "- Cross-check with public exposure data only on assets that fall under the program's stated scope.\n\n"
        "## Where to look on the program's surface\n"
        "- Main domain + documented subdomains (no zone walking outside scope).\n"
        "- API endpoints and admin panels exposed unintentionally.\n"
        "- Marketing/legacy sites that often lag on patching.\n\n"
        "## Evidence to collect for a high-severity report\n"
        "- A minimal request/response pair that demonstrates the vulnerable condition.\n"
        "- A non-destructive proof-of-impact: reading a non-default file, triggering an OOB callback, or surfacing data the role should not access.\n"
        "- Version evidence (banner, hash, response artifact) tying the asset to the CVE.\n\n"
        "## CVE text (for reference)\n"
        f"{desc.strip()}\n"
    )


def _cve_report_output(record: dict[str, Any]) -> str:
    desc = record.get("description") or ""
    cid = record.get("cve_id") or ""
    return (
        "## Title\n"
        f"{cid} affecting <asset> — <bug class> leading to <impact>\n\n"
        "## Summary\n"
        "<one paragraph: what the bug is, what asset is affected, what the attacker gains. Reference the CVE.>\n\n"
        "## Reproduction steps\n"
        "1. <recon step that confirms the vulnerable component / version>\n"
        "2. <minimal request or interaction that triggers the bug>\n"
        "3. <observation that proves the condition>\n\n"
        "## Impact\n"
        "- <data sensitivity gained or capability obtained>\n"
        "- <user/role boundary crossed>\n"
        "- <blast radius: single user / tenant / global>\n\n"
        "## Severity rationale\n"
        "- Tie to CVSS vector from the advisory if available.\n"
        "- Adjust for program-specific multipliers (admin asset, sensitive data type).\n\n"
        "## Suggested remediation\n"
        "- Apply the fixed version from the vendor advisory.\n"
        "- If patching is delayed, document temporary mitigation (input validation, WAF rule, feature flag).\n\n"
        "## Underlying CVE text\n"
        f"{desc.strip()}\n"
    )


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


def iter_cisa_kev_instructions(record: dict[str, Any]) -> Iterator[dict[str, Any]]:
    cid = record.get("cve_id") or ""
    vendor = record.get("vendor") or ""
    product = record.get("product") or ""
    name = record.get("name") or ""
    desc = record.get("description") or ""
    required = record.get("required_action") or ""
    date_added = record.get("date_added") or ""
    ransomware = record.get("ransomware") or "Unknown"
    cwes = record.get("cwes") or []
    tags = infer_tags(name + " " + desc + " " + product) or ["KEV"]

    inp = (
        f"CVE: {cid}\n"
        f"Vendor: {vendor}\n"
        f"Product: {product}\n"
        f"Name: {name}\n"
        f"CISA KEV added: {date_added}\n"
        f"Known ransomware use: {ransomware}\n"
        f"CWEs: {', '.join(cwes) if cwes else '(none listed)'}\n"
        f"Description: {desc}\n"
        f"Required mitigation (defender side): {required}"
    )

    out = (
        "## Why this CVE matters right now\n"
        f"- `{cid}` is on the CISA Known Exploited Vulnerabilities catalog (added {date_added}).\n"
        f"- That means real-world adversaries are using it; a triager will treat reachable instances as **critical**.\n"
        f"- Ransomware-use signal: **{ransomware}**.\n\n"
        "## Attack surface to fingerprint\n"
        f"- Product: `{product}` by `{vendor}`. Identify in-scope assets running this product (banner, version string, distinctive endpoint).\n"
        "- Cross-reference the program's documented stack and any third-party integrations (vendors of vendors).\n\n"
        "## Hunting playbook (in-scope only)\n"
        "- Confirm version against the vendor advisory's vulnerable range.\n"
        "- Trigger the documented condition with a minimal, non-destructive probe (banner/response delta, OOB callback, error class).\n"
        "- Capture concrete evidence: HTTP request/response pair, version banner, OOB log line.\n\n"
        "## Bounty-grade impact framing\n"
        "- 'Known-exploited' provides automatic severity uplift; tie your evidence to data sensitivity / lateral movement potential on the specific asset.\n"
        f"- Reference `{cid}` and the KEV listing in the report to short-circuit triage discussion.\n\n"
        "## Defender's required mitigation (for context)\n"
        f"{required.strip() or '(See vendor advisory.)'}\n"
    )

    yield {
        "instruction": (
            "You are advising an authorized bug bounty hunter on a CVE that CISA has confirmed is being "
            "actively exploited. Explain why it should be top-of-list, how to fingerprint the affected "
            "product on the program's surface, what evidence to collect, and how to frame impact in the report. "
            f"{AUTHORIZATION_NOTE}"
        ),
        "input": inp,
        "output": out,
        "tags": tags,
        "meta": {"source": "cisa_kev", "cve_id": cid, "vendor": vendor, "product": product},
    }


def iter_mitre_attack_instructions(record: dict[str, Any]) -> Iterator[dict[str, Any]]:
    tid = record.get("technique_id") or ""
    name = record.get("name") or ""
    desc = record.get("description") or ""
    platforms = record.get("platforms") or []
    detection = record.get("detection") or ""
    phases = record.get("kill_chain_phases") or []
    url = record.get("url") or ""
    is_sub = record.get("is_subtechnique")
    tags = infer_tags(name + " " + desc) or [tid.split(".")[0] if "." in tid else tid]

    inp = (
        f"MITRE ATT&CK technique: {tid} - {name}\n"
        f"Type: {'sub-technique' if is_sub else 'technique'}\n"
        f"Kill chain phases: {', '.join(phases) if phases else '(none)'}\n"
        f"Platforms: {', '.join(platforms) if platforms else '(any)'}\n"
        f"URL: {url}\n\n"
        f"Description:\n{desc}\n\n"
        f"Defender detection guidance:\n{detection or '(none)'}"
    )

    out = (
        f"## How an offensive operator uses {tid} ({name})\n"
        f"- Where it sits in the kill chain: {', '.join(phases) if phases else 'multiple stages'}.\n"
        "- Reframe the description from defender language into the attacker's question: *what does this primitive let me do that I couldn't do before?*\n"
        "- Identify the smallest action that demonstrates the technique on an authorized target (e.g. process creation, registry write, OAuth token replay).\n\n"
        "## Mapping to bug-bounty / pentest scope\n"
        "- Most bounty programs reward web/app primitives; ATT&CK techniques are most relevant when chained to a web-side initial-access bug (RCE, SSRF, file write).\n"
        "- For internal/AD engagements, this technique is a candidate post-exploitation step — only execute when explicitly in scope.\n\n"
        "## Evidence to capture\n"
        "- Minimal artifact set the defender team can replay (command, network packet, log line).\n"
        "- Tie back to ATT&CK ID in the report so triagers immediately understand the impact class.\n\n"
        "## Detection notes to reason about (red-team perspective)\n"
        f"{detection.strip() or '(See MITRE page.)'}\n"
    )

    yield {
        "instruction": (
            "Translate the following MITRE ATT&CK technique into actionable offensive guidance for an "
            "authorized bug-hunting / pentest context: where it fits in an exploit chain, what evidence to "
            "capture, and what defender telemetry to expect. "
            f"{AUTHORIZATION_NOTE}"
        ),
        "input": inp,
        "output": out,
        "tags": tags,
        "meta": {"source": "mitre_attack", "technique_id": tid, "name": name, "url": url},
    }


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
            elif src == "cisa_kev":
                yield from iter_cisa_kev_instructions(record)
            elif src == "mitre_attack":
                yield from iter_mitre_attack_instructions(record)


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
