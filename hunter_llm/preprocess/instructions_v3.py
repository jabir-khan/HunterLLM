"""v3 SFT builder — prescriptive / task-shaped pairs on top of v2's descriptive ones.

v2 fixed the "output is a template" bug from v1. v3 fixes the next layer: most
of v2's sources are still narrative prose. The model trained on v2 alone will
still default to writing *about* bug hunting rather than *doing* it.

v3 adds the buckets that teach the doing:

  - payload_v3      :  "Give me payloads for <bug class> in <context>"  ->  real
                       payload block from PayloadsAllTheThings (code fences, not
                       generic summary lines).
  - wordlist_v3     :  "Give me a wordlist for fuzzing <thing>"  ->  the first ~100
                       lines of the matching PAtT Intruder/ file.
  - nuclei_v3       :  "Write a nuclei template that detects <vuln>"  ->  the YAML.
  - tool_invocation :  curated "given task, give the command" pairs for
                       ffuf / sqlmap / dalfox / nuclei / curl / amass.
  - personal_v3     :  the user's own bug bounty reports turned into
                       "write the report" / "what's the next probe?" pairs.

Each bucket forces the gold output to look like a real pentester's Slack
message: payloads in fences, curl examples, specific endpoints, terse prose.
That style is what reduces "lecture mode" at inference time.

This module REPLACES v2 only for these new buckets — call together with
`write_v2_dataset` to keep the v2 outputs (write-ups, CVE descriptions, KEV,
ATT&CK, OWASP, Metasploit) in the mix.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterator

from hunter_llm.preprocess.taxonomy import infer_tags
from hunter_llm.prompts import AUTHORIZATION_NOTE

MIN_OUTPUT_CHARS = 200
MAX_OUTPUT_CHARS = 6000


def _trim(text: str, limit: int = MAX_OUTPUT_CHARS) -> str:
    text = text.strip()
    if len(text) <= limit:
        return text
    cut = text[:limit]
    last_para = cut.rfind("\n\n")
    if last_para > limit * 0.6:
        cut = cut[:last_para]
    return cut.rstrip()


# ---------------------------------------------------------------------------
# PayloadsAllTheThings — README sections (prescriptive payload blocks).
# ---------------------------------------------------------------------------

_HEADING_RE = re.compile(r"^(#{2,3})\s+(.+?)\s*$", re.MULTILINE)


def iter_patt_payload_sections(patt_root: Path) -> Iterator[dict[str, Any]]:
    """Walk every Markdown file under every top-level category in
    PayloadsAllTheThings (README.md *and* engine-specific siblings like
    `MySQL Injection.md`). Yield a training pair per H2 / H3 subsection that
    contains at least one fenced code block (i.e. real payloads, not narrative).
    """
    if not patt_root.is_dir():
        return
    skip_headings = {"summary", "references", "labs", "tools"}
    for category_dir in sorted(p for p in patt_root.iterdir() if p.is_dir() and not p.name.startswith(("_", "."))):
        category = category_dir.name
        for md in sorted(category_dir.glob("*.md")):
            if md.name in {"CONTRIBUTING.md", "DISCLAIMER.md", "README_CN.md"}:
                continue
            text = md.read_text(encoding="utf-8", errors="ignore")
            file_topic = md.stem if md.name != "README.md" else category
            matches = list(_HEADING_RE.finditer(text))
            if not matches:
                continue
            for i, m in enumerate(matches):
                heading = m.group(2).strip()
                if heading.lower().rstrip(":") in skip_headings:
                    continue
                start = m.end()
                end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
                chunk = text[start:end].strip()
                if "```" not in chunk:
                    continue
                if len(chunk) < MIN_OUTPUT_CHARS:
                    continue
                out = _trim(chunk)
                tags = infer_tags(category + " " + heading + " " + chunk) or [category]
                topic_label = f"{category} / {file_topic}" if file_topic != category else category
                yield {
                    "instruction": (
                        f"You are pair-hunting with an authorized pentester. Give them concrete "
                        f"payloads for **{topic_label} -- {heading}**. Keep every code fence "
                        f"intact and add a one-line note on when each payload variant applies. "
                        f"{AUTHORIZATION_NOTE}"
                    ),
                    "input": (
                        f"Bug class: {category}\n"
                        f"Engine / variant: {file_topic}\n"
                        f"Technique: {heading}\n"
                    ),
                    "output": out,
                    "tags": tags,
                    "meta": {
                        "source": "patt",
                        "category": category,
                        "file": md.name,
                        "section": heading,
                        "kind": "payload_v3",
                    },
                }


def iter_patt_intruder_lists(patt_root: Path, max_lines: int = 120) -> Iterator[dict[str, Any]]:
    """Each `Intruder/*.txt` is a raw payload list — useful as a "wordlist for X"
    response. We cap at `max_lines` to keep the training row a reasonable size.
    """
    if not patt_root.is_dir():
        return
    for txt in sorted(patt_root.rglob("Intruder/*.txt")):
        try:
            lines = txt.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            continue
        cleaned = [ln for ln in lines if ln.strip()]
        if len(cleaned) < 5:
            continue
        body = "\n".join(cleaned[:max_lines])
        if len(body) < MIN_OUTPUT_CHARS:
            continue
        category = txt.parent.parent.name
        list_name = txt.stem.replace("_", " ").replace("-", " ")
        out = f"```\n{body}\n```"
        if len(cleaned) > max_lines:
            out += f"\n\n[... {len(cleaned) - max_lines} more entries in the source list ...]"
        yield {
            "instruction": (
                f"Give me a focused wordlist for **{category}** — variant: **{list_name}**. "
                f"One payload per line, no commentary. {AUTHORIZATION_NOTE}"
            ),
            "input": f"Bug class: {category}\nWordlist variant: {list_name}\n",
            "output": out,
            "tags": infer_tags(category + " " + list_name) or [category],
            "meta": {"source": "patt_intruder", "category": category, "list": list_name, "kind": "wordlist_v3"},
        }


# ---------------------------------------------------------------------------
# Nuclei templates — YAML probes.
# ---------------------------------------------------------------------------

_NUCLEI_PRIORITY_TAGS = {
    "cve",  # known-CVE detection templates
    "rce", "sqli", "xss", "ssrf", "lfi", "rfi", "xxe", "ssti",
    "oauth", "auth-bypass", "auth", "takeover", "idor",
    "exposed-panel", "exposed-token", "exposure", "fileupload",
    "graphql", "jwt", "saml", "redirect",
    "cisco", "fortinet", "vmware", "atlassian", "jira", "confluence",
    "wordpress", "drupal", "joomla",
}


def iter_nuclei_templates(nuclei_root: Path, max_per_dir: int = 25) -> Iterator[dict[str, Any]]:
    """Sample nuclei templates: prefer those tagged with high-value vuln classes.

    Caps `max_per_dir` to avoid swamping the dataset with wp-plugin-cve YAML
    that all look the same.
    """
    if not nuclei_root.is_dir():
        return
    http_root = nuclei_root / "http"
    if not http_root.is_dir():
        http_root = nuclei_root
    by_dir: dict[Path, int] = {}
    for yml in sorted(http_root.rglob("*.yaml")):
        if "_template" in yml.name.lower():
            continue
        try:
            raw = yml.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if len(raw) < 200 or len(raw) > 8000:
            continue
        # Lightweight YAML inspection without importing PyYAML for speed —
        # we only need id / name / tags / matchers, and rely on regex.
        info_match = re.search(r"(?ms)^info:\s*\n((?:[ \t]+.+\n)+)", raw)
        if not info_match:
            continue
        info_block = info_match.group(1)
        name_m = re.search(r"name:\s*(.+)", info_block)
        tags_m = re.search(r"tags:\s*(.+)", info_block)
        sev_m = re.search(r"severity:\s*(\w+)", info_block)
        if not name_m:
            continue
        name = name_m.group(1).strip().strip("\"'")
        tags_csv = tags_m.group(1).strip().strip("\"'") if tags_m else ""
        severity = sev_m.group(1).strip().lower() if sev_m else "info"
        tag_set = {t.strip() for t in tags_csv.split(",") if t.strip()}
        if severity in {"info"} and not (tag_set & _NUCLEI_PRIORITY_TAGS):
            continue  # drop low-signal info templates without a priority tag
        bucket = yml.parent
        if by_dir.get(bucket, 0) >= max_per_dir:
            continue
        by_dir[bucket] = by_dir.get(bucket, 0) + 1
        rel = yml.relative_to(nuclei_root)
        out = f"```yaml\n{raw.strip()}\n```"
        yield {
            "instruction": (
                f"Write a nuclei template that detects: **{name}**. Use the standard nuclei "
                f"YAML schema (id, info, http/request, matchers). Keep it minimal and "
                f"non-destructive. {AUTHORIZATION_NOTE}"
            ),
            "input": (
                f"Detection target: {name}\n"
                f"Severity: {severity}\n"
                f"Tags: {tags_csv or '(none)'}\n"
                f"Template path (for reference): nuclei-templates/{rel}\n"
            ),
            "output": out,
            "tags": list(tag_set) or ["nuclei"],
            "meta": {
                "source": "nuclei",
                "template_path": str(rel),
                "name": name,
                "severity": severity,
                "kind": "nuclei_v3",
            },
        }


# ---------------------------------------------------------------------------
# Tool invocations — curated "task -> command" pairs.
# ---------------------------------------------------------------------------

_TOOL_INVOCATIONS: list[dict[str, str]] = [
    {
        "instruction": "I want to fuzz hidden API endpoints under /api on https://target.example.com. Give me a single ffuf command.",
        "output": (
            "```bash\n"
            "ffuf -u 'https://target.example.com/api/FUZZ' \\\n"
            "     -w ~/wordlists/SecLists/Discovery/Web-Content/api/api-endpoints.txt \\\n"
            "     -mc 200,201,204,301,302,401,403 \\\n"
            "     -fs 0 \\\n"
            "     -H 'User-Agent: Mozilla/5.0' \\\n"
            "     -t 40 -o ffuf_api.json\n"
            "```\n"
            "Tip: `-fs 0` drops empty responses; switch to `-fr '404|not found'` if the app returns 200 for misses."
        ),
        "tags": ["ffuf", "recon"],
    },
    {
        "instruction": "Convert this Burp request to a one-line curl I can iterate on:\n\n```http\nPOST /api/users/123 HTTP/1.1\nHost: target.example.com\nContent-Type: application/json\nAuthorization: Bearer eyJhb...\n\n{\"role\":\"admin\"}\n```",
        "output": (
            "```bash\n"
            "curl -s -i -X POST 'https://target.example.com/api/users/123' \\\n"
            "  -H 'Content-Type: application/json' \\\n"
            "  -H 'Authorization: Bearer eyJhb...' \\\n"
            "  -d '{\"role\":\"admin\"}'\n"
            "```\n"
            "Add `-x http://127.0.0.1:8080` to keep traffic in Burp; tweak the body to test IDOR (`123` -> `124`) or privilege change (`admin` -> other roles)."
        ),
        "tags": ["curl", "burp"],
    },
    {
        "instruction": "Run sqlmap against a single suspect GET parameter `id` on https://target.example.com/item.php?id=1 — keep it conservative (no destructive tests).",
        "output": (
            "```bash\n"
            "sqlmap -u 'https://target.example.com/item.php?id=1' \\\n"
            "       -p id --batch --level=2 --risk=1 \\\n"
            "       --technique=BEUS --random-agent --threads=4\n"
            "```\n"
            "B/E/U/S = boolean/error/UNION/stacked — drop `S` (stacked) for read-only safety. Use `--dbs` only after confirming the injection class."
        ),
        "tags": ["sqlmap", "sqli"],
    },
    {
        "instruction": "I want a DOM XSS scan of https://app.example.com — give me a dalfox invocation.",
        "output": (
            "```bash\n"
            "dalfox url 'https://app.example.com/?q=test' \\\n"
            "       --waf-evasion \\\n"
            "       --custom-payload-file ~/wordlists/payloads/xss-bypass.txt \\\n"
            "       --output dalfox.txt -F\n"
            "```\n"
            "For a list of parameterised URLs: `dalfox file urls.txt`. Add `--cookie 'session=...'` for authenticated scans (with permission)."
        ),
        "tags": ["dalfox", "xss"],
    },
    {
        "instruction": "Enumerate subdomains of target.example.com using only passive sources (no DNS bruteforce noise).",
        "output": (
            "```bash\n"
            "subfinder -d target.example.com -all -silent | \\\n"
            "  httpx -silent -title -status-code -tech-detect -o live_subs.txt\n"
            "```\n"
            "Passive-only by default. Pipe straight into `httpx` to filter to live hosts and grab a quick tech fingerprint."
        ),
        "tags": ["recon", "subfinder", "httpx"],
    },
    {
        "instruction": "Probe a specific in-scope host for a known Log4Shell pattern non-destructively.",
        "output": (
            "Use a nuclei tag-filtered run; do not throw the payload at random params:\n\n"
            "```bash\n"
            "nuclei -u https://target.example.com \\\n"
            "       -tags cve2021,log4j \\\n"
            "       -severity critical,high \\\n"
            "       -interactsh-url <your.oast.fun> \\\n"
            "       -rate-limit 30 -o log4j.txt\n"
            "```\n"
            "`-interactsh-url` gives a fresh OAST endpoint per request so callbacks are attributable. Only run with explicit program permission for the host."
        ),
        "tags": ["nuclei", "log4shell"],
    },
    {
        "instruction": "Given the JS bundle at https://app.example.com/static/main.123abc.js, extract endpoints + JS-side secrets candidates with one command.",
        "output": (
            "```bash\n"
            "linkfinder -i 'https://app.example.com/static/main.123abc.js' -o cli\n"
            "# Also worth running gf in parallel for secrets-shaped strings:\n"
            "curl -s 'https://app.example.com/static/main.123abc.js' | \\\n"
            "  gf secrets | sort -u\n"
            "```\n"
            "Endpoints from `linkfinder` -> feed back into `httpx` to confirm reachability. Validate any candidate secret manually before reporting."
        ),
        "tags": ["recon", "js"],
    },
    {
        "instruction": "Test a GraphQL endpoint for introspection + common auth weaknesses.",
        "output": (
            "```bash\n"
            "# 1) Confirm introspection is open:\n"
            "curl -s -X POST https://api.example.com/graphql \\\n"
            "     -H 'Content-Type: application/json' \\\n"
            "     -d '{\"query\":\"{__schema{queryType{name}}}\"}'\n\n"
            "# 2) Pull the full schema:\n"
            "graphql-cop -t https://api.example.com/graphql -o report.json\n"
            "```\n"
            "Then look in the schema for `me`, `viewer`, `userByEmail`, `deleteUser`, admin mutations. Field-level auth is the most common bug class."
        ),
        "tags": ["graphql", "api"],
    },
    {
        "instruction": "Spot-check an OAuth `redirect_uri` for common bypasses against https://app.example.com/oauth/authorize?client_id=abc&redirect_uri=https://app.example.com/cb.",
        "output": (
            "Throw these 7 variants at the `redirect_uri` and watch for a 302 to a non-`app.example.com` host. Stop at the first hit:\n\n"
            "```\n"
            "redirect_uri=https://app.example.com.attacker.tld/cb\n"
            "redirect_uri=https://attacker.tld#app.example.com/cb\n"
            "redirect_uri=https://app.example.com@attacker.tld/cb\n"
            "redirect_uri=https://app.example.com%2f.attacker.tld/cb\n"
            "redirect_uri=//attacker.tld/cb\n"
            "redirect_uri=https://app.example.com%5c@attacker.tld/cb\n"
            "redirect_uri=https:%2f%2fattacker.tld/cb\n"
            "```\n"
            "If any reflect, chain to ATO by capturing the `code` parameter from the callback. Use a Burp Collaborator URL (`xxxx.oast.fun`) so the callback is attributable."
        ),
        "tags": ["oauth", "open-redirect", "ato"],
    },
    {
        "instruction": "I have a Burp request that returns the victim user's data when I tamper the `id` param. How do I prove IDOR impact for a report?",
        "output": (
            "Capture three pieces of evidence in this order — stop the moment you have all three:\n\n"
            "1. **Two HTTP roundtrips, side-by-side**: your account's `id` vs a colleague-account `id` you control. Demonstrate the response body differs in PII / capability per identity. Do NOT iterate `id` blindly across real users.\n"
            "2. **Impact statement (one line)**: e.g. *\"Any authenticated low-priv user can read another user's email + phone via /api/users/<id> by incrementing the numeric ID.\"*\n"
            "3. **Severity rationale**: PII = high if email/PII; full account = critical. Map to the program's policy.\n\n"
            "Report skeleton ready-to-paste:\n\n"
            "```markdown\n"
            "**Title:** IDOR -- read any user's profile via /api/users/<id>\n"
            "**Summary:** ...\n"
            "**Reproduction:** 1. Log in as Attacker. 2. `curl -H 'Cookie: ...' https://target/api/users/<victim_id>`. 3. Response includes victim's email + phone.\n"
            "**Impact:** Unauthorized read of any user's PII; user count = ~N.\n"
            "**Remediation:** Server-side auth check tying `id` to the authenticated session.\n"
            "```"
        ),
        "tags": ["idor", "report"],
    },
]


def _curated_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "data" / "curated"


def _curated_tool_invocation_path() -> Path:
    return _curated_dir() / "tool_invocations.jsonl"


def _curated_reasoning_path() -> Path:
    return _curated_dir() / "reasoning_chains.jsonl"


def iter_tool_invocations() -> Iterator[dict[str, Any]]:
    """Emit curated tool/command pairs from JSONL (preferred) plus legacy inline list."""
    curated = _curated_tool_invocation_path()
    if curated.is_file():
        with curated.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                instr = (row.get("instruction") or "").strip()
                if not instr:
                    continue
                if AUTHORIZATION_NOTE not in instr:
                    instr = f"{instr} {AUTHORIZATION_NOTE}"
                yield {
                    "instruction": instr,
                    "input": (row.get("input") or "").strip(),
                    "output": (row.get("output") or "").strip(),
                    "tags": row.get("tags") or [],
                    "meta": {"source": "curated_tool", "kind": "tool_invocation"},
                }
        return
    for row in _TOOL_INVOCATIONS:
        yield {
            "instruction": row["instruction"] + f" {AUTHORIZATION_NOTE}",
            "input": "",
            "output": row["output"],
            "tags": row.get("tags", []),
            "meta": {"source": "curated_tool", "kind": "tool_invocation"},
        }


# ---------------------------------------------------------------------------
# Reasoning chains — observe→probe, chaining, triage, code review, decisions.
# ---------------------------------------------------------------------------


def iter_reasoning_chains(path: Path | None = None) -> Iterator[dict[str, Any]]:
    """Curated senior-hunter *reasoning* pairs (data/curated/reasoning_chains.jsonl).

    These teach the model to decide the next move from an observation, chain
    findings, triage severity, and review code — the signal that separates a
    thinking operator from a command lookup table. Regenerate the source file
    with `python scripts/build_reasoning_chains.py`.
    """
    src = path or _curated_reasoning_path()
    if not src.is_file():
        return
    with src.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            instr = (row.get("instruction") or "").strip()
            out = (row.get("output") or "").strip()
            if not instr or len(out) < MIN_OUTPUT_CHARS:
                continue
            if AUTHORIZATION_NOTE not in instr:
                instr = f"{instr} {AUTHORIZATION_NOTE}"
            kind = row.get("kind") or "reasoning"
            tags = row.get("tags") or infer_tags(instr + " " + out)
            yield {
                "instruction": instr,
                "input": (row.get("input") or "").strip(),
                "output": _trim(out),
                "tags": tags,
                "meta": {"source": "reasoning_chain", "kind": f"reasoning_{kind}"},
            }


# ---------------------------------------------------------------------------
# Disclosed reports (HackerOne .json + Bugreader) -> reasoning-framed pairs.
# ---------------------------------------------------------------------------


def _iter_raw_records(raw_paths: list[Path]) -> Iterator[dict[str, Any]]:
    for p in raw_paths:
        if not p or not p.is_file():
            continue
        with p.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue


def _report_reasoning_row(rec: dict[str, Any], source: str) -> dict[str, Any] | None:
    """Turn one disclosed report record into a single reasoning-framed pair.

    Gold output is the real disclosed body (grounded, not synthesized); the
    instruction reframes it as a transferable "brief me + how to hunt similar"
    task so the model learns methodology, not just recall.
    """
    text = (rec.get("text") or "").strip()
    if len(text) < MIN_OUTPUT_CHARS:
        return None
    title = (rec.get("title") or "").strip() or "a disclosed finding"
    program = (rec.get("program") or rec.get("host") or "").strip()
    asset = (rec.get("asset") or program or "the target").strip()
    meta = rec.get("meta") or {}
    url = (rec.get("url") or meta.get("url") or "").strip()
    tags = rec.get("tags") or infer_tags(f"{title} {text[:2000]}")
    bug_class = tags[0] if tags else "web"
    prog_txt = f" on **{program}**" if program else ""
    instruction = (
        f"Study how this **{bug_class}** issue was found and disclosed{prog_txt} "
        f'("{title}"), then brief me like a teammate: the attacker primitive, the '
        f"reproduction, the impact, and how I would hunt the same bug class on a new "
        f"authorized target. Keep requests, payloads, and commands in fenced blocks. "
        f"{AUTHORIZATION_NOTE}"
    )
    input_lines = [f"Title: {title}", f"Asset / Program: {asset}", f"Bug class: {bug_class}"]
    if url:
        input_lines.append(f"Reference: {url}")
    return {
        "instruction": instruction,
        "input": "\n".join(input_lines) + "\n",
        "output": _trim(text),
        "tags": tags or [bug_class],
        "meta": {
            "source": f"report_reasoning_{source}",
            "title": title,
            "url": url,
            "kind": f"report_reasoning_{source}",
        },
    }


def iter_report_reasoning(
    raw_paths: list[Path],
    *,
    bugreader_cap: int | None = None,
    hackerone_cap: int | None = 700,
) -> Iterator[dict[str, Any]]:
    """Emit reasoning-framed pairs from disclosed reports.

    Bugreader records (`meta.bugreader`) and HackerOne `.json` records
    (`meta.hackerone_json`) are surfaced under a "brief me + hunt similar"
    instruction. Bugreader is processed first and uncapped by default so the
    user's own circle of reports is always represented; HackerOne is capped to
    avoid swamping the dataset. Dedup by title keeps near-identical reposts out.
    """
    records = list(_iter_raw_records(raw_paths))
    seen_titles: set[str] = set()

    def _emit(is_bugreader: bool, cap: int | None) -> Iterator[dict[str, Any]]:
        n = 0
        for rec in records:
            if cap is not None and n >= cap:
                break
            meta = rec.get("meta") or {}
            if is_bugreader and not meta.get("bugreader"):
                continue
            if not is_bugreader and not meta.get("hackerone_json"):
                continue
            title_key = (rec.get("title") or "").strip().lower()[:80]
            if title_key and title_key in seen_titles:
                continue
            row = _report_reasoning_row(rec, "bugreader" if is_bugreader else "hackerone")
            if row is None:
                continue
            if title_key:
                seen_titles.add(title_key)
            n += 1
            yield row

    yield from _emit(True, bugreader_cap)
    yield from _emit(False, hackerone_cap)


# ---------------------------------------------------------------------------
# Personal reports — user's own bug bounty drafts.
# ---------------------------------------------------------------------------


def iter_personal_reports(record: dict[str, Any]) -> Iterator[dict[str, Any]]:
    title = record.get("title") or ""
    asset = record.get("asset") or ""
    bug_class = record.get("bug_class") or ""
    program = record.get("program") or "the program"
    severity = record.get("severity") or "unspecified"
    sections = record.get("sections") or {}
    full_body = (record.get("text") or "").strip()
    if not title or len(full_body) < 200:
        return
    tags = infer_tags(title + " " + bug_class + " " + full_body) or ([bug_class] if bug_class else [])
    # Personal reports get a larger output budget — there are very few of them and
    # the full thread (your own voice + your reasoning) is the gold signal here.
    personal_trim = max(MAX_OUTPUT_CHARS, 12000)

    # Pair 1: write the full report -- the user's actual offensive style is the gold output.
    yield {
        "instruction": (
            f"Write a bug bounty report for **{title}** affecting **{asset}** "
            f"(program: {program}, suspected severity: {severity}). Use a structure with "
            f"Summary, Reconnaissance, Steps to reproduce, Exploit/PoC, Impact, and "
            f"Suggested remediation. Be specific -- include requests, parameters, and "
            f"the exact payload that worked. {AUTHORIZATION_NOTE}"
        ),
        "input": f"Title: {title}\nAsset: {asset}\nBug class: {bug_class}\n",
        "output": _trim(full_body, limit=personal_trim),
        "tags": tags,
        "meta": {"source": "personal_report", "title": title, "asset": asset, "kind": "personal_full"},
    }

    # Pair 2: methodology recap -- if we parsed a recon section, ask for it.
    recon = (sections.get("recon") or "").strip()
    steps = (sections.get("steps") or "").strip()
    if recon and steps:
        body = f"## Reconnaissance\n{recon}\n\n## Steps to reproduce\n{steps}"
        yield {
            "instruction": (
                f"I'm hunting on **{asset}** and suspect a **{bug_class or 'web'}** bug similar "
                f"to *{title}*. Walk me through the recon and the minimum reproduction sequence. "
                f"{AUTHORIZATION_NOTE}"
            ),
            "input": f"Target asset: {asset}\nSuspected bug class: {bug_class}\n",
            "output": _trim(body, limit=personal_trim),
            "tags": tags,
            "meta": {"source": "personal_report", "title": title, "kind": "personal_methodology"},
        }

    # Pair 3: impact framing.
    impact = (sections.get("impact") or "").strip()
    if impact:
        yield {
            "instruction": (
                f"For a finding titled *{title}* on **{asset}**, draft the **Impact** section of "
                f"the report -- concrete capability gained, blast radius, and severity rationale. "
                f"{AUTHORIZATION_NOTE}"
            ),
            "input": f"Title: {title}\nAsset: {asset}\nBug class: {bug_class}\n",
            "output": _trim(impact, limit=personal_trim),
            "tags": tags,
            "meta": {"source": "personal_report", "title": title, "kind": "personal_impact"},
        }

    # Pair 4: exploit / PoC isolated.
    exploit = (sections.get("exploit") or "").strip()
    if exploit:
        yield {
            "instruction": (
                f"Give me the minimal exploit / PoC for the **{bug_class or 'web'}** issue "
                f"described in *{title}* on **{asset}** -- a copy-pasteable request or command. "
                f"{AUTHORIZATION_NOTE}"
            ),
            "input": f"Title: {title}\nAsset: {asset}\nBug class: {bug_class}\n",
            "output": _trim(exploit, limit=personal_trim),
            "tags": tags,
            "meta": {"source": "personal_report", "title": title, "kind": "personal_exploit"},
        }

    # Pair 5: brief / one-paragraph elevator pitch -- useful for "tell me about <title>" style queries.
    summary = (sections.get("summary") or "").strip()
    if summary and len(summary) >= 100:
        yield {
            "instruction": (
                f"Brief me on the **{title}** finding -- one paragraph, "
                f"what an attacker can do and why a triager should care. {AUTHORIZATION_NOTE}"
            ),
            "input": f"Title: {title}\nAsset: {asset}\n",
            "output": _trim(summary, limit=2000),
            "tags": tags,
            "meta": {"source": "personal_report", "title": title, "kind": "personal_summary"},
        }


def iter_personal_jsonl(raw_path: Path) -> Iterator[dict[str, Any]]:
    if not raw_path.exists():
        return
    with raw_path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("source") != "personal_report":
                continue
            yield from iter_personal_reports(rec)


# ---------------------------------------------------------------------------
# Top-level driver.
# ---------------------------------------------------------------------------


def write_v3_extra(
    out_jsonl: Path,
    *,
    patt_root: Path | None,
    nuclei_root: Path | None,
    personal_jsonl: Path | None,
    reasoning_jsonl: Path | None = None,
    report_reasoning_paths: list[Path] | None = None,
    hackerone_cap: int | None = 700,
    nuclei_max_per_dir: int = 8,
) -> dict[str, int]:
    """Write *only* the v3-new buckets (does not touch v2 buckets)."""
    out_jsonl.parent.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = {}
    n = 0
    with out_jsonl.open("w", encoding="utf-8") as w:
        sources: list[Iterator[dict[str, Any]]] = []
        if patt_root and patt_root.is_dir():
            sources.append(iter_patt_payload_sections(patt_root))
            sources.append(iter_patt_intruder_lists(patt_root))
        if nuclei_root and nuclei_root.is_dir():
            sources.append(iter_nuclei_templates(nuclei_root, max_per_dir=nuclei_max_per_dir))
        sources.append(iter_tool_invocations())
        sources.append(iter_reasoning_chains(reasoning_jsonl))
        report_paths = [p for p in (report_reasoning_paths or []) if p and p.is_file()]
        if report_paths:
            sources.append(iter_report_reasoning(report_paths, hackerone_cap=hackerone_cap))
        if personal_jsonl and personal_jsonl.exists():
            sources.append(iter_personal_jsonl(personal_jsonl))

        for src in sources:
            for row in src:
                w.write(json.dumps(row, ensure_ascii=False) + "\n")
                n += 1
                kind = (row.get("meta") or {}).get("kind", "?")
                counts[kind] = counts.get(kind, 0) + 1
    counts["_total"] = n
    return counts
