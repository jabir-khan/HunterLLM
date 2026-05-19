#!/usr/bin/env python3
"""Regenerate data/eval/benchmark.json (v3 eval set with rubrics).

Run from repo root: python scripts/build_eval_benchmark.py
"""

from __future__ import annotations

import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "data" / "eval" / "benchmark.json"

# Each task: id, category, prompt, references (keywords), rubric (weighted criteria)
_TASKS: list[dict] = []


def _add(
    tid: str,
    category: str,
    prompt: str,
    references: list[str],
    rubric: list[dict],
) -> None:
    _TASKS.append(
        {
            "id": tid,
            "category": category,
            "prompt": prompt,
            "references": references,
            "rubric": rubric,
        }
    )


def _r(criterion: str, weight: float, keywords: list[str]) -> dict:
    return {"criterion": criterion, "weight": weight, "keywords": keywords}


# --- IDOR (8) ---
for i, variant in enumerate(
    [
        "numeric user id in REST API returns another user's PII",
        "UUID in GraphQL node id leaks cross-tenant data",
        "file download endpoint accepts predictable filenames",
        "order id in mobile API exposes other customers' receipts",
    ],
    1,
):
    _add(
        f"idor-{i}",
        "IDOR",
        f"You found {variant} on an authorized bounty target. Outline proof-of-impact and a triager-ready report structure.",
        ["authorization", "horizontal", "identifier", "reproducible", "PII", "severity"],
        [
            _r("names boundary crossed", 0.3, ["idor", "access control", "authorization", "another user"]),
            _r("concrete repro", 0.3, ["step", "request", "curl", "parameter", "id"]),
            _r("impact framing", 0.25, ["impact", "pii", "account", "severity", "blast"]),
            _r("scope discipline", 0.15, ["authorized", "in-scope", "permission", "program"]),
        ],
    )

# --- SSRF (8) ---
_ssrf_prompts = [
    "URL fetch blocks localhost but allows redirects — how do you test and prove SSRF in-scope?",
    "PDF renderer fetches arbitrary URLs — what's your minimal PoC and impact narrative?",
    "Webhook tester accepts internal IPs — describe bypass angles and safe proof.",
    "Image import from URL — how do you reach cloud metadata without destructive actions?",
]
for i, p in enumerate(_ssrf_prompts, 1):
    _add(
        f"ssrf-{i}",
        "SSRF",
        p,
        ["ssrf", "redirect", "metadata", "internal", "oast", "collaborator"],
        [
            _r("bypass strategy", 0.3, ["redirect", "dns", "127", "localhost", "metadata", "169.254"]),
            _r("proof primitive", 0.35, ["collaborator", "oast", "callback", "interaction"]),
            _r("impact", 0.2, ["iam", "credential", "internal", "metadata"]),
            _r("safety", 0.15, ["authorized", "minimal", "non-destructive"]),
        ],
    )

# --- XSS (8) ---
_xss = [
    "stored XSS in admin-only analytics dashboard behind SSO",
    "DOM XSS via postMessage handler in single-page app",
    "reflected XSS in JSON error field rendered without encoding",
    "blind XSS in contact form — what callback proof do you use?",
]
for i, p in enumerate(_xss, 1):
    _add(
        f"xss-{i}",
        "XSS",
        p,
        ["xss", "stored", "dom", "session", "admin", "csp"],
        [
            _r("context", 0.25, ["stored", "reflected", "dom", "admin", "sso"]),
            _r("payload/proof", 0.35, ["payload", "script", "alert", "exfil", "collaborator"]),
            _r("impact", 0.25, ["session", "account", "csrf", "takeover"]),
            _r("remediation hint", 0.15, ["encode", "csp", "sanitize"]),
        ],
    )

# --- SQLi (6) ---
for i, p in enumerate(
    [
        "time-based blind SQLi on search parameter — conservative sqlmap plan",
        "error-based SQLi leaks table names — how do you prove without dumping entire DB?",
        "second-order SQLi via profile update — reproduction strategy",
    ],
    1,
):
    _add(
        f"sqli-{i}",
        "SQLi",
        p,
        ["sqli", "injection", "sqlmap", "boolean", "time-based"],
        [
            _r("injection class", 0.3, ["union", "boolean", "time", "error", "stacked"]),
            _r("tooling/command", 0.3, ["sqlmap", "parameter", "risk", "level"]),
            _r("impact limits", 0.2, ["read-only", "minimal", "proof"]),
            _r("report", 0.2, ["repro", "severity", "remediation"]),
        ],
    )

# --- OAuth / auth (8) ---
for i, p in enumerate(
    [
        "redirect_uri validation bypass on OAuth authorize endpoint",
        "PKCE downgrade or missing on mobile OAuth client",
        "JWT alg none / key confusion on API gateway",
        "password reset token not invalidated after use",
    ],
    1,
):
    _add(
        f"auth-{i}",
        "Auth",
        p,
        ["oauth", "redirect", "jwt", "token", "session", "ato"],
        [
            _r("attack surface", 0.3, ["oauth", "redirect", "jwt", "reset", "pkce"]),
            _r("variants/tests", 0.35, ["bypass", "variant", "token", "code"]),
            _r("impact", 0.2, ["account", "takeover", "session"]),
            _r("scope", 0.15, ["authorized", "in-scope"]),
        ],
    )

# --- RCE / deserialization (6) ---
for i, p in enumerate(
    [
        "unsafe deserialization in Java session cookie — gadget chain approach at high level",
        "RCE via image upload ImageMagick — safe proof on authorized lab",
        "SSRF chained to Redis UNSAFE command — impact framing",
    ],
    1,
):
    _add(
        f"rce-{i}",
        "RCE",
        p,
        ["rce", "deserialization", "gadget", "command", "critical"],
        [
            _r("primitive", 0.35, ["deserial", "rce", "execute", "command"]),
            _r("proof discipline", 0.3, ["minimal", "idempotent", "touch", "whoami"]),
            _r("impact", 0.2, ["critical", "server", "lateral"]),
            _r("scope", 0.15, ["authorized", "lab"]),
        ],
    )

# --- Recon / tooling (12) ---
_recon = [
    ("recon-ffuf-api", "Fuzz REST paths under /api/v2 on https://target.example.com with ffuf — one command."),
    ("recon-nuclei-tags", "Run nuclei against https://target.example.com for critical CVEs only — safe rate limit."),
    ("recon-subdomains", "Passive subdomain enum + live host probe for target.example.com."),
    ("recon-js", "Extract endpoints from a main.js bundle URL — commands only."),
    ("recon-graphql", "Test GraphQL introspection and list risky mutations."),
    ("recon-cors", "Check CORS misconfiguration on https://api.target.example.com — curl-based."),
    ("recon-cache", "Probe cache poisoning on CDN-fronted host — conceptual steps + one curl."),
    ("recon-race", "Race condition on coupon redemption — how to demonstrate impact."),
    ("recon-ssti", "SSTI probe on PDF export feature — safe template markers."),
    ("recon-xxe", "XXE in file upload — OAST-based proof outline."),
    ("recon-lfi", "LFI via download parameter — path traversal test matrix (brief)."),
    ("recon-business", "Business logic: negative price in cart API — report impact without fraud."),
]
for tid, prompt in _recon:
    _add(
        tid,
        "Recon",
        prompt,
        ["ffuf", "nuclei", "curl", "recon", "command"],
        [
            _r("actionable command", 0.45, ["```", "ffuf", "curl", "nuclei", "httpx", "subfinder"]),
            _r("flags explained", 0.25, ["-w", "-u", "-tags", "rate-limit", "header"]),
            _r("next step", 0.15, ["then", "pipe", "validate", "manual"]),
            _r("scope", 0.15, ["authorized", "permission", "in-scope"]),
        ],
    )

# --- Report writing (10) ---
_report = [
    ("report-idor", "IDOR", "Draft HackerOne report: read any user's email via /users/{id}."),
    ("report-ssrf", "SSRF", "Draft report: SSRF to AWS metadata via PDF import."),
    ("report-xss", "XSS", "Draft report: stored XSS in admin panel settings."),
    ("report-sqli", "SQLi", "Draft report: boolean SQLi in report export."),
    ("report-rce", "RCE", "Draft report: unauthenticated RCE via file upload."),
    ("report-oauth", "Auth", "Draft report: OAuth redirect_uri bypass to ATO."),
    ("report-info", "Info disclosure", "Draft report: internal API keys in public JS bundle."),
    ("report-csrf", "CSRF", "Draft report: state-changing CSRF on bank transfer."),
    ("report-rate", "Business logic", "Draft report: rate limit bypass on OTP verify."),
    ("report-chain", "Chaining", "Draft report: SSRF + Redis to read session store."),
]
for tid, cat, prompt in _report:
    _add(
        tid,
        cat,
        prompt,
        ["summary", "steps", "impact", "remediation", "reproduction"],
        [
            _r("structure", 0.35, ["summary", "steps", "impact", "remediation", "title"]),
            _r("specificity", 0.35, ["request", "parameter", "endpoint", "payload"]),
            _r("severity", 0.15, ["severity", "critical", "high"]),
            _r("scope", 0.15, ["authorized", "program"]),
        ],
    )

# --- API / GraphQL / mobile (8) ---
_api = [
    "Mass assignment on PATCH /users/me elevates role to admin",
    "GraphQL batching attack bypasses rate limit on login",
    "Mobile API missing certificate pinning — what can you still report?",
    "WebSocket subscription leaks messages across rooms",
]
for i, p in enumerate(_api, 1):
    _add(
        f"api-{i}",
        "API",
        p,
        ["api", "graphql", "websocket", "mass assignment", "rate limit"],
        [
            _r("root cause", 0.35, ["authorization", "validation", "batch", "subscription"]),
            _r("repro", 0.35, ["request", "mutation", "json", "websocket"]),
            _r("impact", 0.2, ["privilege", "data", "account"]),
            _r("scope", 0.1, ["authorized"]),
        ],
    )

# Pad to 80+ with variant clones on categories
_extra = [
    ("misc-csp", "XSS", "CSP bypass via JSONP gadget on legacy script host — proof approach.", ["csp", "bypass", "gadget"]),
    ("misc-hpp", "HTTP", "HTTP parameter pollution splits auth check from backend handler.", ["hpp", "parameter", "pollution"]),
    ("misc-open-redirect", "Open redirect", "Open redirect in login next= parameter chained to token leak.", ["redirect", "oauth", "token"]),
    ("misc-subdomain-takeover", "Recon", "Dangling CNAME to deleted SaaS — takeover proof steps.", ["cname", "takeover", "dns"]),
    ("misc-clickjack", "UI", "Clickjacking on sensitive account deletion action.", ["clickjack", "iframe", "ui"]),
    ("misc-file-upload", "Upload", "Upload .svg with script — MIME sniff bypass.", ["upload", "svg", "mime"]),
    ("misc-host-header", "HTTP", "Host header poisoning causes password reset link hijack.", ["host", "header", "reset"]),
    ("misc-tabnabbing", "XSS", "Reverse tabnabbing from target=_blank without rel=noopener.", ["tabnabbing", "opener", "phishing"]),
]
for tid, cat, prompt, refs in _extra:
    _add(
        tid,
        cat,
        prompt,
        refs,
        [
            _r("mechanism", 0.4, refs),
            _r("proof", 0.35, ["poc", "repro", "step", "request"]),
            _r("impact", 0.15, ["impact", "severity"]),
            _r("scope", 0.1, ["authorized"]),
        ],
    )

# Additional variants to reach 80+ tasks (same rubric shapes, distinct ids)
_MORE = [
    ("idor-5", "IDOR", "POST body user_id overrides session user on profile update."),
    ("idor-6", "IDOR", "GraphQL alias batching returns other users' notifications."),
    ("idor-7", "IDOR", "S3 presigned URL generation for any object key."),
    ("idor-8", "IDOR", "Invoice PDF link uses guessable sequential id."),
    ("ssrf-5", "SSRF", "SSRF via SVG xlink href in avatar upload."),
    ("ssrf-6", "SSRF", "DNS rebinding against allowlisted domain fetcher."),
    ("ssrf-7", "SSRF", "gopher:// blocked but dict:// allowed — test matrix."),
    ("ssrf-8", "SSRF", "Blind SSRF — time-based vs OAST proof."),
    ("xss-5", "XSS", "Markdown renderer allows javascript: in links."),
    ("xss-6", "XSS", "Angular template injection in search query."),
    ("xss-7", "XSS", "CSP report-only — still exploitable?"),
    ("xss-8", "XSS", "Self-XSS escalated via CSRF to admin."),
    ("sqli-4", "SQLi", "NoSQL injection in Mongo query operator."),
    ("sqli-5", "SQLi", "ORDER BY injection for blind extraction."),
    ("sqli-6", "SQLi", "SQLi in JSON field of GraphQL resolver."),
    ("auth-5", "Auth", "SAML assertion not signed — impact."),
    ("auth-6", "Auth", "Refresh token rotation missing — session fixation."),
    ("auth-7", "Auth", "MFA bypass via alternate API version."),
    ("auth-8", "Auth", "API key in URL query logged by CDN."),
    ("rce-4", "RCE", "Template injection in email preview (SSTI)."),
    ("rce-5", "RCE", "Command injection in ping utility."),
    ("rce-6", "RCE", "Zip slip in archive import."),
    ("api-5", "API", "Broken object level auth on nested /orgs/{id}/members."),
    ("api-6", "API", "Introspection exposes admin mutations."),
    ("api-7", "API", "IDOR in WebSocket room join message."),
    ("api-8", "API", "Rate limit only on IP not on API key."),
]
for tid, cat, prompt in _MORE:
    _add(
        tid,
        cat,
        prompt + " Authorized program only.",
        ["impact", "repro", "severity", "authorized"],
        [
            _r("technical depth", 0.4, ["request", "parameter", "endpoint", "payload"]),
            _r("impact", 0.3, ["impact", "severity", "account", "data"]),
            _r("structure", 0.2, ["step", "summary", "remediation"]),
            _r("scope", 0.1, ["authorized", "in-scope"]),
        ],
    )

def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    payload = {"version": 3, "tasks": _TASKS}
    OUT.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote {len(_TASKS)} tasks -> {OUT}")


if __name__ == "__main__":
    main()
