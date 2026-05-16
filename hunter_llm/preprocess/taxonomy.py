"""Lightweight OWASP-oriented tagging from free text."""

from __future__ import annotations

import re

_PATTERNS: list[tuple[str, list[str]]] = [
    (r"\bxss\b|cross-site scripting", ["XSS"]),
    (r"\bsqli\b|sql injection|' ?or ?'1'?='?1", ["SQLi"]),
    (r"\bssrf\b|server-side request forgery", ["SSRF"]),
    (r"\bidor\b|insecure direct object", ["IDOR"]),
    (r"\bcsrf\b|cross-site request forgery", ["CSRF"]),
    (r"\brce\b|remote code execution|code execution", ["RCE"]),
    (r"\blfi\b|local file inclusion|path traversal|\.\./", ["PathTraversal", "LFI"]),
    (r"\brfi\b|remote file inclusion", ["RFI"]),
    (r"\bxxe\b|xml external entity", ["XXE"]),
    (r"\bssti\b|template injection", ["SSTI"]),
    (r"\bopen redirect\b|redirect_uri", ["OpenRedirect"]),
    (r"\bbusiness logic\b|race condition", ["BusinessLogic"]),
    (r"\bjwt\b|json web token", ["JWT"]),
    (r"\boauth\b", ["OAuth"]),
    (r"\bsaml\b", ["SAML"]),
    (r"\bdeserialization\b|pickle\b|yaml\.load", ["Deserialization"]),
    (r"\bprototype pollution\b", ["PrototypePollution"]),
    (r"\bgraphql\b", ["GraphQL"]),
    (r"\bclickjacking\b|x-frame-options", ["Clickjacking"]),
    (r"\bcors\b", ["CORS"]),
    (r"\bcsp\b|content-security-policy", ["CSP"]),
]


def infer_tags(text: str) -> list[str]:
    t = text.lower()
    found: list[str] = []
    seen: set[str] = set()
    for pat, labels in _PATTERNS:
        if re.search(pat, t, re.IGNORECASE):
            for lb in labels:
                if lb not in seen:
                    seen.add(lb)
                    found.append(lb)
    return found
