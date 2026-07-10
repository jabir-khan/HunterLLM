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
    (r"\baccess control\b|broken access|authorization bypass|authz|403 bypass|forced browsing", ["AccessControl"]),
    (r"\bauth(?:entication)? bypass\b|auth bypass|login bypass", ["AuthBypass"]),
    (r"\baccount takeover\b|\bato\b|takeover", ["ATO"]),
    (r"\bbola\b|broken object level", ["IDOR", "BOLA"]),
    (r"\bcommand injection\b|os command|shell injection|rce via", ["RCE", "CommandInjection"]),
    (r"\binfo(?:rmation)? (?:leak|disclosure)\b|verbose error|stack trace|debug=true", ["InfoLeak"]),
    (r"\bbrute ?force\b|credential stuffing|password spray", ["BruteForce"]),
    (r"\btiming attack\b|constant.time|timing side.channel", ["TimingAttack"]),
    (r"\bcrypto\b|cryptograph|weak (?:hash|cipher)|secret_key|hardcoded secret", ["Crypto"]),
    (r"\brace condition\b|toctou|double spend", ["RaceCondition"]),
    (r"\bcache poison|web cache", ["CachePoisoning"]),
    (r"\bsubdomain takeover\b|dangling (?:dns|cname)", ["SubdomainTakeover"]),
    (r"\bfile upload\b|unrestricted upload|arbitrary file write", ["FileUpload"]),
    (r"\brecon\b|enumeration|attack surface|subdomain enum", ["Recon"]),
    (r"\bmethodology\b|prioriti|triage|scope", ["Methodology"]),
    # OWASP Top 10 for LLM Applications
    (r"\bprompt injection\b|jailbreak|ignore (?:previous|all) instructions|indirect injection", ["LLM", "PromptInjection"]),
    (r"\bsystem prompt\b|leak the prompt|reveal your (?:instructions|prompt)", ["LLM", "SystemPromptLeak"]),
    (r"\bexcessive agency\b|over[- ]?privileged (?:agent|tool)|unbounded tool", ["LLM", "ExcessiveAgency"]),
    (r"\binsecure output handling\b|improper output handling|unsanitized llm output", ["LLM", "InsecureOutputHandling"]),
    (r"\bmodel poison|data poison|training data poison", ["LLM", "DataPoisoning"]),
    (r"\brag\b|retrieval[- ]augmented|vector (?:store|db|database)|embedding (?:inversion|leak)", ["LLM", "RAG"]),
    (r"\bunbounded consumption\b|model dos|denial of wallet|token flood", ["LLM", "UnboundedConsumption"]),
    (r"\bsensitive information disclosure\b.*llm|llm.*data leak|pii in (?:completion|response)", ["LLM", "SensitiveDataDisclosure"]),
    (r"\bhallucinat|llm misinformation|overreliance", ["LLM", "Misinformation"]),
    (r"\bllm supply chain\b|poisoned model|malicious (?:adapter|lora|gguf)|pickle model", ["LLM", "SupplyChain"]),
    (r"\bagent(?:ic)?\b.*(?:tool|function call)|tool[- ]?calling abuse", ["LLM", "AgentAbuse"]),
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
