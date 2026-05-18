---
title: "Short bug title — e.g. OAuth open redirect via redirect_uri on www.facebook.com"
asset: "www.facebook.com"          # or graph.facebook.com / instagram.com / m.facebook.com / oculus.com / ...
program: "Meta Bug Bounty"         # or "HackerOne — <program>", "Internal pentest", etc.
severity: "high"                    # low | medium | high | critical
bug_class: "OAuth / open-redirect"  # free-form, e.g. "IDOR", "stored XSS", "GraphQL auth bypass"
bounty_usd: "TBD"                   # number, or "TBD" / "n/a"
date: "2024-08"                     # YYYY-MM or YYYY-MM-DD; optional
references:                          # optional public references
  - "https://example.com/related-writeup"
---

## Summary
One paragraph: what the bug is, what an attacker gains, on what asset.

## Reconnaissance / discovery
How you found it. What you were looking at. What pivot led you here.
Be specific — endpoint names, parameter names, JS bundle hashes,
GraphQL operations. This is the part the model needs to learn most.

## Steps to reproduce
1. ...
2. ...
3. ...

Inline requests with code fences:

```http
GET /api/v1/whatever?id=123 HTTP/1.1
Host: www.example.com
Authorization: Bearer <REDACTED>
```

And responses:

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"id":123,"email":"victim@example.com"}
```

## Exploit / PoC
The minimal payload or chain. Include the exact strings.

```
curl -X POST https://target/whatever \
  -H 'Content-Type: application/json' \
  -d '{"id":"../admin"}'
```

## Impact
- What data / capability the attacker ends up with.
- User / role boundary crossed.
- Blast radius (single user, tenant, global).

## What I tried that didn't work (optional, very high signal)
- Variant X — blocked by server-side check Z.
- Variant Y — caused 500 but not exploitable.

## Suggested remediation (optional)
Short, constructive. What you told the program.

## Outcome (optional)
- Triage time, severity assigned, bounty range, lessons learned.
