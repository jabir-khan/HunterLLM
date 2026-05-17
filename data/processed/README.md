---
license: cc-by-sa-4.0
language:
- en
tags:
- security
- bug-bounty
- offensive-security
- red-team
- instruction-tuning
- dpo
- cisa-kev
- mitre-attack
task_categories:
- text-generation
- question-answering
size_categories:
- 10K<n<100K
pretty_name: HunterLLM SFT v1
---

# HunterLLM SFT v1

Instruction + preference dataset for training a bug-bounty / offensive-security
assistant that thinks like a red-teamer, prioritizes attacker primitives and
reachable impact, and writes triager-friendly reports — strictly scoped to
**authorized engagements** (bug bounty programs, contracted pentests, isolated
labs).

## Files

| File | Rows | Schema |
|---|---|---|
| `sft_train.jsonl` | ~33.1k | `{instruction, input, output, tags, meta}` |
| `dpo_pairs.jsonl` | ~33.1k | `{prompt, chosen, rejected}` |

## Sources (raw)

| Source family | Provider | Records (raw) | License |
|---|---|---|---|
| GitHub repos (26 curated) | Various | ~20.6k files | MIT / Apache-2.0 / CC-BY-SA-4.0 / BSD / CC-BY-4.0 / Public Domain |
| NVD API 2.0 | NIST | ~3.5k CVEs (90 day window) | Public domain |
| **CISA KEV catalog** | DHS CISA | ~1.6k actively-exploited CVEs | Public domain |
| **MITRE ATT&CK** (Enterprise) | MITRE | ~697 techniques | Apache-2.0 |
| **Curated writeup URLs** | trafilatura-extracted | ~28 long-form research posts | Per-site (text excerpts only, provenance in `meta`) |

### GitHub repos used

OWASP/CheatSheetSeries, OWASP/wstg, OWASP/ASVS, OWASP/owasp-mastg, OWASP/API-Security,
OWASP/Top10, swisskyrepo/PayloadsAllTheThings, swisskyrepo/InternalAllTheThings,
danielmiessler/SecLists (filtered), projectdiscovery/nuclei-templates,
rapid7/metasploit-framework (docs only), reddelexc/hackerone-reports (indexes only),
nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters, jhaddix/tbhm,
Hari-prasaanth/Web-App-Pentest-Checklist, harshinsecurity/web-pentesting-checklist,
dwisiswant0/awesome-oneliner-bugbounty, infoslack/awesome-web-hacking,
EdOverflow/bugbounty-cheatsheet, ngalongc/bug-bounty-reference,
Ignitetechnologies/Mindmap, 0xInfection/Awesome-WAF,
bugcrowd/vulnerability-rating-taxonomy, devanshbatham/Awesome-Bugbounty-Writeups,
kh4sh3i/Bug-Bounty-Writeups, qazbnm456/awesome-web-security.

### Writeup URL hosts

portswigger.net (Research blog), googleprojectzero.blogspot.com,
blog.doyensec.com, research.nccgroup.com, bishopfox.com,
posts.specterops.io, blog.assetnote.io, labs.detectify.com,
blog.detectify.com, projectdiscovery.io, github.blog, snyk.io,
www.acunetix.com, owasp.org.

## Instruction synthesis

Per-source specialized templates produce diverse training signals:

- **GitHub generic:** `hunt_plan`, `code_review`, `report_draft`.
- **GitHub specialized:** Metasploit module → exploitation + proof-of-impact +
  adjacent surfaces. HackerOne report-index row → infer primitive + hunt strategy
  + report skeleton. Nuclei template → matcher analysis + weaponization +
  adjacent templates. OWASP doc → focused triple-template.
- **NVD CVE:** three templates per CVE — `triage` (offensive root cause), `hunt`
  (fingerprint + evidence), `report` (HackerOne-style skeleton).
- **CISA KEV:** "actively-exploited" priority framing with vendor/product
  fingerprinting and severity uplift narrative.
- **MITRE ATT&CK:** TTP → offensive operator framing (kill-chain phase, evidence,
  defender telemetry to expect).
- **URL writeups:** offensive distillation of research posts (attacker
  playbook + impact stack + replay strategy).

Every instruction carries the `AUTHORIZATION_NOTE` so the model learns to keep
work scoped to authorized targets.

## Curation pipeline

1. Quality scoring penalizes config/build files, short or low-prose inputs,
   pure YAML/key-value blobs.
2. MinHash LSH deduplication at threshold 0.85 (datasketch).
3. Tag inference on bug-class keywords — XSS, SQLi, RCE, SSRF, XXE,
   Deserialization, OAuth, GraphQL, PathTraversal/LFI/RFI, CSRF, CSP, CORS,
   IDOR, etc.

## DPO pair synthesis

For each curated SFT row we keep the original `output` as `chosen` and
synthesize a deliberately weaker / over-cautious `rejected` response, training
the model to prefer concrete attacker-primitive reasoning over generic
defensive boilerplate.

## Intended use

- Fine-tuning small/mid open LLMs (Llama-3-8B-Instruct, Mistral-7B-Instruct,
  DeepSeek-Coder, etc.) for bug-bounty mentoring, report drafting, and
  attacker-primitive analysis on authorized targets.
- Not intended for unauthorized testing, weaponization against third parties,
  or evasion of program rules.

## Limitations & known biases

- HackerOne report titles are public metadata only; the dataset does **not**
  contain disclosed report bodies.
- Public writeup extraction is best-effort (some sites JS-render or block
  scrapers); failed URLs are silently skipped.
- Quality filter is heuristic; a small fraction of low-signal rows remain.
- Built on a single NVD lookback window — extend with `hunter-llm collect-nvd
  --years N` for longer coverage.
- CISA KEV uses templated short descriptions; MinHash dedup drops ~70% of
  entries as near-duplicates by design (the 482 surviving rows still represent
  the breadth of vendor/product/CVE primitives).

## Reproducibility

Generated by [HunterLLM](https://github.com/jabir-khan/HunterLLM):

```bash
hunter-llm bootstrap-data --skip-trickest --full \
    --urls data/urls/writeups.txt
# Or piecewise:
hunter-llm collect-github --skip-trickest
hunter-llm collect-nvd --years 3
hunter-llm collect-cisa-kev
hunter-llm collect-mitre-attack
hunter-llm collect-urls data/urls/writeups.txt
hunter-llm build-dataset
hunter-llm export-dpo
```

## License

CC-BY-SA-4.0, matching the most restrictive permissive source license in the
mix (OWASP). Underlying sources retain their respective licenses; provenance
is preserved in `meta`.
