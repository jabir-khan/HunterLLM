# HackerOne disclosed reports — how to ingest

## Why ``collect-urls`` fails (`0 chars`)

The public report URL (`/reports/<id>`) returns **HTML that is mostly a React shell**.
**``trafilatura``** extracts almost nothing (~0–120 characters), which is below the
pipeline minimum (200 chars), so you see **`skipped N/N`**.

Datacenter IPs can also hit **Cloudflare 403** on plain GET.

## What works instead: **`/reports/<id>.json`**

HackerOne serves a JSON document alongside each report page. It contains at least:

- **`vulnerability_information`** — Markdown from the researcher
- **`summaries`** — Optional team/researcher disclosure blurbs (often richer)

### Command

From the repo root (polite pacing is built-in, ~0.55s between requests):

```bash
hunter-llm collect-h1-json --urls-file data/urls/hackerone_top_reports.txt
```

**Smoke test** (first 15 IDs only):

```bash
hunter-llm collect-h1-json --limit 15
```

**Merge** into ``data/raw/urls_writeups.jsonl`` — default is **append** so you don't wipe other URL ingests:

```bash
hunter-llm collect-h1-json
```

**Fresh file** with only H1 rows:

```bash
hunter-llm collect-h1-json --replace-out --out data/raw/hackerone_writeups.jsonl
```

Rebuild processed data afterwards (e.g. ``build-dataset-v3``).

### Terms

Follow [HackerOne Terms](https://www.hackerone.com/terms) and each program policy.
Only use **actually disclosed**, public narratives you are entitled to automate at
your scale (~2k polite requests).

### Debugging HTML / Cloudflare anyway

```bash
hunter-llm collect-urls data/urls/hackerone_top_reports.txt --verbose-skips 5
```

For bulk training text, **`collect-h1-json` is the correct path.**
