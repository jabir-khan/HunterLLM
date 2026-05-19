# Personal bug bounty reports — private training data

This folder holds **your own** bug bounty reports / pentest notes that get
mixed into the v3 SFT dataset. Files here are **gitignored** and never
pushed to GitHub. They go to the RunPod only as part of the HF dataset
push and live in a private HF dataset repo.

## Why this is the most valuable data we have

Every other source teaches the model how *other people* write *about*
finding bugs. Your own reports teach it **your offensive style on the
exact assets you'll point it at later** (Facebook / Meta surface in
particular). 50 of your reports are worth more than 5,000 random Medium
write-ups for that use-case.

## Target volume (v3 training)

Aim for **20–50** triager-ready reports in `reports/` before the training run.
Each file becomes **3–5** SFT pairs (full report, methodology, impact, exploit).
Four reports ≈ ~15 training rows; fifty reports ≈ ~150–250 rows and dominates
your voice in the mix.

Check progress:

```bash
ls data/personal/reports/*.md | wc -l    # exclude _template.md
hunter-llm collect-personal
```

## What to drop in `reports/`

One `.md` file per bug. Filename can be anything (e.g.
`fb_2024_oauth_redirect.md`). Use the template at `reports/_template.md`.
Keep the structure — the ingester parses the headings.

You don't have to fill *every* section. Bare minimum that's useful:
**Title**, **Asset**, **Steps to reproduce**, **Impact**. Bounty / dates
are optional.

## Sanitisation checklist before saving

Strip these from each report before saving it here (the ingester will
warn on obvious leaks but it's not perfect):

- Real session cookies, JWTs, access tokens, refresh tokens.
- Internal Meta employee emails / FB internal hostnames not in the
  public scope page.
- Other researchers' PII you may have stumbled on during the bug.
- Screenshot file paths if they point to private buckets / Drive shares.

Keep:

- Public URLs (e.g. `https://www.facebook.com/...`, `graph.facebook.com`).
- The vulnerable parameter / request shape.
- Your reasoning / methodology — that's the gold.
- Bounty amount if you're OK with it; otherwise replace with "TBD".

## Ingesting

**Local markdown** (your private notes):

```bash
hunter-llm collect-personal
```

**Bugreader circle** (your public profile + friends on [Bugreader](https://bugreader.com/jabir0x0)):

Edit `data/urls/bugreader_circle.txt` (usernames), then:

```bash
hunter-llm collect-bugreader-circle
```

This merges Bugreader bodies + local `reports/*.md` into
`data/raw/personal_reports.jsonl`. The v3 builder emits 3–5 task-shaped
pairs per report (full report, methodology, impact, exploit snippets).

## Privacy guarantees

- `data/personal/reports/` is in `.gitignore` — never committed to GitHub.
- The HF dataset we push for training will be **set to private**.
- After training, your reports stay on your laptop + the RunPod (which
  gets destroyed). The merged model never re-emits raw training rows
  verbatim *unless* a prompt closely matches one — for a 72B model
  trained on ~30k pairs at low LR for 1 epoch, this is a small but
  non-zero risk. If you have reports that are NDA-bound or otherwise
  must never echo back, **do not put them in this folder.**
