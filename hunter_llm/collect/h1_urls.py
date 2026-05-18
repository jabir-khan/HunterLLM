"""Build a curated subset of disclosed HackerOne report URLs from the
`reddelexc/hackerone-reports` CSV index. We don't scrape HackerOne directly
here — the existing `collect-urls` command does that once the URL list is in
place. The HackerOne site is Cloudflare-fronted and rejects most datacenter
IPs with 403, so the user should run `collect-urls hackerone_top_reports.txt`
from a residential connection.
"""

from __future__ import annotations

import csv
from pathlib import Path


def build_h1_subset(
    csv_path: Path,
    out_path: Path,
    *,
    min_upvotes: int = 20,
    max_rows: int = 2000,
    require_bounty: bool = False,
) -> int:
    """Pick the cream of disclosed H1 reports by community signal.

    Sort key: bounty (high first) then upvotes — so paid + community-validated
    rises above novelty.
    """
    rows: list[tuple[int, float, str, str, str]] = []
    with csv_path.open(encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            try:
                upv = int(r.get("upvotes") or 0)
            except ValueError:
                upv = 0
            try:
                bty = float(r.get("bounty") or 0)
            except ValueError:
                bty = 0.0
            if upv < min_upvotes:
                continue
            if require_bounty and bty <= 0:
                continue
            link = (r.get("link") or "").strip()
            if not link:
                continue
            if not link.startswith("http"):
                link = "https://" + link.lstrip("/")
            rows.append((upv, bty, r.get("program", ""), r.get("title", ""), link))

    rows.sort(key=lambda x: (x[1], x[0]), reverse=True)
    rows = rows[:max_rows]

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as w:
        w.write(
            "# Curated HackerOne disclosed reports (top picks by bounty + upvotes).\n"
            f"# Generated from reddelexc/hackerone-reports CSV. Limit: {max_rows}, min_upvotes: {min_upvotes}.\n"
            "# HackerOne datacenter IPs return 403 -- run `collect-urls` on this file from a\n"
            "# residential connection. Many reports redirect to a thin login shell; expect\n"
            "# 30-60% body-extraction success. Metadata sidecar: same path with .meta.tsv suffix.\n"
            "#\n"
        )
        for _upv, _bty, _program, _title, link in rows:
            w.write(link + "\n")

    meta_path = out_path.with_suffix(out_path.suffix + ".meta.tsv")
    with meta_path.open("w", encoding="utf-8") as w:
        w.write("url\tprogram\ttitle\tupvotes\tbounty_usd\n")
        for upv, bty, program, title, link in rows:
            t = title.replace("\t", " ").replace("\n", " ")
            p = program.replace("\t", " ")
            w.write(f"{link}\t{p}\t{t}\t{upv}\t{bty:.0f}\n")
    return len(rows)
