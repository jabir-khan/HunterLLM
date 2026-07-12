"""CLI entrypoints for collection → curation → training."""

from __future__ import annotations

import glob
import os
import subprocess
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from hunter_llm.load_dotenv_utils import load_dotenv_if_present

load_dotenv_if_present()

from hunter_llm.config import DEFAULT_REPOS, settings
from hunter_llm.collect.cisa_kev import ingest_cisa_kev
from hunter_llm.collect.github_repos import ingest_repos
from hunter_llm.collect.mitre_attack import ingest_mitre_attack
from hunter_llm.collect.nvd_cve import ingest_nvd_long_window, ingest_nvd_window
from hunter_llm.collect.web_writeups import ingest_url_list
from hunter_llm.collect.url_discovery import (
    dedupe_urls,
    discover_ysamm_post_urls,
    discover_urls_from_feed_file,
    normalize_trackable_url,
)
from hunter_llm.preprocess.dpo_export import sft_jsonl_to_dpo_jsonl
from hunter_llm.preprocess.pipeline import build_curated_dataset

app = typer.Typer(no_args_is_help=True, help="Bug-hunting LLM data + fine-tuning pipeline")
console = Console()


@app.command("collect-github")
def collect_github(
    out: Path | None = typer.Option(None, help="Output JSONL path"),
    skip_trickest: bool = typer.Option(False, help="Skip GPL-licensed trickest/cve"),
):
    """Shallow-clone roadmap repos and emit one JSONL record per text file."""
    repos = [r for r in DEFAULT_REPOS if not (skip_trickest and r["repo"] == "cve")]
    out_path = out or (settings.raw_dir / "github_files.jsonl")
    console.print(f"[bold]Cloning / updating[/bold] {len(repos)} repos → {out_path}")
    counts = ingest_repos(repos, out_path)
    table = Table(title="GitHub ingest")
    table.add_column("repo")
    table.add_column("records", justify="right")
    for k, v in counts.items():
        table.add_row(k, str(v))
    console.print(table)
    console.print(f"[green]Total[/green] {sum(counts.values())} records")


@app.command("collect-nvd")
def collect_nvd(
    days: int = typer.Option(30, help="Short lookback window (days). Ignored if --years is given."),
    years: float | None = typer.Option(
        None,
        help="Long-window mode: paginate the last N years of CVEs in monthly chunks.",
    ),
    out: Path | None = typer.Option(None),
):
    """Pull CVE summaries from NVD API 2.0 (rate-limit friendly; HUNTER_NVD_API_KEY recommended for --years)."""
    out_path = out or (settings.raw_dir / "nvd_cves.jsonl")
    if years and years > 0:
        console.print(f"[bold]Fetching NVD[/bold] last {years} years (monthly chunks) → {out_path}")
        n = ingest_nvd_long_window(years, out_path)
    else:
        console.print(f"[bold]Fetching NVD[/bold] last {days} days → {out_path}")
        n = ingest_nvd_window(days, out_path)
    console.print(f"[green]Wrote[/green] {n} CVE records")


@app.command("collect-urls")
def collect_urls(
    urls_file: Path = typer.Argument(..., exists=True, readable=True),
    out: Path | None = typer.Option(None),
    append: bool = typer.Option(False, help="Append JSONL rows to existing file instead of replacing it"),
    verbose_skips: int = typer.Option(
        0,
        "--verbose-skips",
        help="Print status_code + raw_html length for the first N skipped URLs (debug HackerOne / Cloudflare).",
    ),
):
    """Fetch and extract write-ups from an allowlisted URL list (respect robots / terms)."""
    out_path = out or (settings.raw_dir / "urls_writeups.jsonl")
    console.print(f"[bold]Ingesting URLs[/bold] from {urls_file}")
    n = ingest_url_list(urls_file, out_path, append=append, verbose_skips=verbose_skips)
    console.print(f"[green]Kept[/green] {n} non-trivial articles")


@app.command("collect-h1-json")
def collect_h1_json(
    urls_file: Path = typer.Option(
        Path("data/urls/hackerone_top_reports.txt"),
        "--urls-file",
        help="One hackerone.com/reports/<id> URL per line (# comments ok).",
        exists=True,
        readable=True,
    ),
    out: Path | None = typer.Option(None, help="Default: append to raw/urls_writeups.jsonl unless --replace-out"),
    replace_out: bool = typer.Option(False, "--replace-out", help="Write only H1 rows to --out instead of merging"),
    pause: float = typer.Option(0.55, "--pause", help="Seconds between HackerOne API requests (be polite)."),
    limit: int | None = typer.Option(None, "--limit", help="Stop after processing this many URLs (smoke tests)."),
    min_chars: int = typer.Option(200, "--min-chars"),
    only_missing: bool = typer.Option(
        False,
        "--only-missing",
        help="Skip report IDs already present in the output JSONL (resume top-2k ingest).",
    ),
):
    """Ingest disclosed HackerOne reports via the public ``/reports/<id>.json`` API.

    **Do not** use ``collect-urls`` on HackerOne HTML --- it returns SPA shells.

    Concatenates ``vulnerability_information`` + disclosure ``summaries`` into one
    text block per report. Use ``--append`` pattern: default output is merged
    into ``data/raw/urls_writeups.jsonl`` unless ``--replace-out`` is passed.
    """
    from hunter_llm.collect.hackerone_json import ingest_hackerone_url_list

    out_path = out or (settings.raw_dir / "urls_writeups.jsonl")
    from hunter_llm.collect.hackerone_json import existing_report_ids

    skip_ids: set[str] = set()
    if only_missing and not replace_out:
        skip_ids = existing_report_ids(out_path)
        console.print(f"[dim]Skipping {len(skip_ids)} report IDs already in {out_path}[/dim]")
    console.print(f"[bold]HackerOne JSON ingest[/bold] from {urls_file} → {out_path}")
    stats = ingest_hackerone_url_list(
        urls_file,
        out_path,
        pause_sec=pause,
        min_chars=min_chars,
        append=not replace_out,
        progress=True,
        limit=limit,
        skip_ids=skip_ids if only_missing else None,
    )
    t = Table(title="HackerOne JSON ingest")
    t.add_column("metric")
    t.add_column("count", justify="right")
    for k, v in stats.items():
        t.add_row(k, str(v))
    console.print(t)
    console.print(f"[green]Wrote[/green] {stats['written']} reports → {out_path}")

def build_h1_urls_cmd(
    csv_path: Path = typer.Option(
        Path("data/raw/repos/hackerone-reports/data.csv"),
        "--csv",
        help="Path to the cloned reddelexc/hackerone-reports data.csv",
    ),
    out: Path = typer.Option(
        Path("data/urls/hackerone_top_reports.txt"),
        "--out",
    ),
    min_upvotes: int = typer.Option(20),
    max_rows: int = typer.Option(2000),
    require_bounty: bool = typer.Option(False, "--require-bounty"),
):
    """Build a curated URL list of top disclosed HackerOne reports.

    Ingest the bodies with (**not** plain ``collect-urls``)::

        hunter-llm collect-h1-json --urls-file data/urls/hackerone_top_reports.txt

    That uses ``GET /reports/<id>.json`` (``vulnerability_information`` + summaries).
    """
    from hunter_llm.collect.h1_urls import build_h1_subset

    if not csv_path.is_file():
        console.print(f"[red]Missing {csv_path}. Clone reddelexc/hackerone-reports first.[/red]")
        raise typer.Exit(code=1)
    n = build_h1_subset(
        csv_path,
        out,
        min_upvotes=min_upvotes,
        max_rows=max_rows,
        require_bounty=require_bounty,
    )
    console.print(f"[green]Wrote {n} URLs -> {out}[/green]")
    console.print(f"[dim]metadata sidecar: {out.with_suffix(out.suffix + '.meta.tsv')}[/dim]")


@app.command("collect-personal")
def collect_personal(
    reports_dir: Path = typer.Option(
        Path("data/personal/reports"),
        "--reports-dir",
        help="Folder of YAML-frontmatter Markdown reports (see data/personal/README.md)",
    ),
    out: Path | None = typer.Option(None, help="Output raw JSONL; default: data/raw/personal_reports.jsonl"),
):
    """Ingest your own bug bounty reports into raw JSONL the v3 builder can consume.

    Reports stay on your machine — this folder is gitignored. Run after dropping
    files into `data/personal/reports/`. Re-run any time to refresh.
    """
    from hunter_llm.collect.personal_reports import ingest_personal_reports

    if not reports_dir.is_dir():
        console.print(f"[red]Missing {reports_dir}. See data/personal/README.md[/red]")
        raise typer.Exit(code=1)
    out_path = out or (settings.raw_dir / "personal_reports.jsonl")
    stats = ingest_personal_reports(reports_dir, out_path)
    console.print(f"[green]Wrote[/green] {stats['written']} personal reports -> {stats['out']}")
    for s in stats.get("skipped", []):
        console.print(f"  [yellow]skip[/yellow] {s}")
    for name, hits in stats.get("secret_warnings", []):
        console.print(f"  [red]secret warning[/red] {name}: {', '.join(hits)} -- sanitize before training!")


@app.command("collect-bugreader-circle")
def collect_bugreader_circle(
    authors_file: Path = typer.Option(
        Path("data/urls/bugreader_circle.txt"),
        "--authors-file",
        help="Usernames to treat as personal/circle (one per line). Default includes jabir0x0 + friends.",
    ),
    out: Path | None = typer.Option(None, help="Default: data/raw/personal_reports.jsonl"),
    start_id: int = typer.Option(1, "--start-id"),
    end_id: int = typer.Option(305, "--end-id"),
    merge_local_md: bool = typer.Option(
        True,
        "--merge-local-md/--no-merge-local-md",
        help="Also ingest data/personal/reports/*.md into the same JSONL.",
    ),
    pause: float = typer.Option(0.2, "--pause"),
    ids_file: Path | None = typer.Option(
        Path("data/urls/bugreader_reports.txt"),
        "--ids-file",
        help="Use known report URLs instead of scanning 1..end-id (much faster).",
    ),
    no_discover: bool = typer.Option(
        False,
        "--no-discover",
        help="Only use --ids-file URLs; do not probe the full ID range.",
    ),
):
    """Ingest public Bugreader reports by *real* author (profile link), not URL slug.

    Your profile: https://bugreader.com/jabir0x0 — edit ``data/urls/bugreader_circle.txt``
    to add friends' handles. Merges with local markdown reports when ``--merge-local-md``.
    """
    from hunter_llm.collect.bugreader import ingest_bugreader_circle, load_usernames_file

    if not authors_file.is_file():
        console.print(f"[red]Missing {authors_file}[/red]")
        raise typer.Exit(code=1)
    authors = load_usernames_file(authors_file)
    if not authors:
        console.print("[red]No usernames in authors file[/red]")
        raise typer.Exit(code=1)
    out_path = out or (settings.raw_dir / "personal_reports.jsonl")
    local = Path("data/personal/reports") if merge_local_md else None
    console.print(
        f"[bold]Bugreader circle ingest[/bold] authors={authors} ids={start_id}..{end_id}"
    )
    stats = ingest_bugreader_circle(
        authors=authors,
        out_path=out_path,
        start_id=start_id,
        end_id=end_id,
        pause_sec=pause,
        append_local_md=local,
        ids_file=ids_file if (ids_file and ids_file.is_file()) else None,
        discover=not no_discover,
    )
    t = Table(title="Bugreader circle")
    t.add_column("metric")
    t.add_column("value", justify="right")
    for k, v in stats.items():
        if k == "by_author":
            continue
        t.add_row(k, str(v))
    console.print(t)
    if stats.get("by_author"):
        console.print(f"[dim]by_author: {stats['by_author']}[/dim]")
    console.print(f"[green]Wrote[/green] {stats['written']} rows -> {out_path}")


def _comma_sep_paths(csv: str | None) -> list[Path]:
    if not csv:
        return []
    return [Path(x.strip().expanduser()) for x in csv.split(",") if x.strip()]


def _comma_host_suffixes(csv: str | None) -> tuple[str, ...] | None:
    if not csv:
        return None
    tup = tuple(x.strip() for x in csv.split(",") if x.strip())
    return tup or None


@app.command("discover-writeup-urls")
def discover_writeup_urls(
    preset: str = typer.Option(
        "combined",
        "--preset",
        help="combined | ysamm-only | rss-only",
    ),
    feeds_file: Path = typer.Option(
        Path("data/urls/medium_feeds.txt"),
        "--feeds-file",
        help="One RSS/Atom URL per line (Medium tag feeds); ignored when --preset ysamm-only",
    ),
    out: Path = typer.Option(
        Path("data/urls/discovered_writeups.txt"),
        "--out",
        help="One URL per line for collect-urls",
    ),
    rss_host_only: str | None = typer.Option(
        None,
        "--rss-host-only",
        help="Comma host suffix filters for RSS links only (e.g. medium.com)",
    ),
    merge_with: str | None = typer.Option(
        None,
        "--merge-with",
        help="Comma-separated URL list files merged after discovery",
    ),
):
    """Discover permalinks (ysamm.com + Medium tag RSS). See data/urls/BUGREADER.md for Bugreader limits."""
    pl = preset.strip().lower().replace("-", "_")
    filt = _comma_host_suffixes(rss_host_only)
    acc: list[str] = []

    if pl == "combined":
        y = discover_ysamm_post_urls()
        console.print(f"[dim]Ysamm homepage posts[/dim] {len(y)}")
        acc.extend(y)
        if not feeds_file.is_file():
            console.print(f"[red]Missing feeds file[/red] {feeds_file}")
            raise typer.Exit(code=1)
        rss = discover_urls_from_feed_file(feeds_file, rss_host_suffixes=filt)
        console.print(f"[dim]RSS feed links[/dim] {len(rss)}")
        acc.extend(rss)
    elif pl == "ysamm_only":
        y = discover_ysamm_post_urls()
        console.print(f"[dim]Ysamm homepage posts[/dim] {len(y)}")
        acc.extend(y)
    elif pl == "rss_only":
        if not feeds_file.is_file():
            console.print(f"[red]Missing feeds file[/red] {feeds_file}")
            raise typer.Exit(code=1)
        rss = discover_urls_from_feed_file(feeds_file, rss_host_suffixes=filt)
        console.print(f"[dim]RSS feed links[/dim] {len(rss)}")
        acc.extend(rss)
    else:
        console.print("[red]Use --preset combined | ysamm-only | rss-only[/red]")
        raise typer.Exit(code=1)

    for fp in _comma_sep_paths(merge_with):
        if not fp.is_file():
            console.print(f"[yellow]skip missing[/yellow] {fp}")
            continue
        extra = 0
        for ln in fp.read_text(encoding="utf-8").splitlines():
            s = ln.strip()
            if s.startswith(("http://", "https://")):
                acc.append(normalize_trackable_url(s))
                extra += 1
        console.print(f"[dim]Merged[/dim] {fp.name}: +{extra} lines")

    acc = dedupe_urls(acc)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(acc) + ("\n" if acc else ""), encoding="utf-8")
    console.print(f"[green]Wrote[/green] {len(acc)} URLs → {out}")


@app.command("collect-cisa-kev")
def collect_cisa_kev(
    out: Path | None = typer.Option(None),
):
    """Fetch CISA Known Exploited Vulnerabilities catalog (public domain, daily)."""
    out_path = out or (settings.raw_dir / "cisa_kev.jsonl")
    console.print(f"[bold]Fetching CISA KEV[/bold] → {out_path}")
    n = ingest_cisa_kev(out_path)
    console.print(f"[green]Wrote[/green] {n} KEV entries")


@app.command("collect-mitre-attack")
def collect_mitre_attack(
    out: Path | None = typer.Option(None),
):
    """Fetch MITRE ATT&CK enterprise techniques bundle (Apache-2.0)."""
    out_path = out or (settings.raw_dir / "mitre_attack.jsonl")
    console.print(f"[bold]Fetching MITRE ATT&CK[/bold] → {out_path}")
    n = ingest_mitre_attack(out_path)
    console.print(f"[green]Wrote[/green] {n} techniques")


@app.command("build-dataset")
def build_dataset(
    raw_glob: str | None = typer.Option(
        None,
        "--raw-glob",
        help="Glob for raw JSONL files; default: HUNTER_DATA_ROOT/raw/*.jsonl",
    ),
    out: Path | None = typer.Option(None),
    min_quality: float = typer.Option(0.8),
    no_dedup: bool = typer.Option(False),
):
    """Instruction-tune dataset with heuristic labels, quality gate, and MinHash dedup."""
    pattern = raw_glob or str(settings.raw_dir / "*.jsonl")
    raw_files = sorted(Path(p) for p in glob.glob(pattern))
    if not raw_files:
        console.print("[red]No raw JSONL files found. Run collect-* first.[/red]")
        raise typer.Exit(code=1)
    out_path = out or (settings.processed_dir / "sft_train.jsonl")
    stats = build_curated_dataset(
        raw_files,
        out_path,
        min_quality=min_quality,
        dedup=not no_dedup,
    )
    table = Table(title="Dataset build")
    table.add_column("Stage")
    table.add_column("Count")
    for k, v in stats.items():
        table.add_row(k, str(v))
    console.print(table)
    console.print(f"[green]Curated dataset:[/green] {out_path}")


@app.command("export-dpo")
def export_dpo(
    from_path: Path = typer.Option(Path("data/processed/sft_train.jsonl"), "--from"),
    out: Path = typer.Option(Path("data/processed/dpo_pairs.jsonl")),
    limit: int | None = typer.Option(None, help="Cap rows for smoke tests"),
    curated: Path = typer.Option(
        Path("data/curated/dpo_preferences.jsonl"),
        "--curated",
        help="Hand-authored preference pairs (judgment: FP/lecture/verify/escalate). Prepended.",
    ),
):
    """Derive DPO preference pairs from curated SFT JSONL, plus hand-authored pairs."""
    if not from_path.is_file():
        console.print(f"[red]Missing {from_path}. Run build-dataset first.[/red]")
        raise typer.Exit(code=1)
    curated_path = curated if curated and curated.is_file() else None
    n = sft_jsonl_to_dpo_jsonl(from_path, out, limit=limit, curated_path=curated_path)
    extra = f" (incl. curated {curated})" if curated_path else " (no curated file found)"
    console.print(f"[green]Wrote[/green] {n} DPO rows → {out}{extra}")


@app.command("rag-build")
def rag_build(
    jsonl: Path = typer.Argument(..., exists=True, readable=True),
    out_dir: Path = typer.Option(Path("data/rag/index")),
    model_name: str = typer.Option("sentence-transformers/all-MiniLM-L6-v2"),
):
    """Chunk + embed JSONL for retrieval-augmented prompting."""
    from hunter_llm.rag.simple_index import build_index

    n = build_index(jsonl, out_dir, model_name=model_name)
    console.print(f"[green]Indexed[/green] {n} chunks → {out_dir}")


@app.command("rag-query")
def rag_query(
    query: str = typer.Argument(...),
    index_dir: Path = typer.Option(Path("data/rag/index")),
    top_k: int = typer.Option(5),
):
    from hunter_llm.rag.simple_index import query_index

    if not (index_dir / "embeddings.npy").is_file():
        console.print(f"[red]No index at {index_dir}. Run rag-build first.[/red]")
        raise typer.Exit(code=1)
    for score, chunk in query_index(index_dir, query, top_k=top_k):
        console.print(f"[bold]{score:.4f}[/bold] line={chunk.get('line')} off={chunk.get('offset')}")
        text = chunk.get("text") or ""
        console.print(text[:1200] + ("…" if len(text) > 1200 else ""))
        console.print("---")


@app.command("build-dataset-v2")
def build_dataset_v2(
    raw_glob: str | None = typer.Option(
        None,
        "--raw-glob",
        help="Glob for raw JSONL files; default: HUNTER_DATA_ROOT/raw/*.jsonl",
    ),
    out: Path | None = typer.Option(None),
    dedup: bool = typer.Option(True, "--dedup/--no-dedup"),
    dedup_threshold: float = typer.Option(0.92),
):
    """v2 SFT dataset — outputs are the real source bodies (write-ups, CVE / KEV /
    ATT&CK descriptions, OWASP / Metasploit prose). Smaller than v1 but every
    pair carries real domain content.
    """
    from hunter_llm.preprocess.instructions_v2 import write_v2_dataset
    from hunter_llm.preprocess.dedup import dedup_rows_jsonl

    pattern = raw_glob or str(settings.raw_dir / "*.jsonl")
    raw_files = sorted(Path(p) for p in glob.glob(pattern))
    if not raw_files:
        console.print("[red]No raw JSONL files found. Run collect-* first.[/red]")
        raise typer.Exit(code=1)
    out_path = out or (settings.processed_dir / "sft_train_v2.jsonl")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    interim = out_path.with_suffix(".interim.jsonl")
    counts = write_v2_dataset(raw_files, interim)

    if dedup:
        kept, skipped = dedup_rows_jsonl(interim, out_path, threshold=dedup_threshold)
        interim.unlink(missing_ok=True)
        counts["after_dedup_kept"] = kept
        counts["after_dedup_skipped"] = skipped
    else:
        interim.replace(out_path)
        counts["after_dedup_kept"] = counts.get("_total", 0)

    table = Table(title="v2 dataset build")
    table.add_column("Bucket")
    table.add_column("Count")
    for k in sorted(counts):
        table.add_row(k, str(counts[k]))
    console.print(table)
    console.print(f"[green]v2 SFT dataset:[/green] {out_path}")


@app.command("build-dataset-v3")
def build_dataset_v3(
    raw_glob: str | None = typer.Option(
        None,
        "--raw-glob",
        help="Glob for raw JSONL files; default: HUNTER_DATA_ROOT/raw/*.jsonl",
    ),
    out: Path | None = typer.Option(None),
    patt_root: Path = typer.Option(Path("data/raw/repos/PayloadsAllTheThings"), "--patt-root"),
    nuclei_root: Path = typer.Option(Path("data/raw/repos/nuclei-templates"), "--nuclei-root"),
    personal_jsonl: Path = typer.Option(Path("data/raw/personal_reports.jsonl"), "--personal"),
    reasoning_jsonl: Path = typer.Option(Path("data/curated/reasoning_chains.jsonl"), "--reasoning"),
    report_reasoning: bool = typer.Option(
        True,
        "--report-reasoning/--no-report-reasoning",
        help="Reframe disclosed HackerOne (.json) + Bugreader reports as 'brief me + hunt similar' pairs.",
    ),
    hackerone_cap: int = typer.Option(
        700, "--hackerone-cap", help="Max HackerOne report-reasoning pairs (Bugreader is uncapped)."
    ),
    nuclei_max_per_dir: int = typer.Option(8),
    dedup: bool = typer.Option(True, "--dedup/--no-dedup"),
    dedup_threshold: float = typer.Option(0.94),
):
    """v3 SFT dataset — v2 buckets (real source bodies) + v3 prescriptive buckets
    (payloads, wordlists, nuclei probes, tool invocations, personal reports).

    Produces a *task-shaped* dataset: the gold output for most pairs is what an
    operator actually wants — payloads in code fences, exact curl invocations,
    nuclei YAML, or the user's own report style.
    """
    from hunter_llm.preprocess.dedup import dedup_rows_jsonl
    from hunter_llm.preprocess.instructions_v2 import write_v2_dataset
    from hunter_llm.preprocess.instructions_v3 import write_v3_extra

    pattern = raw_glob or str(settings.raw_dir / "*.jsonl")
    raw_files = sorted(Path(p) for p in glob.glob(pattern))
    if not raw_files:
        console.print("[red]No raw JSONL files found. Run collect-* first.[/red]")
        raise typer.Exit(code=1)

    out_path = out or (settings.processed_dir / "sft_train_v3.jsonl")
    out_path.parent.mkdir(parents=True, exist_ok=True)

    v2_interim = out_path.with_suffix(".v2_interim.jsonl")
    v3_interim = out_path.with_suffix(".v3_interim.jsonl")
    merged_interim = out_path.with_suffix(".merged_interim.jsonl")

    v2_counts = write_v2_dataset(raw_files, v2_interim)
    v3_counts = write_v3_extra(
        v3_interim,
        patt_root=patt_root,
        nuclei_root=nuclei_root,
        personal_jsonl=personal_jsonl,
        reasoning_jsonl=reasoning_jsonl if reasoning_jsonl.is_file() else None,
        report_reasoning_paths=raw_files if report_reasoning else None,
        hackerone_cap=hackerone_cap,
        nuclei_max_per_dir=nuclei_max_per_dir,
    )

    with merged_interim.open("w", encoding="utf-8") as w:
        for p in (v2_interim, v3_interim):
            if p.exists():
                with p.open() as r:
                    for line in r:
                        w.write(line)
    v2_interim.unlink(missing_ok=True)
    v3_interim.unlink(missing_ok=True)

    if dedup:
        kept, skipped = dedup_rows_jsonl(merged_interim, out_path, threshold=dedup_threshold)
        merged_interim.unlink(missing_ok=True)
    else:
        merged_interim.replace(out_path)
        kept, skipped = sum(v2_counts.get("_total", 0) + v3_counts.get("_total", 0)), 0

    table = Table(title="v3 dataset build")
    table.add_column("Bucket")
    table.add_column("Count")
    for k in sorted(v2_counts):
        table.add_row(f"v2.{k}", str(v2_counts[k]))
    for k in sorted(v3_counts):
        table.add_row(f"v3.{k}", str(v3_counts[k]))
    table.add_row("after_dedup_kept", str(kept))
    table.add_row("after_dedup_skipped", str(skipped))
    console.print(table)
    console.print(f"[green]v3 SFT dataset:[/green] {out_path}")


@app.command("eval-benchmark")
def eval_benchmark(
    benchmark_path: Path = typer.Option(Path("data/eval/benchmark.json")),
):
    from hunter_llm.eval.benchmark import load_benchmark

    if not benchmark_path.is_file():
        console.print(f"[red]Missing {benchmark_path}[/red]")
        raise typer.Exit(code=1)
    tasks = load_benchmark(benchmark_path)
    table = Table(title="Benchmark tasks")
    table.add_column("id")
    table.add_column("category")
    table.add_column("rubric")
    for t in tasks:
        table.add_row(
            t.get("id", ""),
            t.get("category", ""),
            "yes" if t.get("rubric") else "no",
        )
    console.print(table)
    console.print(
        f"[dim]{len(tasks)} tasks — run model with `hunter-llm eval-run`, "
        f"then score with `hunter-llm eval-score data/eval/answers.jsonl`.[/dim]"
    )


@app.command("eval-run")
def eval_run_cmd(
    out: Path = typer.Option(
        Path("data/eval/answers.jsonl"),
        "--out",
        help="JSONL output: one {task_id, answer} per line (appended; use --no-resume to overwrite).",
    ),
    benchmark_path: Path = typer.Option(Path("data/eval/benchmark.json"), "--benchmark"),
    resume: bool = typer.Option(True, "--resume/--no-resume", help="Skip task_ids already in --out."),
    limit: int | None = typer.Option(None, "--limit", help="Only run the first N benchmark tasks."),
    score_only: bool = typer.Option(
        False,
        "--score-only",
        help="Skip generation; score existing --out and print mean.",
    ),
    base_model: str | None = typer.Option(
        None,
        "--base-model",
        help="HF base id for local inference (with --adapter-dir).",
    ),
    adapter_dir: Path | None = typer.Option(
        None,
        "--adapter-dir",
        help="LoRA folder for local GPU inference.",
    ),
    merged_model: Path | None = typer.Option(
        None,
        "--merged-model",
        help="Merged weights folder for local inference.",
    ),
    no_4bit: bool = typer.Option(False, "--no-4bit", help="Disable 4-bit load for local inference."),
    endpoint_url: str | None = typer.Option(
        None,
        "--endpoint-url",
        help="HF Inference Endpoint URL (defaults to ENDPOINT_URL env).",
    ),
    endpoint_mode: str = typer.Option(
        "custom",
        "--endpoint-mode",
        help="custom (handler.py) or openai (vLLM / OpenAI-compatible).",
    ),
    endpoint_model: str | None = typer.Option(
        None,
        "--endpoint-model",
        help="Model id for openai mode (defaults to ENDPOINT_MODEL env).",
    ),
    hf_token: str | None = typer.Option(None, "--hf-token", help="Defaults to HF_TOKEN env."),
    max_new_tokens: int = typer.Option(512, "--max-new-tokens"),
    fast: bool = typer.Option(False, "--fast", help="Greedy decode (temperature 0)."),
    timeout: int = typer.Option(180, "--timeout", help="Per-request timeout seconds (endpoint)."),
    system_prompt: str | None = typer.Option(
        None,
        "--system-prompt",
        help="Override system prompt (defaults to HUNTER_SYSTEM_PROMPT or SYSTEM_BUG_HUNTER).",
    ),
):
    """Run all benchmark prompts through the model; writes answers.jsonl for eval-score."""
    from hunter_llm.eval.run_benchmark import run_benchmark

    if not benchmark_path.is_file():
        console.print(f"[red]Missing {benchmark_path}[/red]")
        raise typer.Exit(code=1)

    url = (endpoint_url or os.environ.get("ENDPOINT_URL") or os.environ.get("HUNTER_ENDPOINT_URL") or "").strip()

    if score_only:
        if not out.is_file():
            console.print(f"[red]Missing {out} — run eval-run first[/red]")
            raise typer.Exit(code=1)
        from hunter_llm.eval.benchmark import score_tasks_with_reference

        result = score_tasks_with_reference(benchmark_path, out)
        console.print(
            f"[green]mean={result['mean']:.3f}[/green] "
            f"count={int(result['count'])} min={result.get('min', 0):.3f} max={result.get('max', 0):.3f}"
        )
        return

    if not url and merged_model is None and adapter_dir is None:
        console.print(
            "[red]Set ENDPOINT_URL (remote) or pass --adapter-dir / --merged-model (local CUDA).[/red]"
        )
        raise typer.Exit(code=1)

    backend = f"endpoint {url[:48]}…" if url else f"local adapter={adapter_dir} merged={merged_model}"
    console.print(f"[bold]eval-run[/bold] → {out} ({backend})")

    try:
        summary = run_benchmark(
            benchmark_path=benchmark_path,
            out_path=out,
            system_prompt=system_prompt,
            resume=resume,
            limit=limit,
            base_model=base_model,
            adapter_dir=adapter_dir,
            merged_model=merged_model,
            use_4bit=not no_4bit,
            endpoint_url=url or None,
            endpoint_mode=endpoint_mode,
            endpoint_model=endpoint_model,
            hf_token=hf_token,
            max_new_tokens=max_new_tokens,
            fast=fast,
            request_timeout=timeout,
        )
    except Exception as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc

    console.print(
        f"[green]generated={summary['generated']}[/green] "
        f"skipped={summary['skipped_resume']} errors={summary['errors']}"
    )
    if "mean" in summary:
        console.print(
            f"[bold green]mean={summary['mean']:.3f}[/bold green] "
            f"scored={summary.get('count_scored')} "
            f"min={summary.get('min', 0):.3f} max={summary.get('max', 0):.3f}"
        )
    console.print(f"[dim]Score again: hunter-llm eval-score {out}[/dim]")


@app.command("eval-score")
def eval_score(
    benchmark_path: Path = typer.Option(Path("data/eval/benchmark.json")),
    answers: Path = typer.Argument(..., help="JSONL with {task_id, answer} per line"),
    min_score: float = typer.Option(0.0, help="Only show tasks below this score"),
):
    """Score model answers against benchmark rubrics (keyword + ROUGE-L blend)."""
    from hunter_llm.eval.benchmark import load_benchmark, score_tasks_with_reference

    if not benchmark_path.is_file():
        console.print(f"[red]Missing {benchmark_path}[/red]")
        raise typer.Exit(code=1)
    if not answers.is_file():
        console.print(f"[red]Missing {answers}[/red]")
        raise typer.Exit(code=1)
    result = score_tasks_with_reference(benchmark_path, answers)
    table = Table(title="Eval scores")
    table.add_column("task_id")
    table.add_column("score", justify="right")
    for tid, sc in sorted(result["per_task"], key=lambda x: x[1]):
        if sc < min_score or min_score <= 0:
            table.add_row(tid, f"{sc:.3f}")
    console.print(table)
    console.print(
        f"[green]mean={result['mean']:.3f}[/green] "
        f"count={int(result['count'])} min={result.get('min', 0):.3f} max={result.get('max', 0):.3f}"
    )


@app.command("bootstrap-data")
def bootstrap_data(
    skip_github: bool = typer.Option(False, help="Skip large repo clones"),
    skip_trickest: bool = typer.Option(True, help="Exclude GPL trickest/cve when cloning"),
    nvd_days: int = typer.Option(90, help="Short NVD window in days (used when --years not set)"),
    years: float | None = typer.Option(
        None,
        "--years",
        help="If set, fetch the last N years of CVEs in monthly chunks (long-window mode).",
    ),
    full: bool = typer.Option(
        False,
        "--full",
        help="Convenience: equivalent to --years 3 if --years not given.",
    ),
    skip_kev: bool = typer.Option(False, help="Skip CISA KEV catalog fetch"),
    skip_mitre: bool = typer.Option(False, help="Skip MITRE ATT&CK bundle fetch"),
    urls_file: Path | None = typer.Option(
        None,
        "--urls",
        help="Optional URL allowlist file for write-up extraction (e.g. data/urls/writeups.txt).",
    ),
):
    """One shot: GitHub + NVD + CISA KEV + MITRE ATT&CK (+ URLs) → curated SFT → DPO pairs."""
    if not skip_github:
        repos = [r for r in DEFAULT_REPOS if not (skip_trickest and r["repo"] == "cve")]
        gh_out = settings.raw_dir / "github_files.jsonl"
        console.print(f"[bold]GitHub[/bold] ({len(repos)} repos) → {gh_out}")
        counts = ingest_repos(repos, gh_out)
        total = sum(counts.values())
        console.print(f"[green]GitHub:[/green] {total} records across {len(counts)} repos")
    nv_out = settings.raw_dir / "nvd_cves.jsonl"
    eff_years = years if years and years > 0 else (3.0 if full else None)
    if eff_years:
        console.print(f"[bold]NVD[/bold] last {eff_years} years (monthly chunks) → {nv_out}")
        n_cve = ingest_nvd_long_window(eff_years, nv_out)
    else:
        console.print(f"[bold]NVD[/bold] last {nvd_days}d → {nv_out}")
        n_cve = ingest_nvd_window(nvd_days, nv_out)
    console.print(f"[green]NVD:[/green] {n_cve} CVE records")
    if not skip_kev:
        kev_out = settings.raw_dir / "cisa_kev.jsonl"
        console.print(f"[bold]CISA KEV[/bold] → {kev_out}")
        try:
            n_kev = ingest_cisa_kev(kev_out)
            console.print(f"[green]CISA KEV:[/green] {n_kev} entries")
        except Exception as e:
            console.print(f"[yellow]CISA KEV fetch failed: {e}[/yellow]")
    if not skip_mitre:
        mit_out = settings.raw_dir / "mitre_attack.jsonl"
        console.print(f"[bold]MITRE ATT&CK[/bold] → {mit_out}")
        try:
            n_mit = ingest_mitre_attack(mit_out)
            console.print(f"[green]MITRE ATT&CK:[/green] {n_mit} techniques")
        except Exception as e:
            console.print(f"[yellow]MITRE ATT&CK fetch failed: {e}[/yellow]")
    if urls_file and urls_file.is_file():
        u_out = settings.raw_dir / "urls_writeups.jsonl"
        console.print(f"[bold]URLs[/bold] from {urls_file} → {u_out}")
        try:
            n_urls = ingest_url_list(urls_file, u_out)
            console.print(f"[green]URLs:[/green] {n_urls} articles")
        except Exception as e:
            console.print(f"[yellow]URL ingest failed: {e}[/yellow]")
    pattern = str(settings.raw_dir / "*.jsonl")
    raw_files = sorted(Path(p) for p in glob.glob(pattern))
    if not raw_files:
        console.print("[red]No raw JSONL after collection.[/red]")
        raise typer.Exit(code=1)
    out_path = settings.processed_dir / "sft_train.jsonl"
    stats = build_curated_dataset(raw_files, out_path)
    console.print(stats)
    dpo_out = settings.processed_dir / "dpo_pairs.jsonl"
    curated_dpo = Path("data/curated/dpo_preferences.jsonl")
    n_dpo = sft_jsonl_to_dpo_jsonl(
        out_path, dpo_out, curated_path=curated_dpo if curated_dpo.is_file() else None
    )
    console.print(f"[green]SFT[/green] {out_path}\n[green]DPO[/green] {n_dpo} pairs → {dpo_out}")


@app.command("train-dpo")
def train_dpo(
    dataset_jsonl: Path = typer.Option(Path("data/processed/dpo_pairs.jsonl")),
    output_dir: Path = typer.Option(Path("outputs/hunter-dpo-lora")),
    model_name: str | None = typer.Option(None, help="Overrides HUNTER_BASE_MODEL"),
    sft_adapter_dir: Path | None = typer.Option(
        None,
        "--sft-adapter-dir",
        help="SFT adapter dir (e.g. outputs/hunter-lora); omit for LoRA-from-scratch DPO on base.",
    ),
):
    """Preference-tune after SFT (needs a strong GPU — two 4-bit model weights in VRAM)."""
    cmd = [
        sys.executable,
        "-m",
        "hunter_llm.train.dpo_qlora",
        "--dataset-jsonl",
        str(dataset_jsonl),
        "--output-dir",
        str(output_dir),
    ]
    if model_name:
        cmd.extend(["--model-name", model_name])
    if sft_adapter_dir and sft_adapter_dir.is_dir():
        cmd.extend(["--sft-adapter-dir", str(sft_adapter_dir)])
    console.print(f"[bold]Running:[/bold] {' '.join(cmd)}")
    subprocess.check_call(cmd)


@app.command("train")
def train(
    dataset_jsonl: Path = typer.Option(Path("data/processed/sft_train.jsonl")),
    output_dir: Path = typer.Option(Path("outputs/hunter-lora")),
    model_name: str | None = typer.Option(None, help="Overrides HUNTER_BASE_MODEL"),
):
    """QLoRA SFT on curated JSONL (CUDA GPU + HF token for gated bases)."""
    cmd = [
        sys.executable,
        "-m",
        "hunter_llm.train.sft_qlora",
        "--dataset-jsonl",
        str(dataset_jsonl),
        "--output-dir",
        str(output_dir),
    ]
    if model_name:
        cmd.extend(["--model-name", model_name])
    console.print(f"[bold]Running:[/bold] {' '.join(cmd)}")
    subprocess.check_call(cmd)


@app.command("chat")
def chat_cmd(
    adapter_dir: Path = typer.Option(Path("outputs/hunter-lora"), "--adapter-dir"),
    merged_model: Path | None = typer.Option(None, "--merged-model"),
    base_model: str | None = typer.Option(None, help="Defaults to HUNTER_BASE_MODEL"),
):
    """Interactive terminal chat (base + LoRA or merged folder)."""
    cmd = [sys.executable, "-m", "hunter_llm.infer.chat"]
    if merged_model:
        cmd.extend(["--merged-model", str(merged_model)])
    else:
        if not adapter_dir.is_dir():
            console.print(
                f"[red]No adapter at {adapter_dir}. Run `hunter-llm train` first or pass --merged-model.[/red]"
            )
            raise typer.Exit(code=1)
        if base_model:
            cmd.extend(["--base-model", base_model])
        cmd.extend(["--adapter-dir", str(adapter_dir)])
    subprocess.check_call(cmd)


@app.command("merge-lora")
def merge_lora_cmd(
    adapter_dir: Path = typer.Option(Path("outputs/hunter-lora")),
    out_dir: Path = typer.Option(Path("outputs/hunter-merged")),
    base_model: str | None = typer.Option(None),
):
    """Bake LoRA into full weights for serving tools that expect one model folder."""
    cmd = [sys.executable, "-m", "hunter_llm.infer.merge_lora", "--adapter-dir", str(adapter_dir), "--out-dir", str(out_dir)]
    if base_model:
        cmd.extend(["--base-model", base_model])
    console.print(f"[bold]Running:[/bold] {' '.join(cmd)}")
    subprocess.check_call(cmd)


@app.command("hf-push")
def hf_push_cmd(
    repo: str = typer.Option(..., "--repo", help="HF repo id, e.g. jabir-khan/HunterLLM-8B"),
    folder: Path = typer.Option(..., "--folder", help="Local folder to upload (model dir, dataset dir, etc.)"),
    repo_type: str = typer.Option("model", "--repo-type", help="model | dataset | space"),
    private: bool = typer.Option(False, "--private"),
    commit_message: str = typer.Option("hunter-llm upload"),
):
    """Upload a folder (merged model, adapter, or curated dataset) to Hugging Face Hub."""
    cmd = [
        sys.executable, "-m", "hunter_llm.infer.hf_push",
        "--repo", repo,
        "--folder", str(folder),
        "--repo-type", repo_type,
        "--commit-message", commit_message,
    ]
    if private:
        cmd.append("--private")
    console.print(f"[bold]Running:[/bold] {' '.join(cmd)}")
    subprocess.check_call(cmd)


@app.command("hf-pull")
def hf_pull_cmd(
    repo: str = typer.Option(..., "--repo"),
    out: Path = typer.Option(..., "--out"),
    repo_type: str = typer.Option(
        "model",
        "--repo-type",
        help="model | dataset | space (default: model — symmetric with hf-push)",
    ),
):
    """Download a HF dataset or model folder into `--out`.

    Default `--repo-type` is `model` (matching `hf-push`); pass `--repo-type dataset`
    to fetch a dataset repo. Mismatched repo type returns a 404 on the HF API.
    """
    cmd = [
        sys.executable, "-m", "hunter_llm.infer.hf_pull",
        "--repo", repo,
        "--out", str(out),
        "--repo-type", repo_type,
    ]
    console.print(f"[bold]Running:[/bold] {' '.join(cmd)}")
    subprocess.check_call(cmd)


if __name__ == "__main__":
    app()
