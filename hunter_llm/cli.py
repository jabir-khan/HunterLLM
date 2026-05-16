"""CLI entrypoints for collection → curation → training."""

from __future__ import annotations

import glob
import subprocess
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from hunter_llm.config import DEFAULT_REPOS, settings
from hunter_llm.collect.github_repos import ingest_repos
from hunter_llm.collect.nvd_cve import ingest_nvd_window
from hunter_llm.collect.web_writeups import ingest_url_list
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
    n = ingest_repos(repos, out_path)
    console.print(f"[green]Wrote[/green] {n} records")


@app.command("collect-nvd")
def collect_nvd(
    days: int = typer.Option(30, help="Lookback window for published CVEs"),
    out: Path | None = typer.Option(None),
):
    """Pull CVE summaries from NVD API 2.0 (requires respecting rate limits; optional API key)."""
    out_path = out or (settings.raw_dir / "nvd_cves.jsonl")
    console.print(f"[bold]Fetching NVD[/bold] last {days} days → {out_path}")
    n = ingest_nvd_window(days, out_path)
    console.print(f"[green]Wrote[/green] {n} CVE records")


@app.command("collect-urls")
def collect_urls(
    urls_file: Path = typer.Argument(..., exists=True, readable=True),
    out: Path | None = typer.Option(None),
):
    """Fetch and extract write-ups from an allowlisted URL list (respect robots / terms)."""
    out_path = out or (settings.raw_dir / "urls_writeups.jsonl")
    console.print(f"[bold]Ingesting URLs[/bold] from {urls_file}")
    n = ingest_url_list(urls_file, out_path)
    console.print(f"[green]Kept[/green] {n} non-trivial articles")


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
):
    """Derive DPO preference pairs from curated SFT JSONL."""
    if not from_path.is_file():
        console.print(f"[red]Missing {from_path}. Run build-dataset first.[/red]")
        raise typer.Exit(code=1)
    n = sft_jsonl_to_dpo_jsonl(from_path, out, limit=limit)
    console.print(f"[green]Wrote[/green] {n} DPO rows → {out}")


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


@app.command("eval-benchmark")
def eval_benchmark(
    benchmark_path: Path = typer.Option(Path("data/eval/sample_benchmark.json")),
):
    from hunter_llm.eval.benchmark import load_benchmark

    if not benchmark_path.is_file():
        console.print(f"[red]Missing {benchmark_path}[/red]")
        raise typer.Exit(code=1)
    tasks = load_benchmark(benchmark_path)
    table = Table(title="Benchmark tasks")
    table.add_column("id")
    table.add_column("category")
    for t in tasks:
        table.add_row(t.get("id", ""), t.get("category", ""))
    console.print(table)
    console.print(f"[dim]{len(tasks)} tasks — add model outputs + score with eval/benchmark.py helpers.[/dim]")


@app.command("bootstrap-data")
def bootstrap_data(
    skip_github: bool = typer.Option(False, help="Skip large repo clones"),
    skip_trickest: bool = typer.Option(True, help="Exclude GPL trickest/cve when cloning"),
    nvd_days: int = typer.Option(90),
):
    """One shot: GitHub + NVD → curated SFT → DPO pairs (training is separate: `train` / `train-dpo`)."""
    if not skip_github:
        repos = [r for r in DEFAULT_REPOS if not (skip_trickest and r["repo"] == "cve")]
        gh_out = settings.raw_dir / "github_files.jsonl"
        console.print(f"[bold]GitHub[/bold] ({len(repos)} repos) → {gh_out}")
        ingest_repos(repos, gh_out)
    nv_out = settings.raw_dir / "nvd_cves.jsonl"
    console.print(f"[bold]NVD[/bold] last {nvd_days}d → {nv_out}")
    ingest_nvd_window(nvd_days, nv_out)
    pattern = str(settings.raw_dir / "*.jsonl")
    raw_files = sorted(Path(p) for p in glob.glob(pattern))
    if not raw_files:
        console.print("[red]No raw JSONL after collection.[/red]")
        raise typer.Exit(code=1)
    out_path = settings.processed_dir / "sft_train.jsonl"
    stats = build_curated_dataset(raw_files, out_path)
    console.print(stats)
    dpo_out = settings.processed_dir / "dpo_pairs.jsonl"
    n_dpo = sft_jsonl_to_dpo_jsonl(out_path, dpo_out)
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


if __name__ == "__main__":
    app()
