"""Lightweight dataset stats for sanity checks before training."""

from __future__ import annotations

import json
import statistics
from pathlib import Path

import typer

app = typer.Typer(no_args_is_help=True)


@app.command()
def lengths(dataset_jsonl: Path):
    lens_out = []
    lens_in = []
    with dataset_jsonl.open(encoding="utf-8") as f:
        for line in f:
            row = json.loads(line)
            lens_out.append(len(row.get("output") or ""))
            lens_in.append(len(row.get("input") or ""))
    print(f"samples: {len(lens_out)}")
    if not lens_out:
        return
    print(f"output chars: mean={statistics.mean(lens_out):.0f} p50={statistics.median(lens_out):.0f}")
    print(f"input chars:  mean={statistics.mean(lens_in):.0f} p50={statistics.median(lens_in):.0f}")


if __name__ == "__main__":
    app()
