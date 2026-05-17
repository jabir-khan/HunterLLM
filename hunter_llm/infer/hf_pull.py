"""Pull a dataset or model snapshot from Hugging Face Hub into a local folder."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from hunter_llm.load_dotenv_utils import load_dotenv_if_present


def parse_args() -> argparse.Namespace:
    load_dotenv_if_present()
    p = argparse.ArgumentParser(description="Download a hunter-llm artifact from Hugging Face Hub.")
    p.add_argument("--repo", required=True, help="Source repo id, e.g. jabir-khan/hunter-llm-sft-v1")
    p.add_argument("--out", type=Path, required=True, help="Destination local folder.")
    p.add_argument(
        "--repo-type",
        choices=("model", "dataset", "space"),
        default="dataset",
    )
    p.add_argument(
        "--token",
        default=os.environ.get("HF_TOKEN"),
        help="HF token (only required for private repos).",
    )
    return p.parse_args()


def pull(*, repo: str, out: Path, repo_type: str, token: str | None) -> Path:
    try:
        from huggingface_hub import snapshot_download
    except ImportError as e:
        raise ImportError("huggingface_hub is required. Install with: pip install huggingface_hub") from e
    out.mkdir(parents=True, exist_ok=True)
    path = snapshot_download(
        repo_id=repo,
        repo_type=repo_type,
        local_dir=str(out),
        token=token,
    )
    return Path(path)


def main() -> None:
    args = parse_args()
    p = pull(repo=args.repo, out=args.out, repo_type=args.repo_type, token=args.token)
    print(f"Downloaded {args.repo} -> {p}")


if __name__ == "__main__":
    main()
