"""Push a dataset folder or a model folder to Hugging Face Hub.

Requires `huggingface_hub` and a token: `HF_TOKEN` in repo `.env`, env var, `--token`,
or `huggingface-cli login`.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from hunter_llm.load_dotenv_utils import load_dotenv_if_present


def parse_args() -> argparse.Namespace:
    load_dotenv_if_present()
    p = argparse.ArgumentParser(description="Push a hunter-llm artifact folder to Hugging Face Hub.")
    p.add_argument(
        "--repo",
        required=True,
        help="Destination repo id, e.g. jabir-khan/HunterLLM-8B or jabir-khan/hunter-llm-sft-v1",
    )
    p.add_argument("--folder", type=Path, required=True, help="Local folder to upload.")
    p.add_argument(
        "--repo-type",
        choices=("model", "dataset", "space"),
        default="model",
    )
    p.add_argument("--private", action="store_true", help="Create the repo as private (default public).")
    p.add_argument("--commit-message", default="hunter-llm upload")
    p.add_argument(
        "--token",
        default=os.environ.get("HF_TOKEN"),
        help="HF access token (write scope). Defaults to HF_TOKEN env var.",
    )
    p.add_argument(
        "--allow-patterns",
        default=None,
        help="Comma-separated glob list to restrict what is uploaded (e.g. '*.json,*.safetensors').",
    )
    p.add_argument(
        "--ignore-patterns",
        default="*.bin.tmp,*.lock,checkpoint-*/*",
        help="Comma-separated glob list of files to skip.",
    )
    return p.parse_args()


def push(
    *,
    folder: Path,
    repo: str,
    repo_type: str,
    private: bool,
    commit_message: str,
    token: str | None,
    allow_patterns: list[str] | None,
    ignore_patterns: list[str] | None,
) -> str:
    """Create the repo if missing and upload the folder. Returns the resulting URL."""
    try:
        from huggingface_hub import HfApi, create_repo, upload_folder
    except ImportError as e:
        raise ImportError(
            "huggingface_hub is required. Install with: pip install huggingface_hub"
        ) from e

    if not folder.is_dir():
        raise FileNotFoundError(f"Folder not found: {folder}")
    if token is None:
        raise RuntimeError(
            "No HF token provided. Put HF_TOKEN=... in `.env` at the repo root, or pass `--token`, "
            "or `export HF_TOKEN=...`, or run `huggingface-cli login` first."
        )

    api = HfApi(token=token)
    create_repo(
        repo_id=repo,
        repo_type=repo_type,
        private=private,
        token=token,
        exist_ok=True,
    )
    api.upload_folder(
        folder_path=str(folder),
        repo_id=repo,
        repo_type=repo_type,
        commit_message=commit_message,
        token=token,
        allow_patterns=allow_patterns,
        ignore_patterns=ignore_patterns,
    )
    url = f"https://huggingface.co/{repo}" if repo_type == "model" else f"https://huggingface.co/{repo_type}s/{repo}"
    return url


def main() -> None:
    args = parse_args()
    allow = [s.strip() for s in args.allow_patterns.split(",")] if args.allow_patterns else None
    ignore = [s.strip() for s in args.ignore_patterns.split(",")] if args.ignore_patterns else None
    url = push(
        folder=args.folder,
        repo=args.repo,
        repo_type=args.repo_type,
        private=args.private,
        commit_message=args.commit_message,
        token=args.token,
        allow_patterns=allow,
        ignore_patterns=ignore,
    )
    print(f"Uploaded {args.folder} -> {url}")


if __name__ == "__main__":
    main()
