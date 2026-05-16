"""GitHub: shallow clone security repos and read filtered text files into raw JSONL records."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Iterable, Iterator

from hunter_llm.config import MAX_FILE_BYTES, TEXT_EXTENSIONS, settings


def _run(cmd: list[str], cwd: Path | None = None) -> None:
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{p.stderr}")


def clone_repo(owner: str, repo: str, dest: Path, depth: int = 1) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    target = dest / repo
    if target.is_dir() and (target / ".git").is_dir():
        try:
            _run(["git", "-C", str(target), "pull", "--ff-only"])
        except RuntimeError:
            # Detached / shallow conflicts: leave the existing clone as-is.
            pass
        return target
    url = f"https://github.com/{owner}/{repo}.git"
    _run(["git", "clone", "--depth", str(depth), "--filter=blob:limit=512k", url, str(target)])
    return target


def _path_allowed(rel_parts: tuple[str, ...], path_filters: Iterable[str] | None) -> bool:
    if path_filters is None:
        return True
    rel_str = "/".join(rel_parts)
    for pf in path_filters:
        if rel_str == pf or rel_str.startswith(pf + "/"):
            return True
    return False


def iter_text_files(root: Path, path_filters: Iterable[str] | None = None) -> Iterator[Path]:
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() not in TEXT_EXTENSIONS:
            continue
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        rel_parts = p.relative_to(root).parts
        lower_parts = {x.lower() for x in rel_parts}
        if ".git" in lower_parts or "node_modules" in lower_parts:
            continue
        if not _path_allowed(rel_parts, path_filters):
            continue
        yield p


def file_to_record(
    path: Path,
    repo_owner: str,
    repo_name: str,
    root: Path,
) -> dict:
    rel = path.relative_to(root)
    try:
        body = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        body = ""
    return {
        "source": "github",
        "repo": f"{repo_owner}/{repo_name}",
        "path": str(rel),
        "ext": path.suffix.lower(),
        "text": body,
    }


def ingest_repos(
    repos: list[dict],
    out_path: Path,
    clone_root: Path | None = None,
) -> dict[str, int]:
    """Clone each repo and append one JSON object per text file to out_path (JSONL).

    Returns a per-repo record count.
    """
    settings.raw_dir.mkdir(parents=True, exist_ok=True)
    clone_root = clone_root or (settings.raw_dir / "repos")
    clone_root.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = {}
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for spec in repos:
            owner = spec["owner"]
            name = spec["repo"]
            paths = spec.get("paths")
            key = f"{owner}/{name}"
            try:
                root = clone_repo(owner, name, clone_root)
            except RuntimeError as e:
                print(f"[warn] skipping {key}: {e}")
                counts[key] = 0
                continue
            n = 0
            for fp in iter_text_files(root, paths):
                rec = file_to_record(fp, owner, name, root)
                if not rec["text"].strip():
                    continue
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                n += 1
            counts[key] = n
    return counts
