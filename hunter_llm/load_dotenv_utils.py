"""Load repo-root `.env` into the process environment (HF_TOKEN, etc.).

Walks upward from cwd until `.env` is found. Uses `python-dotenv` when installed;
otherwise parses simple `KEY=value` lines (does not override existing env unless
`override=True`).
"""

from __future__ import annotations

import os
from pathlib import Path


def _minimal_load_dotenv(env_file: Path, *, override: bool) -> None:
    try:
        text = env_file.read_text(encoding="utf-8")
    except OSError:
        return
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        value = value.rstrip(";").strip()
        if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]:
            value = value[1:-1].strip()
        else:
            value = value.strip("\"'")
        if not key:
            continue
        if override or key not in os.environ:
            os.environ[key] = value


def load_dotenv_if_present(*, override: bool = False) -> None:
    """Load first `.env` found walking cwd → parents."""
    cwd = Path.cwd().resolve()
    for d in (cwd, *cwd.parents):
        env_file = d / ".env"
        if not env_file.is_file():
            continue
        try:
            from dotenv import load_dotenv as _load  # noqa: PLC0415

            _load(env_file, override=override)
        except ImportError:
            _minimal_load_dotenv(env_file, override=override)
        return
