"""Single-cell Kaggle Notebook bootstrap for HunterLLM training (free dual-T4).

Paste this into a Kaggle notebook cell (enable GPU + Internet first). Set the
HF_TOKEN and HF_MODEL_REPO via Kaggle Secrets (Add-ons -> Secrets).

T4 16GB is tight for an 8B model; defaults below use batch=1 + grad-accum=16 and
disable DPO. For DPO you should use a single A6000/A100, not T4.
"""

import os
import subprocess
import sys
from pathlib import Path


def run(cmd: list[str]) -> None:
    print(">>", " ".join(cmd), flush=True)
    subprocess.check_call(cmd)


def main() -> None:
    repo_url = os.environ.get("HUNTER_GIT", "https://github.com/jabir-khan/HunterLLM.git")
    work = Path("/kaggle/working")
    work.mkdir(parents=True, exist_ok=True)
    os.chdir(work)
    if not (work / "HunterLLM").is_dir():
        run(["git", "clone", "--depth", "1", repo_url, "HunterLLM"])
    os.chdir(work / "HunterLLM")

    run([sys.executable, "-m", "pip", "install", "--upgrade", "pip", "wheel"])
    run([sys.executable, "-m", "pip", "install", "-e", ".[train]"])

    try:
        from kaggle_secrets import UserSecretsClient  # type: ignore
        secrets = UserSecretsClient()
        os.environ["HF_TOKEN"] = secrets.get_secret("HF_TOKEN")
        os.environ["HF_MODEL_REPO"] = secrets.get_secret("HF_MODEL_REPO")
    except Exception:
        if "HF_TOKEN" not in os.environ:
            raise RuntimeError("Set HF_TOKEN + HF_MODEL_REPO as Kaggle Secrets or env vars")

    hf_repo = os.environ["HF_MODEL_REPO"]
    base = os.environ.get("HUNTER_BASE_MODEL", "mistralai/Mistral-7B-Instruct-v0.3")
    os.environ["HUNTER_BASE_MODEL"] = base

    dataset_repo = os.environ.get("HF_DATASET_REPO")
    if dataset_repo:
        run([sys.executable, "-m", "hunter_llm.infer.hf_pull", "--repo", dataset_repo, "--out", "data", "--repo-type", "dataset"])
    else:
        run([sys.executable, "-m", "hunter_llm.cli", "bootstrap-data", "--skip-trickest", "--years", "1"])

    run([
        sys.executable, "-m", "hunter_llm.train.sft_qlora",
        "--dataset-jsonl", "data/processed/sft_train.jsonl",
        "--output-dir", "outputs/hunter-lora",
        "--model-name", base,
        "--epochs", "1",
        "--batch-size", "1",
        "--grad-accum", "16",
    ])

    run([
        sys.executable, "-m", "hunter_llm.infer.merge_lora",
        "--base-model", base,
        "--adapter-dir", "outputs/hunter-lora",
        "--out-dir", "outputs/hunter-merged",
        "--dtype", "fp16",
    ])

    run([
        sys.executable, "-m", "hunter_llm.infer.hf_push",
        "--repo", hf_repo,
        "--folder", "outputs/hunter-merged",
        "--repo-type", "model",
        "--commit-message", "hunter-llm Kaggle run",
    ])
    print(f"Done: https://huggingface.co/{hf_repo}")


if __name__ == "__main__":
    main()
