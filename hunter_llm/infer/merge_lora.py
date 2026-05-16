"""Merge LoRA adapter into base weights for a single-folder model (Ollama, HF from_pretrained, etc.)."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Merge hunter-llm LoRA into base and save fp16/BF16 weights")
    p.add_argument(
        "--base-model",
        default=os.environ.get("HUNTER_BASE_MODEL", "meta-llama/Meta-Llama-3-8B-Instruct"),
    )
    p.add_argument("--adapter-dir", type=Path, required=True)
    p.add_argument("--out-dir", type=Path, required=True)
    p.add_argument(
        "--dtype",
        choices=("bf16", "fp16"),
        default="bf16",
        help="Merged weight dtype (needs GPU or enough RAM)",
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    dt = torch.bfloat16 if args.dtype == "bf16" else torch.float16
    tokenizer = AutoTokenizer.from_pretrained(args.base_model, use_fast=True)

    base = AutoModelForCausalLM.from_pretrained(
        args.base_model,
        torch_dtype=dt,
        device_map="auto",
        trust_remote_code=True,
    )
    model = PeftModel.from_pretrained(base, str(args.adapter_dir))
    merged = model.merge_and_unload()
    merged.save_pretrained(str(args.out_dir), safe_serialization=True)
    tokenizer.save_pretrained(str(args.out_dir))
    print(f"Saved merged model to {args.out_dir}")


if __name__ == "__main__":
    main()
