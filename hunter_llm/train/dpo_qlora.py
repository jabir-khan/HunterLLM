"""Direct Preference Optimization (DPO) with QLoRA on top of optional SFT adapter.

TRL 1.x compatible (auto-detects `processing_class` vs `tokenizer`).
"""

from __future__ import annotations

import argparse
import inspect
import os
from pathlib import Path

import torch
from datasets import load_dataset
from peft import LoraConfig, PeftModel, get_peft_model, prepare_model_for_kbit_training
from transformers import AutoModelForCausalLM, AutoTokenizer

from hunter_llm.prompts import SYSTEM_BUG_HUNTER


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="QLoRA DPO on hunter-llm preference pairs JSONL")
    p.add_argument("--dataset-jsonl", type=Path, required=True, help="Lines: prompt, chosen, rejected")
    p.add_argument("--output-dir", type=Path, required=True)
    p.add_argument(
        "--model-name",
        default=os.environ.get("HUNTER_BASE_MODEL", "meta-llama/Meta-Llama-3-8B-Instruct"),
        help="HF base model id",
    )
    p.add_argument("--beta", type=float, default=0.1)
    p.add_argument("--max-prompt-length", type=int, default=2048)
    p.add_argument("--max-length", type=int, default=4096)
    p.add_argument("--epochs", type=float, default=0.5)
    p.add_argument("--batch-size", type=int, default=1)
    p.add_argument("--grad-accum", type=int, default=8)
    p.add_argument("--lr", type=float, default=5e-6)
    p.add_argument("--lora-r", type=int, default=16)
    p.add_argument("--lora-alpha", type=int, default=16)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--no-4bit", action="store_true")
    p.add_argument("--report-to", default="none")
    p.add_argument(
        "--sft-adapter-dir",
        type=Path,
        default=None,
        help="Optional LoRA directory from the SFT stage.",
    )
    return p.parse_args()


def _build_quant_config(use_4bit: bool):
    if not use_4bit:
        return None
    try:
        from transformers import BitsAndBytesConfig
    except ImportError:
        return None
    return BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16,
        bnb_4bit_use_double_quant=True,
    )


def _build_dpo_config(args: argparse.Namespace):
    from trl import DPOConfig

    on_cuda = torch.cuda.is_available()
    fields = set(DPOConfig.__dataclass_fields__.keys())
    desired = dict(
        output_dir=str(args.output_dir),
        beta=args.beta,
        learning_rate=args.lr,
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        gradient_accumulation_steps=args.grad_accum,
        logging_steps=10,
        save_strategy="steps",
        save_steps=100,
        save_total_limit=2,
        bf16=on_cuda and torch.cuda.is_bf16_supported(),
        fp16=on_cuda and not torch.cuda.is_bf16_supported(),
        gradient_checkpointing=on_cuda,
        optim="paged_adamw_8bit" if on_cuda and not args.no_4bit else "adamw_torch",
        report_to=args.report_to,
        max_prompt_length=args.max_prompt_length,
        max_length=args.max_length,
        seed=args.seed,
    )
    cfg_kwargs = {k: v for k, v in desired.items() if k in fields}
    return DPOConfig(**cfg_kwargs)


def _instantiate_dpo_trainer(*, model, ref_model, tokenizer, ds, training_args):
    from trl import DPOTrainer

    sig = inspect.signature(DPOTrainer.__init__).parameters
    kwargs: dict = dict(
        model=model,
        ref_model=ref_model,
        args=training_args,
        train_dataset=ds,
    )
    if "processing_class" in sig:
        kwargs["processing_class"] = tokenizer
    elif "tokenizer" in sig:
        kwargs["tokenizer"] = tokenizer
    return DPOTrainer(**kwargs)


def main() -> None:
    args = parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    if not torch.cuda.is_available() and not args.no_4bit:
        print("[hunter-llm] CUDA not available — disabling 4-bit.")
        args.no_4bit = True

    ds = load_dataset("json", data_files=str(args.dataset_jsonl), split="train")

    tokenizer = AutoTokenizer.from_pretrained(args.model_name, use_fast=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "left"

    def format_prompt(batch: dict) -> dict:
        raw_prompts = batch["prompt"]
        out: list[str] = []
        for rp in raw_prompts:
            messages = [
                {"role": "system", "content": SYSTEM_BUG_HUNTER},
                {"role": "user", "content": rp.strip()},
            ]
            if getattr(tokenizer, "chat_template", None):
                out.append(
                    tokenizer.apply_chat_template(
                        messages, tokenize=False, add_generation_prompt=True
                    )
                )
            else:
                out.append(SYSTEM_BUG_HUNTER.strip() + "\n\nUser:\n" + rp.strip() + "\n\nAssistant:\n")
        return {"prompt": out}

    ds = ds.map(format_prompt, batched=True, batch_size=64)

    quant_cfg = _build_quant_config(not args.no_4bit)
    base_kw: dict = dict(pretrained_model_name_or_path=args.model_name, trust_remote_code=True)
    if quant_cfg is not None:
        base_kw["quantization_config"] = quant_cfg
        base_kw["device_map"] = "auto"
    elif torch.cuda.is_available():
        base_kw["torch_dtype"] = torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16
        base_kw["device_map"] = "auto"
    else:
        base_kw["torch_dtype"] = torch.float32

    model = AutoModelForCausalLM.from_pretrained(**base_kw)
    ref_model = AutoModelForCausalLM.from_pretrained(**base_kw)

    if quant_cfg is not None:
        model = prepare_model_for_kbit_training(model)
    model.enable_input_require_grads()

    ref_model.eval()
    for p in ref_model.parameters():
        p.requires_grad_(False)

    peft_kwargs = dict(
        r=args.lora_r,
        lora_alpha=args.lora_alpha,
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=("q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"),
    )

    if args.sft_adapter_dir and args.sft_adapter_dir.is_dir():
        model = PeftModel.from_pretrained(model, str(args.sft_adapter_dir), is_trainable=True)
    else:
        model = get_peft_model(model, LoraConfig(**peft_kwargs))

    training_args = _build_dpo_config(args)
    trainer = _instantiate_dpo_trainer(
        model=model,
        ref_model=ref_model,
        tokenizer=tokenizer,
        ds=ds,
        training_args=training_args,
    )

    trainer.train()
    trainer.save_model(str(args.output_dir))
    tokenizer.save_pretrained(str(args.output_dir))


if __name__ == "__main__":
    main()
