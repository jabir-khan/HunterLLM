"""QLoRA supervised fine-tuning with TRL 1.x `SFTTrainer`.

Works on TRL >=0.8 (legacy kwargs) and TRL >=1.0 (SFTConfig + processing_class).
Auto-detects device: CUDA enables 4-bit QLoRA via bitsandbytes; CPU/MPS fall back
to fp32/fp16 full-precision (only useful for tiny smoke runs).
"""

from __future__ import annotations

import argparse
import inspect
import math
import os
from pathlib import Path

import torch
from datasets import load_dataset
from peft import LoraConfig, prepare_model_for_kbit_training
from transformers import AutoModelForCausalLM, AutoTokenizer

from hunter_llm.prompts import SYSTEM_BUG_HUNTER


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="QLoRA SFT for hunter-llm JSONL dataset")
    p.add_argument("--dataset-jsonl", type=Path, required=True, help="Curated JSONL with instruction/input/output")
    p.add_argument("--output-dir", type=Path, required=True)
    p.add_argument(
        "--model-name",
        default=os.environ.get("HUNTER_BASE_MODEL", "Qwen/Qwen2.5-7B-Instruct"),
        help="HF model id (ungated default; set HUNTER_BASE_MODEL to override, HF_TOKEN if gated)",
    )
    p.add_argument("--max-seq-length", type=int, default=4096)
    p.add_argument("--epochs", type=float, default=1.0)
    p.add_argument("--batch-size", type=int, default=1)
    p.add_argument("--grad-accum", type=int, default=8)
    p.add_argument("--lr", type=float, default=2e-4)
    p.add_argument("--warmup-ratio", type=float, default=0.03)
    p.add_argument("--lora-r", type=int, default=16)
    p.add_argument("--lora-alpha", type=int, default=16)
    p.add_argument("--lora-dropout", type=float, default=0.05)
    p.add_argument("--val-ratio", type=float, default=0.02)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument(
        "--no-4bit",
        action="store_true",
        help="Disable bitsandbytes 4-bit quantization (use for non-CUDA smoke tests).",
    )
    p.add_argument(
        "--system-prompt",
        default=os.environ.get("HUNTER_SYSTEM_PROMPT") or SYSTEM_BUG_HUNTER,
        help="Overrides default system persona (still should require authorization).",
    )
    p.add_argument(
        "--logging-steps",
        type=int,
        default=10,
        help="How often to log loss to stdout / W&B.",
    )
    p.add_argument(
        "--report-to",
        default="none",
        help="One of 'none', 'wandb', 'tensorboard'. W&B requires WANDB_API_KEY env.",
    )
    return p.parse_args()


def row_to_messages(row: dict, system_prompt: str) -> list[dict]:
    instr = row.get("instruction") or ""
    inp = row.get("input") or ""
    out = row.get("output") or ""
    user = f"{instr.strip()}\n\n### Context\n{inp.strip()}".strip()
    return [
        {"role": "system", "content": system_prompt.strip()},
        {"role": "user", "content": user},
        {"role": "assistant", "content": out.strip()},
    ]


def messages_to_text(tokenizer, messages: list[dict]) -> str:
    if getattr(tokenizer, "chat_template", None):
        return tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=False)
    sys_, user_, asst = "", "", ""
    for m in messages:
        role, content = m.get("role"), m.get("content", "")
        if role == "system":
            sys_ = content
        elif role == "user":
            user_ = content
        elif role == "assistant":
            asst = content
    return f"<system>\n{sys_}\n</system>\n\nUser:\n{user_}\n\nAssistant:\n{asst}"


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


def _build_training_args(args: argparse.Namespace, train_steps_per_epoch: int):
    """Build SFTConfig (TRL >=0.9) or fall back to TrainingArguments + trainer kwargs."""
    eval_every = max(50, train_steps_per_epoch // 10)
    save_every = max(50, train_steps_per_epoch // 10)
    on_cuda = torch.cuda.is_available()
    bf16 = on_cuda and torch.cuda.is_bf16_supported()
    fp16 = on_cuda and not bf16
    optim = "paged_adamw_8bit" if on_cuda and not args.no_4bit else "adamw_torch"

    common = dict(
        output_dir=str(args.output_dir),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        gradient_accumulation_steps=args.grad_accum,
        learning_rate=args.lr,
        warmup_ratio=args.warmup_ratio,
        logging_steps=args.logging_steps,
        eval_strategy="steps",
        eval_steps=eval_every,
        save_strategy="steps",
        save_steps=save_every,
        save_total_limit=3,
        bf16=bf16,
        fp16=fp16,
        gradient_checkpointing=on_cuda,
        optim=optim,
        report_to=args.report_to,
        load_best_model_at_end=False,
        seed=args.seed,
    )
    try:
        from trl import SFTConfig

        fields = set(SFTConfig.__dataclass_fields__.keys())
        cfg_kwargs = {k: v for k, v in common.items() if k in fields}
        if "dataset_text_field" in fields:
            cfg_kwargs["dataset_text_field"] = "text"
        if "max_seq_length" in fields:
            cfg_kwargs["max_seq_length"] = args.max_seq_length
        if "packing" in fields:
            cfg_kwargs["packing"] = False
        return ("sftconfig", SFTConfig(**cfg_kwargs))
    except ImportError:
        from transformers import TrainingArguments

        return ("trainingargs", TrainingArguments(**common))


def _instantiate_trainer(
    *,
    model,
    tokenizer,
    train_ds,
    eval_ds,
    peft_cfg,
    training_args,
    args: argparse.Namespace,
):
    """Construct an SFTTrainer compatible with both TRL 1.x and earlier 0.8.x."""
    from trl import SFTTrainer

    sig = inspect.signature(SFTTrainer.__init__).parameters
    kwargs: dict = dict(
        model=model,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=eval_ds,
        peft_config=peft_cfg,
    )
    if "processing_class" in sig:
        kwargs["processing_class"] = tokenizer
    elif "tokenizer" in sig:
        kwargs["tokenizer"] = tokenizer
    # Older TRL accepts these as direct kwargs; new TRL reads them from SFTConfig.
    if "dataset_text_field" in sig:
        kwargs["dataset_text_field"] = "text"
    if "max_seq_length" in sig:
        kwargs["max_seq_length"] = args.max_seq_length
    if "packing" in sig:
        kwargs["packing"] = False
    return SFTTrainer(**kwargs)


def main() -> None:
    args = parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    if not torch.cuda.is_available() and not args.no_4bit:
        print("[hunter-llm] CUDA not available — disabling 4-bit (use --no-4bit explicitly to silence).")
        args.no_4bit = True

    ds = load_dataset("json", data_files=str(args.dataset_jsonl), split="train")
    ds = ds.shuffle(seed=args.seed)
    if args.val_ratio > 0:
        split = ds.train_test_split(test_size=args.val_ratio, seed=args.seed)
        train_ds, eval_ds = split["train"], split["test"]
    else:
        train_ds, eval_ds = ds, None

    tokenizer = AutoTokenizer.from_pretrained(args.model_name, use_fast=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"

    def to_text(batch: dict) -> dict:
        texts = []
        n = len(batch["instruction"])
        for i in range(n):
            row = {k: batch[k][i] for k in batch}
            texts.append(messages_to_text(tokenizer, row_to_messages(row, args.system_prompt)))
        return {"text": texts}

    cols = train_ds.column_names
    train_ds = train_ds.map(to_text, batched=True, batch_size=32, remove_columns=cols)
    if eval_ds is not None:
        eval_ds = eval_ds.map(to_text, batched=True, batch_size=32, remove_columns=cols)

    quant_cfg = _build_quant_config(not args.no_4bit)

    model_kwargs: dict = dict(trust_remote_code=True)
    if quant_cfg is not None:
        model_kwargs["quantization_config"] = quant_cfg
        model_kwargs["device_map"] = "auto"
    elif torch.cuda.is_available():
        model_kwargs["torch_dtype"] = torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16
        model_kwargs["device_map"] = "auto"
    else:
        model_kwargs["torch_dtype"] = torch.float32

    model = AutoModelForCausalLM.from_pretrained(args.model_name, **model_kwargs)
    if quant_cfg is not None:
        model = prepare_model_for_kbit_training(model)
    if torch.cuda.is_available():
        model.gradient_checkpointing_enable()

    peft_cfg = LoraConfig(
        r=args.lora_r,
        lora_alpha=args.lora_alpha,
        lora_dropout=args.lora_dropout,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=("q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"),
    )

    steps_per_epoch = max(1, math.ceil(len(train_ds) / max(1, args.batch_size * args.grad_accum)))
    _, training_args = _build_training_args(args, steps_per_epoch)

    trainer = _instantiate_trainer(
        model=model,
        tokenizer=tokenizer,
        train_ds=train_ds,
        eval_ds=eval_ds,
        peft_cfg=peft_cfg,
        training_args=training_args,
        args=args,
    )

    trainer.train()
    trainer.save_model(str(args.output_dir))
    tokenizer.save_pretrained(str(args.output_dir))


if __name__ == "__main__":
    main()
