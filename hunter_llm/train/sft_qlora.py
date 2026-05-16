"""QLoRA supervised fine-tuning with TRL `SFTTrainer` (Transformers + PEFT + bitsandbytes)."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

import torch
from datasets import load_dataset
from peft import LoraConfig, prepare_model_for_kbit_training
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig, TrainingArguments
from trl import SFTTrainer

from hunter_llm.prompts import SYSTEM_BUG_HUNTER


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="QLoRA SFT for hunter-llm JSONL dataset")
    p.add_argument("--dataset-jsonl", type=Path, required=True, help="Curated JSONL with instruction/input/output")
    p.add_argument("--output-dir", type=Path, required=True)
    p.add_argument(
        "--model-name",
        default=os.environ.get("HUNTER_BASE_MODEL", "meta-llama/Meta-Llama-3-8B-Instruct"),
        help="HF model id (set HF_TOKEN if gated)",
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
        "--system-prompt",
        default=os.environ.get("HUNTER_SYSTEM_PROMPT") or SYSTEM_BUG_HUNTER,
        help="Overrides default system persona (still should require authorization).",
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


def messages_to_text(tokenizer: AutoTokenizer, messages: list[dict]) -> str:
    if getattr(tokenizer, "chat_template", None):
        return tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=False)
    # Fallback when no chat template is registered (rare for instruct models).
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


def main() -> None:
    args = parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    ds = load_dataset("json", data_files=str(args.dataset_jsonl), split="train")
    ds = ds.shuffle(seed=args.seed)
    split = ds.train_test_split(test_size=args.val_ratio, seed=args.seed)
    train_ds, eval_ds = split["train"], split["test"]

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
    eval_ds = eval_ds.map(to_text, batched=True, batch_size=32, remove_columns=cols)

    bnb = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16,
        bnb_4bit_use_double_quant=True,
    )

    model = AutoModelForCausalLM.from_pretrained(
        args.model_name,
        quantization_config=bnb,
        device_map="auto",
        trust_remote_code=True,
    )
    model = prepare_model_for_kbit_training(model)
    model.gradient_checkpointing_enable()

    peft_cfg = LoraConfig(
        r=args.lora_r,
        lora_alpha=args.lora_alpha,
        lora_dropout=args.lora_dropout,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=("q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"),
    )

    training_args = TrainingArguments(
        output_dir=str(args.output_dir),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        gradient_accumulation_steps=args.grad_accum,
        learning_rate=args.lr,
        warmup_ratio=args.warmup_ratio,
        logging_steps=10,
        eval_strategy="steps",
        eval_steps=max(50, len(train_ds) // (args.batch_size * args.grad_accum * 10)),
        save_strategy="steps",
        save_steps=max(50, len(train_ds) // (args.batch_size * args.grad_accum * 10)),
        save_total_limit=3,
        bf16=torch.cuda.is_bf16_supported(),
        fp16=not torch.cuda.is_bf16_supported(),
        gradient_checkpointing=True,
        optim="paged_adamw_8bit",
        report_to="none",
        load_best_model_at_end=False,
    )

    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=eval_ds,
        peft_config=peft_cfg,
        dataset_text_field="text",
        max_seq_length=args.max_seq_length,
        packing=False,
    )

    trainer.train()
    trainer.save_model(str(args.output_dir))
    tokenizer.save_pretrained(str(args.output_dir))


if __name__ == "__main__":
    main()
