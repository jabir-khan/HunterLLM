"""Interactive chat with the base model + optional LoRA adapter (or a merged checkpoint)."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from threading import Thread

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig, TextIteratorStreamer

from hunter_llm.prompts import SYSTEM_BUG_HUNTER


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Chat with hunter-llm SFT/DPO adapter or merged model")
    p.add_argument(
        "--base-model",
        default=os.environ.get("HUNTER_BASE_MODEL", "meta-llama/Meta-Llama-3-8B-Instruct"),
        help="Original base model HF id (required when using --adapter-dir)",
    )
    p.add_argument(
        "--adapter-dir",
        type=Path,
        default=None,
        help="Directory with LoRA weights (e.g. outputs/hunter-lora or outputs/hunter-dpo-lora)",
    )
    p.add_argument(
        "--merged-model",
        type=Path,
        default=None,
        help="If set, load this folder only (full weights after merge) and ignore base/adapter",
    )
    p.add_argument("--4bit", dest="use_4bit", action="store_true", default=True, help="Load base in 4-bit (default)")
    p.add_argument("--no-4bit", dest="use_4bit", action="store_false", help="Full precision base (needs more VRAM)")
    p.add_argument(
        "--system-prompt",
        default=os.environ.get("HUNTER_SYSTEM_PROMPT") or SYSTEM_BUG_HUNTER,
    )
    p.add_argument("--max-new-tokens", type=int, default=1024)
    return p.parse_args()


def _llama3_stop_token_ids(tokenizer) -> list[int]:
    """Llama 3 instruct ends turns with both <|end_of_text|> and <|eot_id|>; without
    setting both, generation tends to run past the assistant turn into garbage.
    Returns a list of token ids suitable for `eos_token_id=` in `.generate()`."""
    ids: list[int] = []
    if tokenizer.eos_token_id is not None:
        ids.append(tokenizer.eos_token_id)
    for tok in ("<|eot_id|>", "<|end_of_text|>"):
        tid = tokenizer.convert_tokens_to_ids(tok)
        if isinstance(tid, int) and tid is not None and tid > 0 and tid not in ids:
            ids.append(tid)
    return ids or [tokenizer.eos_token_id]


def build_model_and_tokenizer(args: argparse.Namespace):
    tok = AutoTokenizer.from_pretrained(
        args.merged_model or args.base_model,
        use_fast=True,
    )
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token

    if args.merged_model:
        mid = str(args.merged_model)
        kw: dict = {"trust_remote_code": True}
        if torch.cuda.is_available():
            kw["device_map"] = "auto"
            kw["torch_dtype"] = torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16
        else:
            kw["torch_dtype"] = torch.float32
        model = AutoModelForCausalLM.from_pretrained(mid, **kw)
        if not torch.cuda.is_available():
            model = model.to("cpu")
        return model, tok

    bnb = None
    if args.use_4bit and torch.cuda.is_available():
        bnb = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16,
            bnb_4bit_use_double_quant=True,
        )

    dtype = torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16
    model = AutoModelForCausalLM.from_pretrained(
        args.base_model,
        quantization_config=bnb,
        device_map="auto" if torch.cuda.is_available() else None,
        torch_dtype=None if bnb else dtype,
        trust_remote_code=True,
    )

    if args.adapter_dir and args.adapter_dir.is_dir():
        if not (args.adapter_dir / "adapter_config.json").is_file():
            raise FileNotFoundError(f"No adapter_config.json in {args.adapter_dir}")
        model = PeftModel.from_pretrained(model, str(args.adapter_dir))
        model.eval()

    return model, tok


def main() -> None:
    args = parse_args()
    if not args.merged_model and args.adapter_dir is None:
        print("Provide --adapter-dir (LoRA) or --merged-model (full weights). Loading base-only for demo.")
    model, tokenizer = build_model_and_tokenizer(args)
    model.eval()

    dev = next(model.parameters()).device

    print("Chat ready. Empty line to quit. Ctrl+C to exit.\n")

    messages: list[dict] = [{"role": "system", "content": args.system_prompt.strip()}]

    while True:
        try:
            user = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not user:
            break
        messages.append({"role": "user", "content": user})
        prompt = tokenizer.apply_chat_template(
            messages,
            tokenize=False,
            add_generation_prompt=True,
        )
        inputs = tokenizer(prompt, return_tensors="pt")
        inputs = {k: v.to(dev) for k, v in inputs.items()}

        streamer = TextIteratorStreamer(tokenizer, skip_prompt=True, skip_special_tokens=True)
        gen_kwargs = dict(
            **inputs,
            max_new_tokens=args.max_new_tokens,
            do_sample=True,
            temperature=0.7,
            top_p=0.9,
            pad_token_id=tokenizer.pad_token_id,
            eos_token_id=_llama3_stop_token_ids(tokenizer),
            streamer=streamer,
        )

        def _generate() -> None:
            model.generate(**gen_kwargs)

        thread = Thread(target=_generate)
        thread.start()
        print("Assistant: ", end="", flush=True)
        parts: list[str] = []
        for text in streamer:
            print(text, end="", flush=True)
            parts.append(text)
        print()
        thread.join()
        assistant_message = "".join(parts).strip()
        messages.append({"role": "assistant", "content": assistant_message})
        # keep context bounded
        if len(messages) > 20:
            messages = [messages[0]] + messages[-18:]


if __name__ == "__main__":
    main()
