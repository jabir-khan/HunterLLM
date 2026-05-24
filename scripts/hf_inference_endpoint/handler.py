"""Custom HF Inference Endpoint handler for HunterLLM LoRA (Qwen2.5-72B + adapter).

Upload this file + requirements.txt to the root of jabir-khan/HunterLLM-72B-v3 on the Hub,
then deploy the repo as a Custom Inference Endpoint (A100 80GB).
"""

from __future__ import annotations

from typing import Any

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig


SYSTEM_PROMPT = (
    "You are an autonomous offensive-security operator assisting on authorized targets only "
    "(in-scope bug bounty, contracted pentest, or isolated lab). "
    "Require explicit authorization before destructive actions. "
    "Prefer concrete commands, HTTP requests, and stepwise reasoning."
)


class EndpointHandler:
    def __init__(self, path: str = "") -> None:
        base_model = "Qwen/Qwen2.5-72B-Instruct"
        bnb = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16,
            bnb_4bit_use_double_quant=True,
        )
        self.tokenizer = AutoTokenizer.from_pretrained(base_model, use_fast=True, trust_remote_code=True)
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token

        model_kwargs: dict[str, Any] = {
            "quantization_config": bnb,
            "device_map": "auto",
            "trust_remote_code": True,
        }
        try:
            model = AutoModelForCausalLM.from_pretrained(
                base_model,
                attn_implementation="flash_attention_2",
                **model_kwargs,
            )
        except Exception:
            model = AutoModelForCausalLM.from_pretrained(base_model, **model_kwargs)

        self.model = PeftModel.from_pretrained(model, path)
        self.model.eval()

    def _extract_messages(self, data: dict[str, Any]) -> list[dict[str, str]]:
        params = data.get("parameters") or {}
        system = params.get("system") or data.get("system") or SYSTEM_PROMPT
        raw_inputs = data.get("inputs")

        if isinstance(raw_inputs, dict):
            nested = raw_inputs.get("messages")
            if nested:
                return nested
            user_text = raw_inputs.get("text") or raw_inputs.get("prompt") or ""
            if user_text:
                return [
                    {"role": "system", "content": raw_inputs.get("system", system)},
                    {"role": "user", "content": user_text},
                ]

        if data.get("messages"):
            return data["messages"]

        if isinstance(raw_inputs, str) and raw_inputs.strip():
            return [
                {"role": "system", "content": system},
                {"role": "user", "content": raw_inputs.strip()},
            ]

        return []

    @staticmethod
    def _trim_messages(messages: list[dict[str, str]], max_turns: int) -> list[dict[str, str]]:
        if max_turns <= 0:
            return messages
        system = [m for m in messages if m.get("role") == "system"]
        turns = [m for m in messages if m.get("role") in ("user", "assistant")]
        keep = turns[-(max_turns * 2) :]
        return (system[:1] if system else []) + keep

    @staticmethod
    def _generation_kwargs(params: dict[str, Any]) -> dict[str, Any]:
        temperature = float(params.get("temperature", 0.7))
        top_p = float(params.get("top_p", 0.9))
        do_sample = params.get("do_sample")
        if do_sample is None:
            do_sample = temperature > 0.0
        elif isinstance(do_sample, str):
            do_sample = do_sample.strip().lower() in {"1", "true", "yes", "on"}

        if do_sample:
            return {"do_sample": True, "temperature": max(temperature, 1e-5), "top_p": top_p}
        return {"do_sample": False}

    def __call__(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        params = data.get("parameters") or {}
        max_new_tokens = int(params.get("max_new_tokens", 128))
        max_history_turns = int(params.get("max_history_turns", 3))

        chat_messages = self._extract_messages(data)
        if not chat_messages:
            raise ValueError("No user message in request (expected inputs.messages or inputs text).")

        chat_messages = self._trim_messages(chat_messages, max_history_turns)

        prompt = self.tokenizer.apply_chat_template(
            chat_messages,
            tokenize=False,
            add_generation_prompt=True,
        )
        inputs = self.tokenizer(prompt, return_tensors="pt")
        inputs = {k: v.to(self.model.device) for k, v in inputs.items()}

        gen_kwargs = {
            "max_new_tokens": max_new_tokens,
            "pad_token_id": self.tokenizer.pad_token_id,
            "eos_token_id": self.tokenizer.eos_token_id,
            "use_cache": True,
            **self._generation_kwargs(params),
        }

        with torch.inference_mode():
            out = self.model.generate(**inputs, **gen_kwargs)

        text = self.tokenizer.decode(out[0][inputs["input_ids"].shape[-1] :], skip_special_tokens=True)
        return [{"generated_text": text.strip()}]
