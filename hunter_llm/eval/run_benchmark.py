"""Run the held-out benchmark against a local model or HF Inference Endpoint."""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx

from hunter_llm.eval.benchmark import load_benchmark, score_tasks_with_reference
from hunter_llm.prompts import SYSTEM_BUG_HUNTER


def _load_answered_ids(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    done: set[str] = set()
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            tid = row.get("task_id")
            if tid:
                done.add(str(tid))
    return done


def _append_answer(path: Path, row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")


def _call_custom_endpoint(
    *,
    url: str,
    token: str,
    messages: list[dict[str, str]],
    max_new_tokens: int,
    temperature: float,
    top_p: float,
    do_sample: bool,
    timeout: int,
) -> str:
    payload = {
        "inputs": {"messages": messages},
        "parameters": {
            "max_new_tokens": max_new_tokens,
            "temperature": temperature,
            "top_p": top_p,
            "do_sample": do_sample,
            "max_history_turns": 0,
        },
    }
    with httpx.Client(timeout=httpx.Timeout(30.0, read=float(timeout))) as client:
        resp = client.post(
            url.rstrip("/"),
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json=payload,
        )
    if resp.status_code >= 400:
        raise RuntimeError(f"Endpoint HTTP {resp.status_code}: {resp.text[:2000]}")
    data = resp.json()
    if isinstance(data, list) and data:
        item = data[0]
        if isinstance(item, dict) and "generated_text" in item:
            return str(item["generated_text"]).strip()
        return str(item).strip()
    if isinstance(data, dict):
        if "generated_text" in data:
            return str(data["generated_text"]).strip()
        if "error" in data:
            raise RuntimeError(str(data["error"]))
    return str(data)


def _call_openai_endpoint(
    *,
    url: str,
    token: str,
    model_id: str,
    messages: list[dict[str, str]],
    max_new_tokens: int,
    temperature: float,
    top_p: float,
    timeout: int,
) -> str:
    api_url = url if url.rstrip("/").endswith("/v1/chat/completions") else f"{url.rstrip('/')}/v1/chat/completions"
    payload = {
        "model": model_id,
        "messages": messages,
        "max_tokens": max_new_tokens,
        "temperature": temperature,
        "top_p": top_p,
        "stream": False,
    }
    with httpx.Client(timeout=httpx.Timeout(30.0, read=float(timeout))) as client:
        resp = client.post(
            api_url,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json=payload,
        )
    if resp.status_code >= 400:
        raise RuntimeError(f"Endpoint HTTP {resp.status_code}: {resp.text[:2000]}")
    data = resp.json()
    return str(data["choices"][0]["message"]["content"]).strip()


def generate_via_endpoint(
    *,
    url: str,
    token: str,
    mode: str,
    model_id: str,
    system_prompt: str,
    user_prompt: str,
    max_new_tokens: int,
    temperature: float,
    top_p: float,
    do_sample: bool,
    timeout: int,
) -> str:
    messages = [
        {"role": "system", "content": system_prompt.strip()},
        {"role": "user", "content": user_prompt.strip()},
    ]
    if mode == "openai":
        return _call_openai_endpoint(
            url=url,
            token=token,
            model_id=model_id,
            messages=messages,
            max_new_tokens=max_new_tokens,
            temperature=temperature,
            top_p=top_p,
            timeout=timeout,
        )
    return _call_custom_endpoint(
        url=url,
        token=token,
        messages=messages,
        max_new_tokens=max_new_tokens,
        temperature=temperature,
        top_p=top_p,
        do_sample=do_sample,
        timeout=timeout,
    )


def run_benchmark(
    *,
    benchmark_path: Path,
    out_path: Path,
    system_prompt: str | None = None,
    resume: bool = True,
    limit: int | None = None,
    # local model
    base_model: str | None = None,
    adapter_dir: Path | None = None,
    merged_model: Path | None = None,
    use_4bit: bool = True,
    # endpoint
    endpoint_url: str | None = None,
    endpoint_mode: str = "custom",
    endpoint_model: str | None = None,
    hf_token: str | None = None,
    max_new_tokens: int = 512,
    fast: bool = False,
    request_timeout: int = 180,
    progress_callback: Any | None = None,
) -> dict[str, Any]:
    """Generate answers for benchmark tasks. Returns summary dict."""
    from tqdm import tqdm

    system = (system_prompt or os.environ.get("HUNTER_SYSTEM_PROMPT") or SYSTEM_BUG_HUNTER).strip()
    tasks = load_benchmark(benchmark_path)
    if limit is not None and limit > 0:
        tasks = tasks[:limit]

    done = _load_answered_ids(out_path) if resume else set()
    pending = [t for t in tasks if t.get("id") not in done]
    if resume and done:
        # Truncate file rewrite not needed — append-only resume
        pass
    elif not resume and out_path.is_file():
        out_path.unlink()

    use_endpoint = bool(endpoint_url and endpoint_url.strip())
    local_model = None
    local_tokenizer = None

    if not use_endpoint:
        if merged_model is None and adapter_dir is None:
            raise ValueError(
                "Provide --endpoint-url (or ENDPOINT_URL) for remote inference, "
                "or --merged-model / --adapter-dir for local GPU inference."
            )
        from hunter_llm.infer.chat import build_model_and_tokenizer, generate_reply

        ns = SimpleNamespace(
            base_model=base_model or os.environ.get("HUNTER_BASE_MODEL", "Qwen/Qwen2.5-72B-Instruct"),
            adapter_dir=adapter_dir,
            merged_model=merged_model,
            use_4bit=use_4bit,
        )
        local_model, local_tokenizer = build_model_and_tokenizer(ns)
        local_model.eval()

    token = (hf_token or os.environ.get("HF_TOKEN") or "").strip()
    if use_endpoint and not token:
        raise ValueError("HF_TOKEN (or --hf-token) required for endpoint inference.")

    mode = endpoint_mode.strip().lower()
    if mode not in {"custom", "openai"}:
        raise ValueError("endpoint_mode must be 'custom' or 'openai'")

    model_id = (endpoint_model or os.environ.get("ENDPOINT_MODEL") or "jabir-khan/HunterLLM-72B-v3").strip()
    gen_temperature = 0.0 if fast else 0.7
    do_sample = not fast

    errors: list[str] = []
    iterator = tqdm(pending, desc="eval-run", unit="task")
    for task in iterator:
        tid = str(task.get("id") or "")
        prompt = str(task.get("prompt") or "").strip()
        if not tid or not prompt:
            continue
        iterator.set_postfix_str(tid[:24])
        try:
            if use_endpoint:
                answer = generate_via_endpoint(
                    url=endpoint_url.strip(),  # type: ignore[union-attr]
                    token=token,
                    mode=mode,
                    model_id=model_id,
                    system_prompt=system,
                    user_prompt=prompt,
                    max_new_tokens=max_new_tokens,
                    temperature=gen_temperature,
                    top_p=0.9,
                    do_sample=do_sample,
                    timeout=request_timeout,
                )
            else:
                answer = generate_reply(
                    local_model,
                    local_tokenizer,
                    system_prompt=system,
                    user_message=prompt,
                    max_new_tokens=max_new_tokens,
                    temperature=gen_temperature,
                    do_sample=do_sample,
                )
        except Exception as exc:
            answer = f"[eval-run error: {exc}]"
            errors.append(f"{tid}: {exc}")

        row = {
            "task_id": tid,
            "category": task.get("category"),
            "answer": answer,
        }
        _append_answer(out_path, row)
        if progress_callback:
            progress_callback(tid, answer)

    summary: dict[str, Any] = {
        "benchmark": str(benchmark_path),
        "out": str(out_path),
        "total_tasks": len(tasks),
        "generated": len(pending),
        "skipped_resume": len(tasks) - len(pending),
        "errors": len(errors),
        "backend": "endpoint" if use_endpoint else "local",
    }
    if out_path.is_file() and out_path.stat().st_size > 0:
        scored = score_tasks_with_reference(benchmark_path, out_path)
        summary["mean"] = scored["mean"]
        summary["count_scored"] = scored["count"]
        summary["min"] = scored.get("min")
        summary["max"] = scored.get("max")
    return summary
