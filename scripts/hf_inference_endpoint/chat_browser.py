#!/usr/bin/env python3
"""Browser chat UI for HunterLLM on a Hugging Face Inference Endpoint.

Keeps HF_TOKEN server-side (not in the browser). Opens a local Gradio page.

Setup:
  pip install gradio requests
  export HF_TOKEN=hf_...
  export ENDPOINT_URL=https://xxxxx.region.aws.endpoints.huggingface.cloud

Environment (optional `.env`): `ENDPOINT_MODE` (`openai`|`custom`),
`ENDPOINT_STREAM`, `ENDPOINT_DEFAULT_MAX_NEW_TOKENS`,
`ENDPOINT_MAX_NEW_TOKENS_CEILING`, `ENDPOINT_STREAM_READ_TIMEOUT`,
`ENDPOINT_STREAM_READ_IDLE_UNLIMITED=1`,
`ENDPOINT_STREAM_REASONING=1`. Set `ENDPOINT_STREAM=0` to disable streamed tokens.

Or put vars in repo-root `.env`, then:

  python scripts/hf_inference_endpoint/chat_browser.py
  python scripts/hf_inference_endpoint/chat_browser.py --share  # temporary public link
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
from collections.abc import Iterator
from typing import Any
from pathlib import Path

import requests

# Allow running from repo root without install
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from hunter_llm.load_dotenv_utils import load_dotenv_if_present
from hunter_llm.prompts import SYSTEM_ENDPOINT_CHAT


load_dotenv_if_present()


def _token_ceiling() -> int:
    """Upper bound on max_new_tokens (from env after `.env` is loaded)."""
    return max(512, min(8192, int(os.environ.get("ENDPOINT_MAX_NEW_TOKENS_CEILING") or "4096")))


_TRUNCATION_NOTE = (
    "\n\n**Note:** Reply stopped because it hit **`max_tokens`**. "
    "Open **Generation settings** and raise **max_new_tokens**, or shorten the prompt / history."
)


def _stream_read_timeout(request_timeout_s: float) -> float | None:
    """Seconds without a new SSE byte before disconnect. None disables (not recommended).

    Uses ENDPOINT_STREAM_READ_IDLE_UNLIMITED=1 for None,
    ENDPOINT_STREAM_READ_TIMEOUT if set as float seconds, else mirrors request slider.
    """
    if os.environ.get("ENDPOINT_STREAM_READ_IDLE_UNLIMITED", "").strip().lower() in {"1", "true", "yes", "on"}:
        return None
    raw = (os.environ.get("ENDPOINT_STREAM_READ_TIMEOUT") or "").strip()
    if raw:
        return float(raw)
    return float(request_timeout_s)


def _append_truncation_notice(text: str, finish_reason: str | None) -> str:
    if finish_reason != "length":
        return text
    if "**max_tokens**" in text and "Generation settings" in text:
        return text
    return text + _TRUNCATION_NOTE


def _endpoint_config() -> tuple[str, str, str, str, bool, int, bool, int, int]:
    load_dotenv_if_present()
    url = (os.environ.get("ENDPOINT_URL") or os.environ.get("HUNTER_ENDPOINT_URL") or "").strip().rstrip("/")
    token = (os.environ.get("HF_TOKEN") or "").strip()
    mode = (os.environ.get("ENDPOINT_MODE") or "custom").strip().lower()
    model_id = (os.environ.get("ENDPOINT_MODEL") or "jabir-khan/HunterLLM-72B-v3").strip()
    fast = (os.environ.get("ENDPOINT_FAST") or "1").strip().lower() not in {"0", "false", "no", "off"}
    max_history = int(os.environ.get("ENDPOINT_MAX_HISTORY_TURNS") or "3")
    stream = (os.environ.get("ENDPOINT_STREAM") or "1").strip().lower() not in {"0", "false", "no", "off"}
    if not url:
        raise SystemExit(
            "Set ENDPOINT_URL to your Inference Endpoint URL, e.g.\n"
            "  export ENDPOINT_URL=https://xxxxx.us-east-1.aws.endpoints.huggingface.cloud"
        )
    if not token:
        raise SystemExit("Set HF_TOKEN (write or fine-grained with endpoint access).")
    if mode not in {"custom", "openai"}:
        raise SystemExit("ENDPOINT_MODE must be 'custom' (handler.py) or 'openai' (vLLM).")
    default_mnt_raw = os.environ.get("ENDPOINT_DEFAULT_MAX_NEW_TOKENS") or ("512" if mode == "openai" else "256")
    ceil = _token_ceiling()
    default_mnt = max(32, min(ceil, int(default_mnt_raw)))
    return url, token, mode, model_id, fast, max_history, stream, default_mnt, ceil


def _call_custom_handler(
    *,
    url: str,
    token: str,
    messages: list[dict[str, str]],
    max_new_tokens: int,
    temperature: float,
    top_p: float,
    timeout: int,
    do_sample: bool,
    max_history_turns: int,
) -> str:
    payload = {
        "inputs": {"messages": messages},
        "parameters": {
            "max_new_tokens": max_new_tokens,
            "temperature": temperature,
            "top_p": top_p,
            "do_sample": do_sample,
            "max_history_turns": max_history_turns,
        },
    }
    resp = requests.post(
        url,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json=payload,
        timeout=(30, timeout),
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


def _openai_chat_url(url: str) -> str:
    return url if url.endswith("/v1/chat/completions") else f"{url}/v1/chat/completions"


def _call_openai_vllm(
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
    api_url = _openai_chat_url(url)
    payload = {
        "model": model_id,
        "messages": messages,
        "max_tokens": max_new_tokens,
        "temperature": temperature,
        "top_p": top_p,
        "stream": False,
    }
    resp = requests.post(
        api_url,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json=payload,
        timeout=(30, timeout),
    )
    if resp.status_code >= 400:
        raise RuntimeError(f"Endpoint HTTP {resp.status_code}: {resp.text[:2000]}")
    data = resp.json()
    try:
        choice0 = data["choices"][0]
        msg = str(choice0["message"]["content"])
        finish = choice0.get("finish_reason") if isinstance(choice0, dict) else None
        return _append_truncation_notice(msg.strip(), str(finish) if finish else None)
    except (KeyError, IndexError, TypeError) as e:
        raise RuntimeError(f"Unexpected OpenAI response: {data!r}") from e


def _iter_openai_sse_data_objects(response: requests.Response) -> Iterator[dict[str, Any]]:
    """Yield JSON objects after each `data: ` SSE line."""
    for raw in response.iter_lines(decode_unicode=True):
        if raw is None:
            continue
        if not isinstance(raw, str):
            continue
        line = raw.strip()
        if not line:
            continue
        if line.startswith(":"):
            continue  # SSE comment / keep-alive
        if not line.lower().startswith("data:"):
            continue
        payload = line[5:].lstrip()
        if payload == "[DONE]":
            break
        try:
            obj = json.loads(payload)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            yield obj


def _chunks_from_sse_choice_delta(obj: dict[str, Any]) -> tuple[list[str], str | None]:
    """Extract streamed text fragments and optional finish_reason from one SSE chunk."""
    pieces: list[str] = []
    finish_reason: str | None = None
    choices = obj.get("choices")
    if not isinstance(choices, list) or not choices:
        return pieces, finish_reason
    c0 = choices[0]
    if not isinstance(c0, dict):
        return pieces, finish_reason
    fr_raw = c0.get("finish_reason")
    if fr_raw:
        finish_reason = str(fr_raw)
    delta = c0.get("delta")
    if isinstance(delta, dict):
        content = delta.get("content") or ""
        if content:
            pieces.append(str(content))
        reasoning = delta.get("reasoning_content") or ""
        if reasoning and os.environ.get("ENDPOINT_STREAM_REASONING", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }:
            pieces.append(str(reasoning))
    return pieces, finish_reason


def _stream_openai_vllm(
    *,
    url: str,
    token: str,
    model_id: str,
    messages: list[dict[str, str]],
    max_new_tokens: int,
    temperature: float,
    top_p: float,
    timeout: int,
    finish_holder: dict[str, str | None],
) -> Iterator[str]:
    api_url = _openai_chat_url(url)
    payload = {
        "model": model_id,
        "messages": messages,
        "max_tokens": max_new_tokens,
        "temperature": temperature,
        "top_p": top_p,
        "stream": True,
    }
    read_timeout = _stream_read_timeout(float(timeout))
    timeouts: tuple[float, float | None] = (45.0, read_timeout)

    finish_holder.setdefault("reason", None)
    with requests.post(
        api_url,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json=payload,
        timeout=timeouts,
        stream=True,
    ) as resp:
        if resp.status_code >= 400:
            body = ""
            try:
                body = resp.text[:4000]
            except Exception:
                pass
            raise RuntimeError(f"Endpoint HTTP {resp.status_code}: {body}")

        for obj in _iter_openai_sse_data_objects(resp):
            frags, finish = _chunks_from_sse_choice_delta(obj)
            if finish:
                finish_holder["reason"] = finish
            for frag in frags:
                yield frag


def _call_endpoint(
    *,
    mode: str,
    model_id: str,
    url: str,
    token: str,
    messages: list[dict[str, str]],
    max_new_tokens: int,
    temperature: float,
    top_p: float,
    timeout: int,
    do_sample: bool,
    max_history_turns: int,
) -> str:
    if mode == "openai":
        return _call_openai_vllm(
            url=url,
            token=token,
            model_id=model_id,
            messages=messages,
            max_new_tokens=max_new_tokens,
            temperature=temperature,
            top_p=top_p,
            timeout=timeout,
        )
    return _call_custom_handler(
        url=url,
        token=token,
        messages=messages,
        max_new_tokens=max_new_tokens,
        temperature=temperature,
        top_p=top_p,
        timeout=timeout,
        do_sample=do_sample,
        max_history_turns=max_history_turns,
    )


def _trim_history(history: list[dict[str, str]], max_turns: int) -> list[dict[str, str]]:
    if max_turns <= 0:
        return history
    return history[-(max_turns * 2) :]


def build_ui(
    url: str,
    token: str,
    mode: str,
    model_id: str,
    default_timeout: int,
    *,
    default_fast: bool,
    default_max_history: int,
    default_stream: bool,
    default_max_new_tokens: int,
    tokens_ceiling: int,
):
    try:
        import gradio as gr
    except ImportError as e:
        raise SystemExit("Install Gradio: pip install gradio requests") from e

    system_prompt = (
        os.environ.get("ENDPOINT_SYSTEM_PROMPT") or SYSTEM_ENDPOINT_CHAT
    ).strip()

    def _history_to_messages(history: list[dict[str, str]], max_turns: int) -> list[dict[str, str]]:
        messages: list[dict[str, str]] = [{"role": "system", "content": system_prompt}]
        for item in _trim_history(history, max_turns):
            role = item.get("role")
            content = item.get("content")
            if role in ("user", "assistant") and content:
                messages.append({"role": role, "content": content})
        return messages

    def respond(
        message: str,
        history: list[dict[str, str]],
        max_new_tokens: int,
        temperature: float,
        top_p: float,
        request_timeout: int,
        fast_mode: bool,
        max_history_turns: int,
        stream_replies: bool,
    ):
        if not message.strip():
            yield "", history
            return

        user_turn = message.strip()
        pending = history + [
            {"role": "user", "content": user_turn},
            {"role": "assistant", "content": "_Waiting for endpoint…_"},
        ]
        yield "", pending

        do_sample = not fast_mode
        gen_temperature = float(temperature) if do_sample else 0.0
        turns = int(max_history_turns)
        messages = _history_to_messages(history, turns)
        messages.append({"role": "user", "content": user_turn})

        use_stream = bool(stream_replies) and mode == "openai"

        try:
            if use_stream:
                parts: list[str] = []
                finish_holder: dict[str, str | None] = {"reason": None}
                for delta in _stream_openai_vllm(
                    url=url,
                    token=token,
                    model_id=model_id,
                    messages=messages,
                    max_new_tokens=int(max_new_tokens),
                    temperature=gen_temperature,
                    top_p=float(top_p),
                    timeout=int(request_timeout),
                    finish_holder=finish_holder,
                ):
                    parts.append(delta)
                    yield "", history + [
                        {"role": "user", "content": user_turn},
                        {"role": "assistant", "content": "".join(parts)},
                    ]
                reply = _append_truncation_notice(
                    "".join(parts).strip() or "(empty response)",
                    finish_holder.get("reason"),
                )
                yield "", history + [
                    {"role": "user", "content": user_turn},
                    {"role": "assistant", "content": reply},
                ]
                return
            reply = _call_endpoint(
                mode=mode,
                model_id=model_id,
                url=url,
                token=token,
                messages=messages,
                max_new_tokens=int(max_new_tokens),
                temperature=gen_temperature,
                top_p=float(top_p),
                timeout=int(request_timeout),
                do_sample=do_sample,
                max_history_turns=turns,
            )
        except Exception as exc:
            reply = f"**Error:** {exc}"

        yield "", history + [
            {"role": "user", "content": user_turn},
            {"role": "assistant", "content": reply},
        ]

    with gr.Blocks(title="HunterLLM — Endpoint Chat") as demo:
        gr.Markdown(
            f"""
# HunterLLM v3 (72B LoRA)
Chat via your **Hugging Face Inference Endpoint**. Token stays on this machine.

**Endpoint:** `{url[:60]}{"…" if len(url) > 60 else ""}`  
**Mode:** `{mode}` {f"(model `{model_id}`)" if mode == "openai" else "(custom handler)"}

Use only on **authorized** targets (bug bounty / pentest / lab).

**Speed tips:** **OpenAI/vLLM** (`ENDPOINT_MODE=openai`): use **Stream replies** for quicker time-to-first-token; raise **max_new_tokens** if answers stop mid-thought (**hit max_tokens / length**).
**Fast mode** = greedy decode (faster). **Custom handler** returns one JSON body (no SSE). For **terminal + browser + proxy agent loops**, install **[Strix](https://github.com/usestrix/strix)** and follow `docs/agent_strix.md` to point Strix at this model.
"""
        )
        chatbot = gr.Chatbot(height=480, label="Chat")
        with gr.Row():
            msg = gr.Textbox(
                label="Message",
                placeholder="e.g. Authorized recon plan for api.example.com …",
                scale=4,
                lines=2,
            )
            send = gr.Button("Send", variant="primary", scale=1)
        with gr.Accordion("Generation settings", open=False):
            fast_mode = gr.Checkbox(
                value=default_fast,
                label="Fast mode (greedy decode — much faster, less creative)",
            )
            stream_replies = gr.Checkbox(
                value=bool(default_stream and mode == "openai"),
                label="Stream replies (token-by-token; OpenAI/vLLM only)",
                interactive=mode == "openai",
            )
            max_tokens = gr.Slider(
                32,
                tokens_ceiling,
                value=min(default_max_new_tokens, tokens_ceiling),
                step=64,
                label=f"max_new_tokens (slider ceiling {tokens_ceiling}; raise via ENDPOINT_MAX_NEW_TOKENS_CEILING)",
            )
            max_history = gr.Slider(1, 8, value=default_max_history, step=1, label="history turns kept")
            temperature = gr.Slider(0.0, 1.2, value=0.7, step=0.05, label="temperature (ignored in fast mode)")
            top_p = gr.Slider(0.1, 1.0, value=0.9, step=0.05, label="top_p (ignored in fast mode)")
            req_timeout = gr.Slider(30, 600, value=default_timeout, step=30, label="timeout (seconds)")
            gr.Markdown(
                "**If replies look chopped:** raise **max_new_tokens**, bump **timeout**, "
                "or add `ENDPOINT_STREAM_READ_IDLE_UNLIMITED=1` if SSE drops idle mid-generation. "
                "Unclosed Markdown code fences also break the bubble layout."
            )
        clear = gr.Button("Clear chat")

        inputs = [msg, chatbot, max_tokens, temperature, top_p, req_timeout, fast_mode, max_history, stream_replies]
        msg.submit(respond, inputs, [msg, chatbot])
        send.click(respond, inputs, [msg, chatbot])
        clear.click(lambda: ([], ""), None, [chatbot, msg])

    return demo


def _resolve_port(host: str, preferred: int, *, scan: int = 20) -> int:
    """Use preferred port if free, otherwise pick the next available one."""
    for port in range(preferred, preferred + scan):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((host, port))
                return port
            except OSError:
                continue
    raise SystemExit(
        f"No free port in range {preferred}-{preferred + scan - 1}. "
        f"Stop the process using port {preferred} or pass --port."
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Browser chat for HunterLLM HF Inference Endpoint")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=7860)
    parser.add_argument("--share", action="store_true", help="Gradio temporary public URL")
    parser.add_argument("--timeout", type=int, default=180, help="Default request timeout seconds")
    args = parser.parse_args()

    (
        url,
        token,
        mode,
        model_id,
        default_fast,
        default_max_history,
        default_stream,
        default_max_new_tokens,
        tokens_ceiling,
    ) = _endpoint_config()
    demo = build_ui(
        url,
        token,
        mode,
        model_id,
        args.timeout,
        default_fast=default_fast,
        default_max_history=default_max_history,
        default_stream=default_stream,
        default_max_new_tokens=default_max_new_tokens,
        tokens_ceiling=tokens_ceiling,
    )
    port = _resolve_port(args.host, args.port)
    if port != args.port:
        print(f"* Port {args.port} is in use; using http://{args.host}:{port} instead.")
    demo.launch(server_name=args.host, server_port=port, share=args.share)


if __name__ == "__main__":
    main()
