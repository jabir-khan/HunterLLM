# HunterLLM v3 — inference (chat + RAG)

Use this **after** SFT training (or with base Qwen + LoRA adapter).

## 1. Pull weights

**LoRA adapter only** (training used `SKIP_MERGE=1`):

```bash
export HF_TOKEN=hf_...
huggingface-cli download jabir-khan/HunterLLM-72B-v3 --local-dir outputs/hunter-lora
```

**Merged model** (if you merged locally and pushed full weights):

```bash
huggingface-cli download jabir-khan/HunterLLM-72B-v3-merged --local-dir outputs/hunter-merged
```

## 2. Build RAG index (recommended)

Index the same corpus the model saw (write-ups + CVE-ish text from processed SFT):

```bash
cd HunterLLM
pip install -e ".[train]"

python -m hunter_llm.cli rag-build \
  data/processed/sft_train_v3.jsonl \
  --out-dir data/rag/index_v3 \
  --model-name sentence-transformers/all-MiniLM-L6-v2
```

On a fresh machine without local JSONL, pull the private dataset first:

```bash
python -m hunter_llm.infer.hf_pull \
  --repo jabir-khan/hunter-llm-sft-v3-private \
  --out data/processed \
  --repo-type dataset

python -m hunter_llm.cli rag-build data/processed/sft_train.jsonl --out-dir data/rag/index_v3
```

Query before chatting (manual smoke test):

```bash
python -m hunter_llm.cli rag-query "SSRF bypass localhost pdf renderer" \
  --index-dir data/rag/index_v3 --top-k 5
```

## 3. Interactive chat

`SYSTEM_BUG_HUNTER` is applied by default (operator mode, authorized scope).

**Base + LoRA:**

```bash
export HUNTER_BASE_MODEL=Qwen/Qwen2.5-72B-Instruct
python -m hunter_llm.infer.chat \
  --base-model "$HUNTER_BASE_MODEL" \
  --adapter-dir outputs/hunter-lora
```

**Merged folder:**

```bash
python -m hunter_llm.infer.chat --merged-model outputs/hunter-merged
```

Override system prompt only if needed:

```bash
export HUNTER_SYSTEM_PROMPT="$(cat prompts/SYSTEM_BUG_HUNTER.txt)"   # if you externalize it
```

## 4. RAG-augmented prompting (manual pattern)

There is no single `chat --rag` flag yet; prepend retrieved chunks to the user turn:

1. Run `rag-query` (or call `query_index` from Python).
2. Paste top chunks under `### Retrieved context` in the user message.
3. Ask the model for payloads / commands / report sections.

Example user message shape:

```text
### Retrieved context
<chunk 1>
<chunk 2>

### Task
Given an authorized target on app.example.com, give ffuf command to fuzz /api/v1.
```

## 5. Post-train eval

Run the model on `data/eval/benchmark.json`, save one JSONL line per task:

```json
{"task_id": "idor-1", "answer": "..."}
```

Score:

```bash
python -m hunter_llm.cli eval-score data/eval/answers.jsonl
python -m hunter_llm.cli eval-score data/eval/answers.jsonl --min-score 0.5
```

Regenerate benchmark tasks:

```bash
python scripts/build_eval_benchmark.py
```

## 6. When to train a second epoch

Only if `eval-score` **mean** improves on a held-out answer set and manual spot-checks
do not show CVE-template regurgitation. Otherwise stay at **1 epoch** for v3.
