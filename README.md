# HunterLLM

An open-source data pipeline and fine-tuning stack for building a **bug-bounty / vulnerability-research assistant** on top of an open-weights base model (Llama-3, Mistral, Qwen, DeepSeek-Coder, etc.).

> **Scope.** HunterLLM is designed to assist with vulnerability triage, secure-code review, and bug-bounty methodology on systems you are **explicitly authorized to test** — in-scope bug bounty programs, contracted pentests, CTFs, and your own lab. The system prompt and dataset are built around that constraint. Do not use it against third-party systems you do not have permission to test.

---

## What this repo gives you

| Stage | Module | What it does |
|---|---|---|
| Collect | `hunter_llm/collect/` | Clone security repos (PayloadsAllTheThings, SecLists, nuclei-templates, OWASP, etc.), pull NVD CVE descriptions, extract write-ups from URLs |
| Preprocess | `hunter_llm/preprocess/` | Convert raw sources into `instruction / input / output` rows, OWASP-style tagging, heuristic quality filter, MinHash dedup, DPO-pair export |
| Train | `hunter_llm/train/` | QLoRA supervised fine-tuning (SFT) and Direct Preference Optimization (DPO) with TRL + PEFT + bitsandbytes |
| Serve | `hunter_llm/infer/` | Interactive terminal chat against base + LoRA adapter, or a merged model folder; LoRA-merge helper for Ollama / vLLM / HF Hub |
| RAG | `hunter_llm/rag/` | Sentence-transformers + numpy retrieval index over the curated corpus |
| Evaluate | `hunter_llm/eval/` | Held-out benchmark JSON + ROUGE-L / heuristic scoring helpers |

A single Typer CLI ties it together: `hunter-llm --help`.

---

## Status

- Data pipeline: **working**. End-to-end smoke run produced ~3.5k raw CVE records → ~2.2k curated SFT rows → 2.2k DPO pairs.
- Trainers: implemented for the QLoRA path; **require a CUDA GPU** in practice (bitsandbytes 4-bit). Not runnable on Apple Silicon CPU/MPS — see [Compute options](#compute-options).
- Chat: works against any base + LoRA adapter or a merged folder, on CPU or GPU.

This is an early-stage research codebase. Expect rough edges. PRs and issues welcome.

---

## Install

```bash
git clone https://github.com/jabir-khan/HunterLLM.git
cd HunterLLM
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
# Optional retrieval extras (sentence-transformers + numpy):
pip install -e ".[rag]"
```

Optional env (defaults usually fine):

```bash
# .env in repo root, all optional
HUNTER_DATA_ROOT=./data
HUNTER_NVD_API_KEY=...                                  # higher NVD rate limits
HUNTER_BASE_MODEL=mistralai/Mistral-7B-Instruct-v0.3    # any HF id
HF_TOKEN=hf_xxx                                         # if base model is gated
```

---

## End-to-end workflow

```bash
# 1) Collect raw sources (GitHub repos + last N days of NVD)
hunter-llm bootstrap-data --skip-trickest    # add --skip-github to skip repo clones

# 2) Build the curated SFT dataset and DPO preference pairs
#    (already done by bootstrap-data; re-run after adding new sources)
hunter-llm build-dataset
hunter-llm export-dpo

# 3) (Optional) build a retrieval index over the curated corpus
hunter-llm rag-build data/processed/sft_train.jsonl

# 4) Fine-tune on a CUDA GPU
export HUNTER_BASE_MODEL=mistralai/Mistral-7B-Instruct-v0.3
hunter-llm train                                                  # SFT -> outputs/hunter-lora
hunter-llm train-dpo --sft-adapter-dir outputs/hunter-lora        # DPO -> outputs/hunter-dpo-lora

# 5) Chat with the adapter (CPU OK for small bases; GPU for 7B+)
hunter-llm chat --adapter-dir outputs/hunter-dpo-lora

# 6) Optional: bake LoRA into one folder for Ollama / vLLM / HF Hub
hunter-llm merge-lora --adapter-dir outputs/hunter-dpo-lora --out-dir outputs/hunter-merged
hunter-llm chat --merged-model outputs/hunter-merged
```

All commands have `--help`.

---

## Compute options

Training **cannot run on Apple Silicon** — bitsandbytes 4-bit needs CUDA and the recommended bases (Mistral-7B, Llama-3-8B) need ~16 GB VRAM for SFT and ~24 GB for DPO. Practical options:

| Where | Cost | Notes |
|---|---|---|
| **Kaggle Notebooks** | free | 30 hr/wk on dual T4 16 GB or P100. Push artifacts to HF Hub or you lose them. |
| **Google TPU Research Cloud** | free | Apply at `sites.research.google/trc/about/`. Best free option for serious runs. |
| **RunPod community A6000 48 GB** | ~$0.40–0.70/hr | Sweet spot for one-shot training runs. Persistent volumes available. |
| **Lambda Labs A100 40 GB** | ~$1.29/hr | Closest thing to "rent a real Ubuntu GPU server". |
| **NVIDIA Inception** | free signup | Stacks discounts on DGX Cloud and partner clouds. |

Pull the merged adapter back to a local machine to chat with it from anywhere.

---

## Data sources (default)

- **NVD CVE 2.0 API** — `services.nvd.nist.gov` (public domain).
- **swisskyrepo/PayloadsAllTheThings** (MIT)
- **danielmiessler/SecLists** (MIT)
- **projectdiscovery/nuclei-templates** (MIT)
- **OWASP/CheatSheetSeries** (CC-BY-SA-4.0)
- **trickest/cve** (GPL-3.0 — excluded by default; pass `--skip-trickest=false` to include)
- User-supplied URL lists for blog write-ups (you are responsible for ensuring you have rights to ingest them).

Per-sample provenance is tracked in the `meta` field of every generated instruction row.

---

## CLI cheatsheet

```text
hunter-llm collect-github       # clone repos -> raw JSONL
hunter-llm collect-nvd          # NVD lookback window -> raw JSONL
hunter-llm collect-urls FILE    # extract write-ups from URL list -> raw JSONL
hunter-llm build-dataset        # instruction synth + quality + dedup -> SFT JSONL
hunter-llm export-dpo           # synthesize chosen/rejected pairs -> DPO JSONL
hunter-llm rag-build PATH       # embed JSONL into a retrieval index
hunter-llm rag-query QUERY      # query the retrieval index
hunter-llm eval-benchmark       # list benchmark tasks
hunter-llm train                # QLoRA SFT
hunter-llm train-dpo            # QLoRA DPO on preference pairs
hunter-llm merge-lora           # bake LoRA into base -> single folder
hunter-llm chat                 # interactive terminal chat
hunter-llm bootstrap-data       # one shot: collect + build + DPO export
```

---

## Ethics and safety

- **Authorization required.** The shipped system prompt instructs the model to refuse requests aimed at systems the user is not authorized to test.
- **No weaponization aid.** The dataset emphasizes methodology, impact framing, and report quality — not turnkey exploits against named third parties.
- **Provenance retained.** Source URL / repo / CVE is preserved per sample so users can audit, re-derive, or excise individual sources.
- **Misuse is your responsibility.** Open weights and open datasets cannot prevent abuse on their own; deployment should add policy filters, rate limiting, and abuse logging.

If you intend to expose a hosted version of HunterLLM via API, please add an authorization-attestation step (program URL, ROE acknowledgement) before serving offensive-toned content.

---

## Roadmap

- [ ] Expand sources: Metasploit module docs, OWASP WSTG, HackerOne disclosed-report index, CWE catalog
- [ ] Scale curated corpus to 50–200k rows
- [ ] Replace synthetic DPO pairs with reviewer-curated preference data
- [ ] Rubric-based eval beyond ROUGE-L (impact accuracy, chain coherence, faithfulness)
- [ ] Contamination report on the held-out benchmark
- [ ] GGUF / AWQ release for single-GPU local inference
- [ ] Hosted demo Space on Hugging Face

---

## License

MIT for the code in this repository (see [`LICENSE`](LICENSE)).

Released datasets, model weights, and evaluation artifacts will carry their own licenses derived from the upstream source terms; per-sample provenance is recorded so downstream users can audit.

---

## Acknowledgements

- The methodology roadmap and source list were inspired by the structured guide in `pull-request-template-prompt` style discussions on building security-focused LLMs.
- Built on top of [Hugging Face Transformers / TRL / PEFT](https://huggingface.co), [bitsandbytes](https://github.com/TimDettmers/bitsandbytes), [datasketch](https://github.com/ekzhu/datasketch), and [trafilatura](https://github.com/adbar/trafilatura).
