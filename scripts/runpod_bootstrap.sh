#!/usr/bin/env bash
# HunterLLM end-to-end training on a fresh RunPod (or any CUDA Ubuntu) pod.
#
# Required env (export before running, or place in a .env file in repo root):
#   HF_TOKEN                Hugging Face read+write token (accepts Llama / Qwen licenses)
#   HF_MODEL_REPO           Target HF repo for the merged model (e.g. jabir-khan/HunterLLM-72B-v3)
# Optional env:
#   HF_DATASET_REPO         If set, pull curated dataset from this HF dataset repo
#                           (skips local data collection on the pod).
#   HUNTER_BASE_MODEL       Base model to fine-tune. Recommended:
#                             - meta-llama/Meta-Llama-3-8B-Instruct   (A6000-48GB, ~1h)
#                             - Qwen/Qwen2.5-32B-Instruct             (A100-80GB,  ~4h)
#                             - Qwen/Qwen2.5-72B-Instruct             (A100-80GB or H100-80GB, ~6-10h)
#                           Defaults to Qwen/Qwen2.5-72B-Instruct.
#   SFT_EPOCHS              Defaults to 1
#   DPO_EPOCHS              Defaults to 0.5
#   SKIP_DPO=1              Skip the DPO stage entirely (recommended for v3 -- the
#                           SFT dataset is already prescriptive, DPO adds little).
#   SKIP_MERGE=1            Skip the merge stage (push adapter only -- much faster
#                           upload for 72B; user merges locally / on inference host).
#   GRAD_ACCUM              Grad accumulation steps (default scales with model size).
#   MAX_SEQ_LEN             Override max sequence length (defaults to 4096).
#   WANDB_API_KEY           Optional: enables Weights & Biases dashboards
#
# Pod sizing guide:
#   8B  + QLoRA 4-bit : A6000 48GB    (~$0.50/h)   ~1h     -> ~$1
#   32B + QLoRA 4-bit : A100 80GB     (~$2.00/h)   ~4h     -> ~$8
#   72B + QLoRA 4-bit : A100 80GB     (~$2.00/h)   ~6-10h  -> ~$15-20
#   72B + QLoRA 4-bit : H100 80GB     (~$3.50/h)   ~3-5h   -> ~$15-20  (faster, similar $)
#
# Usage on a fresh pod:
#   git clone https://github.com/jabir-khan/HunterLLM.git && cd HunterLLM
#   export HF_TOKEN=hf_xxx HF_MODEL_REPO=jabir-khan/HunterLLM-72B-v3
#   export HF_DATASET_REPO=jabir-khan/hunter-llm-sft-v3-private   # set to v3
#   export SKIP_DPO=1                                              # recommended for v3
#   bash scripts/runpod_bootstrap.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [[ -f .env ]]; then
  # shellcheck disable=SC1091
  set -a; source .env; set +a
fi

: "${HF_TOKEN:?Set HF_TOKEN (Hugging Face write token)}"
: "${HF_MODEL_REPO:?Set HF_MODEL_REPO (e.g. jabir-khan/HunterLLM-72B-v3)}"
HUNTER_BASE_MODEL="${HUNTER_BASE_MODEL:-Qwen/Qwen2.5-72B-Instruct}"
SFT_EPOCHS="${SFT_EPOCHS:-1}"
DPO_EPOCHS="${DPO_EPOCHS:-0.5}"
MAX_SEQ_LEN="${MAX_SEQ_LEN:-4096}"

# Auto-scale grad accumulation by model size unless user overrode it.
if [[ -z "${GRAD_ACCUM:-}" ]]; then
  case "$HUNTER_BASE_MODEL" in
    *72B*|*72b*) GRAD_ACCUM=16 ;;
    *32B*|*32b*) GRAD_ACCUM=12 ;;
    *)           GRAD_ACCUM=8  ;;
  esac
fi

echo "==[1/7] Sanity check GPU"
python -c "import torch; assert torch.cuda.is_available(), 'No CUDA GPU detected'; print(torch.cuda.get_device_name(0))"

echo "==[2/7] Install package + training extras"
pip install --upgrade pip wheel
pip install -e ".[train]"
# huggingface_hub Xet backend (datasets pushed via hf-push use Xet/CAS storage;
# without this plugin snapshot_download silently returns 0-byte pointer files).
pip install -U "huggingface_hub[hf_xet]" hf_xet

echo "==[3/7] HF login"
python - <<PY
from huggingface_hub import login
import os
login(token=os.environ['HF_TOKEN'])
print('HF login OK')
PY

if [[ -n "${WANDB_API_KEY:-}" ]]; then
  echo "==     Enabling W&B reporting"
  pip install wandb >/dev/null
  python -c "import wandb; wandb.login()"
  REPORT_TO=wandb
else
  REPORT_TO=none
fi

echo "==[4/7] Prepare dataset"
if [[ -n "${HF_DATASET_REPO:-}" ]]; then
  echo "    Pulling dataset from HF: $HF_DATASET_REPO"
  # Files are uploaded at the dataset root (sft_train.jsonl, dpo_pairs.jsonl);
  # the trainers read from data/processed/, so pull straight into that folder.
  mkdir -p data/processed
  python -m hunter_llm.infer.hf_pull --repo "$HF_DATASET_REPO" --out data/processed --repo-type dataset
else
  echo "    No HF_DATASET_REPO set — building dataset on the pod (will clone repos + fetch NVD)"
  python -m hunter_llm.cli bootstrap-data --skip-trickest --full
fi

ls -la data/processed/ || true
# Sanity check: training step will fail with a confusing FileNotFoundError if the
# Xet backend silently downloaded 0-byte pointer files. Bail early instead.
if [[ ! -s data/processed/sft_train.jsonl ]]; then
  echo "ERROR: data/processed/sft_train.jsonl missing or empty after dataset pull."
  echo "       Hint: pip install -U 'huggingface_hub[hf_xet]' hf_xet"
  exit 1
fi

echo "==[5/7] SFT QLoRA  (base=$HUNTER_BASE_MODEL  grad_accum=$GRAD_ACCUM  max_seq=$MAX_SEQ_LEN)"
python -m hunter_llm.train.sft_qlora \
  --dataset-jsonl data/processed/sft_train.jsonl \
  --output-dir outputs/hunter-lora \
  --model-name "$HUNTER_BASE_MODEL" \
  --epochs "$SFT_EPOCHS" \
  --grad-accum "$GRAD_ACCUM" \
  --max-seq-length "$MAX_SEQ_LEN" \
  --report-to "$REPORT_TO"

if [[ "${SKIP_DPO:-0}" != "1" ]]; then
  echo "==[6a/7] DPO QLoRA  (grad_accum=$GRAD_ACCUM)"
  python -m hunter_llm.train.dpo_qlora \
    --dataset-jsonl data/processed/dpo_pairs.jsonl \
    --output-dir outputs/hunter-dpo-lora \
    --model-name "$HUNTER_BASE_MODEL" \
    --sft-adapter-dir outputs/hunter-lora \
    --epochs "$DPO_EPOCHS" \
    --grad-accum "$GRAD_ACCUM" \
    --report-to "$REPORT_TO"
  FINAL_ADAPTER=outputs/hunter-dpo-lora
else
  echo "==[6a/7] DPO skipped (SKIP_DPO=1)"
  FINAL_ADAPTER=outputs/hunter-lora
fi

if [[ "${SKIP_MERGE:-0}" != "1" ]]; then
  echo "==[6b/7] Merge LoRA into base weights"
  python -m hunter_llm.infer.merge_lora \
    --base-model "$HUNTER_BASE_MODEL" \
    --adapter-dir "$FINAL_ADAPTER" \
    --out-dir outputs/hunter-merged \
    --dtype bf16
  PUSH_FOLDER=outputs/hunter-merged
else
  echo "==[6b/7] Merge skipped — pushing adapter only"
  PUSH_FOLDER="$FINAL_ADAPTER"
fi

echo "==[7/7] Push to Hugging Face Hub: $HF_MODEL_REPO"
python -m hunter_llm.infer.hf_push \
  --repo "$HF_MODEL_REPO" \
  --folder "$PUSH_FOLDER" \
  --repo-type model \
  --commit-message "hunter-llm: SFT + DPO ($(date -u +%Y-%m-%dT%H:%M:%SZ))"

cat <<EOF

==============================================================
HunterLLM run complete.
  Base model:       $HUNTER_BASE_MODEL
  Final adapter:    $FINAL_ADAPTER
  Pushed:           $PUSH_FOLDER -> https://huggingface.co/$HF_MODEL_REPO

Next: in the RunPod UI, terminate this pod to stop billing.
On any machine: hunter-llm chat --merged-model $HF_MODEL_REPO
==============================================================
EOF
