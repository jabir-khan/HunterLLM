#!/usr/bin/env bash
# HunterLLM end-to-end training on a fresh RunPod (or any CUDA Ubuntu) pod.
#
# Required env (export before running, or place in a .env file in repo root):
#   HF_TOKEN                Hugging Face write token (accepts Llama 3 license)
#   HF_MODEL_REPO           Target HF repo for the merged model (e.g. jabir-khan/HunterLLM-8B)
# Optional env:
#   HF_DATASET_REPO         If set, pull curated dataset from this HF dataset repo
#                           (skips local data collection on the pod).
#   HUNTER_BASE_MODEL       Defaults to meta-llama/Meta-Llama-3-8B-Instruct
#   SFT_EPOCHS              Defaults to 1
#   DPO_EPOCHS              Defaults to 0.5
#   SKIP_DPO=1              Skip the DPO stage entirely
#   SKIP_MERGE=1            Skip the merge stage (push adapter only)
#   WANDB_API_KEY           Optional: enables Weights & Biases dashboards
#
# Usage on a fresh pod:
#   git clone https://github.com/jabir-khan/HunterLLM.git && cd HunterLLM
#   export HF_TOKEN=hf_xxx HF_MODEL_REPO=jabir-khan/HunterLLM-8B
#   # optional: export HF_DATASET_REPO=jabir-khan/hunter-llm-sft-v1
#   bash scripts/runpod_bootstrap.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [[ -f .env ]]; then
  # shellcheck disable=SC1091
  set -a; source .env; set +a
fi

: "${HF_TOKEN:?Set HF_TOKEN (Hugging Face write token)}"
: "${HF_MODEL_REPO:?Set HF_MODEL_REPO (e.g. jabir-khan/HunterLLM-8B)}"
HUNTER_BASE_MODEL="${HUNTER_BASE_MODEL:-meta-llama/Meta-Llama-3-8B-Instruct}"
SFT_EPOCHS="${SFT_EPOCHS:-1}"
DPO_EPOCHS="${DPO_EPOCHS:-0.5}"

echo "==[1/7] Sanity check GPU"
python -c "import torch; assert torch.cuda.is_available(), 'No CUDA GPU detected'; print(torch.cuda.get_device_name(0))"

echo "==[2/7] Install package + training extras"
pip install --upgrade pip wheel
pip install -e ".[train]"

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
  python -m hunter_llm.infer.hf_pull --repo "$HF_DATASET_REPO" --out data --repo-type dataset
else
  echo "    No HF_DATASET_REPO set — building dataset on the pod (will clone repos + fetch NVD)"
  python -m hunter_llm.cli bootstrap-data --skip-trickest --full
fi

ls -la data/processed/ || true

echo "==[5/7] SFT QLoRA"
python -m hunter_llm.train.sft_qlora \
  --dataset-jsonl data/processed/sft_train.jsonl \
  --output-dir outputs/hunter-lora \
  --model-name "$HUNTER_BASE_MODEL" \
  --epochs "$SFT_EPOCHS" \
  --report-to "$REPORT_TO"

if [[ "${SKIP_DPO:-0}" != "1" ]]; then
  echo "==[6a/7] DPO QLoRA"
  python -m hunter_llm.train.dpo_qlora \
    --dataset-jsonl data/processed/dpo_pairs.jsonl \
    --output-dir outputs/hunter-dpo-lora \
    --model-name "$HUNTER_BASE_MODEL" \
    --sft-adapter-dir outputs/hunter-lora \
    --epochs "$DPO_EPOCHS" \
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
