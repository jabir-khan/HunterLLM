"""Mix rebalancing for the SFT dataset — turn a reference-heavy corpus into a
result-oriented one.

The raw v2+v3 merge is dominated by encyclopedic prose (CVE/NVD descriptions,
KEV, Metasploit module docs, ATT&CK, long write-ups). Trained as-is, the model
learns to write *about* security instead of *doing* it — the "chatty model"
failure mode. This pass fixes the mix in two moves, applied AFTER dedup so the
upweighting survives:

  CAP      hard ceiling per reference bucket (drop the tail by random sample) so
           breadth is retained without letting one source swamp the signal.
  WEIGHT   integer repeat factor for the result/"brain" buckets (reasoning
           chains, tool invocations, disclosed-report methodology, payloads,
           the user's own reports) so the operator-style rows are seen more.

Both are keyed on `meta.kind`. Lookups try the exact kind first, then a family
prefix (e.g. every `reasoning_*` / `personal_*` kind), then the default.
"""

from __future__ import annotations

import json
import random
from collections import defaultdict
from pathlib import Path
from typing import Any

# --- Reference buckets: hard ceilings (keep breadth, kill the swamp) ---------
# None / absent => keep all. Values chosen to retain coverage while stopping any
# single encyclopedic source from dominating the loss.
DEFAULT_CAPS: dict[str, int] = {
    "nvd_v2": 1500,        # CVE descriptions — most repetitive, cap hardest
    "kev_v2": 600,
    "metasploit_v2": 800,
    "attack_v2": 400,
    "writeup_v2": 2500,    # write-ups carry real methodology — keep more
    # owasp_v2 (~243) is small and high-value — no cap
    "nuclei_v3": 900,      # concrete YAML but many near-identical CVE templates
}

# --- Result / "brain" buckets: repeat factors (upweight the doing) -----------
# Exact kinds first; PREFIX families catch every suffix variant.
DEFAULT_WEIGHTS: dict[str, int] = {
    "tool_invocation": 3,
    "report_reasoning_bugreader": 2,  # the user's own circle of reports
    "report_reasoning_hackerone": 1,  # already capped upstream at ~700
    "payload_v3": 1,
    "wordlist_v3": 1,
}

# Family-prefix weights (applied when no exact match in DEFAULT_WEIGHTS).
DEFAULT_WEIGHT_PREFIXES: dict[str, int] = {
    "reasoning_": 4,   # smallest bucket, highest signal — the operator's judgment
    "personal_": 3,    # the user's own voice / offensive style
}


def _lookup(kind: str, exact: dict[str, int], prefixes: dict[str, int], default: int | None) -> int | None:
    if kind in exact:
        return exact[kind]
    for pref, val in prefixes.items():
        if kind.startswith(pref):
            return val
    return default


def rebalance_jsonl(
    in_path: Path,
    out_path: Path,
    *,
    caps: dict[str, int] | None = None,
    weights: dict[str, int] | None = None,
    weight_prefixes: dict[str, int] | None = None,
    seed: int = 42,
) -> dict[str, int]:
    """Read `in_path`, apply per-kind caps + repeat weights, shuffle, write.

    Returns a per-kind count of the *final* mix (plus `_total`). Rows without a
    recognisable `meta.kind` are passed through once (weight 1, no cap).
    """
    caps = DEFAULT_CAPS if caps is None else caps
    weights = DEFAULT_WEIGHTS if weights is None else weights
    weight_prefixes = DEFAULT_WEIGHT_PREFIXES if weight_prefixes is None else weight_prefixes
    rng = random.Random(seed)

    by_kind: dict[str, list[dict[str, Any]]] = defaultdict(list)
    with in_path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            kind = (row.get("meta") or {}).get("kind") or "?"
            by_kind[kind].append(row)

    final: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    for kind, rows in by_kind.items():
        cap = _lookup(kind, caps, {}, None)
        if cap is not None and len(rows) > cap:
            rows = rng.sample(rows, cap)
        weight = _lookup(kind, weights, weight_prefixes, 1) or 1
        emitted = rows * weight
        counts[kind] = len(emitted)
        final.extend(emitted)

    rng.shuffle(final)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as w:
        for row in final:
            w.write(json.dumps(row, ensure_ascii=False) + "\n")

    counts["_total"] = len(final)
    return counts
