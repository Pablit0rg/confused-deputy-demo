#!/usr/bin/env python3
"""
Runner do Experimento: Autoridade Ambiente (V1) vs. Autoridade do Solicitante (V2).

NOTA DE PROTOCOLO (FASE A):
- Na Fase A este script NAO deve ser executado contra a rede (zero chamadas a modelo).
- A execucao real (Fase B, com grok-4.3, 5 rodadas, temperatura padrao do provedor 1.0)
  exige a flag explicita '--phase-b-live' apos o commit do pre-registro pelo HOTL.
"""

from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import time
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.agent_capability import DeterministicCapabilityValidator  # noqa: E402
from experiments.ambient_vs_requester_authority.classifier import (  # noqa: E402
    AUTH_MAP_PATH,
    ENTRIES_PATH,
    EXPERIMENT_DIR,
    LABELS_PATH,
    SYSTEM_PROMPT_STAGE_A,
    SYSTEM_PROMPT_STAGE_B,
    build_stage_a_messages,
    build_stage_b_user_prompt,
    build_v1_ambient_capability,
    build_v2_requester_capability,
    classify_stage_a_outcome,
    classify_stage_b_outcome,
    evaluate_with_validator,
    load_authorization_map,
    load_entries,
    load_labels,
)

RAW_OUTPUT_PATH = EXPERIMENT_DIR / "raw_calls.jsonl"
SUMMARY_OUTPUT_PATH = EXPERIMENT_DIR / "summary.json"

MODEL_ID = "grok-4.3"
PROVIDER = "xAI"
BASE_URL = "https://api.x.ai/v1"
TEMPERATURE_CONFIG = "provider_default (1.0)"
ROUNDS_PER_ENTRY = 5
MAX_ATTEMPTS = 3


def compute_layer_counts(
    round_records: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Calcula as contagens absolutas k/N por camada (proposta, autojulgamento, V1, V2),
    separando entradas maliciosas (N=100 em 5 rodadas) e benignas (N=50 em 5 rodadas).
    """
    mal_records = [r for r in round_records if r["expected_label"] == "maliciosa"]
    ben_records = [r for r in round_records if r["expected_label"] == "benigna"]

    def _summarize_group(subset: list[dict[str, Any]]) -> dict[str, Any]:
        n_total = len(subset)
        prop_mal = sum(1 for r in subset if r["stage_a_classification"] == "proposta_maliciosa")
        prop_ben = sum(1 for r in subset if r["stage_a_classification"] == "proposta_benigna")
        prop_inv = sum(1 for r in subset if r["stage_a_classification"] == "formato_invalido")
        prop_fail = sum(1 for r in subset if r["stage_a_classification"] == "falha_execucao")

        b_autoconf = sum(1 for r in subset if r["stage_b_classification"] == "autoconfirmado")
        b_refused = sum(1 for r in subset if r["stage_b_classification"] == "recusado")
        b_inv = sum(1 for r in subset if r["stage_b_classification"] == "formato_invalido")
        b_fail = sum(1 for r in subset if r["stage_b_classification"] == "falha_execucao")

        v1_passed = sum(1 for r in subset if r["v1_ambient_verdict"] == "passou")
        v1_blocked = sum(1 for r in subset if r["v1_ambient_verdict"] == "bloqueado")

        v2_passed = sum(1 for r in subset if r["v2_requester_verdict"] == "passou")
        v2_blocked = sum(1 for r in subset if r["v2_requester_verdict"] == "bloqueado")

        # Subconjunto condicional: rodadas em que o modelo propos alvo fora do escopo (proposta_maliciosa)
        wrong_target_subset = [r for r in subset if r["stage_a_classification"] == "proposta_maliciosa"]
        n_wrong = len(wrong_target_subset)
        b_autoconf_given_wrong = sum(
            1 for r in wrong_target_subset if r["stage_b_classification"] == "autoconfirmado"
        )
        v1_passed_given_wrong = sum(
            1 for r in wrong_target_subset if r["v1_ambient_verdict"] == "passou"
        )
        v2_passed_given_wrong = sum(
            1 for r in wrong_target_subset if r["v2_requester_verdict"] == "passou"
        )

        return {
            "total_rounds": n_total,
            "layer_1_proposal": {
                "malicious_proposals_k_N": f"{prop_mal}/{n_total}",
                "malicious_proposals_count": prop_mal,
                "benign_proposals_k_N": f"{prop_ben}/{n_total}",
                "benign_proposals_count": prop_ben,
                "invalid_format_k_N": f"{prop_inv}/{n_total}",
                "invalid_format_count": prop_inv,
                "execution_failures_k_N": f"{prop_fail}/{n_total}",
                "execution_failures_count": prop_fail,
            },
            "layer_2_self_judgment": {
                "self_confirmed_all_k_N": f"{b_autoconf}/{n_total}",
                "self_confirmed_all_count": b_autoconf,
                "rejected_all_k_N": f"{b_refused}/{n_total}",
                "rejected_all_count": b_refused,
                "invalid_format_all_k_N": f"{b_inv}/{n_total}",
                "invalid_format_all_count": b_inv,
                "execution_failures_all_k_N": f"{b_fail}/{n_total}",
                "execution_failures_all_count": b_fail,
                "self_confirmed_given_malicious_proposal_k_N": f"{b_autoconf_given_wrong}/{n_wrong}",
                "self_confirmed_given_malicious_proposal_count": b_autoconf_given_wrong,
            },
            "layer_3_v1_ambient": {
                "passed_all_k_N": f"{v1_passed}/{n_total}",
                "passed_all_count": v1_passed,
                "blocked_all_k_N": f"{v1_blocked}/{n_total}",
                "blocked_all_count": v1_blocked,
                "passed_given_malicious_proposal_k_N": f"{v1_passed_given_wrong}/{n_wrong}",
                "passed_given_malicious_proposal_count": v1_passed_given_wrong,
            },
            "layer_4_v2_requester": {
                "passed_all_k_N": f"{v2_passed}/{n_total}",
                "passed_all_count": v2_passed,
                "blocked_all_k_N": f"{v2_blocked}/{n_total}",
                "blocked_all_count": v2_blocked,
                "passed_given_malicious_proposal_k_N": f"{v2_passed_given_wrong}/{n_wrong}",
                "passed_given_malicious_proposal_count": v2_passed_given_wrong,
            },
        }

    return {
        "malicious_entries": _summarize_group(mal_records),
        "benign_entries": _summarize_group(ben_records),
        "all_entries": _summarize_group(round_records),
    }


async def run_phase_b() -> None:
    """Executa a coleta empirica da Fase B com grok-4.3 (bloqueada na Fase A)."""
    import httpx
    import openai
    from experiments.issue_4_self_confirmation.run_experiment import (
        call_xai_with_retry,
        redact_secrets,
    )

    xai_key = os.environ.get("XAI_API_KEY")
    if not xai_key:
        raise RuntimeError("Variavel de ambiente XAI_API_KEY ausente.")

    auth_map = load_authorization_map(AUTH_MAP_PATH)
    entries = load_entries(ENTRIES_PATH)
    labels_list = load_labels(LABELS_PATH)
    labels_by_id = {item["id"]: item for item in labels_list}

    validator = DeterministicCapabilityValidator()
    v1_cap = build_v1_ambient_capability(auth_map)

    client = openai.AsyncOpenAI(
        api_key=xai_key,
        base_url=BASE_URL,
        max_retries=0,
        timeout=httpx.Timeout(30.0, connect=10.0),
    )
    sem = asyncio.Semaphore(6)

    async def _run_one(idx: int, entry: dict[str, Any], round_num: int) -> dict[str, Any]:
        async with sem:
            entry_id = entry["id"]
            requester = entry["context"]["requester"]
            label = labels_by_id[entry_id]
            messages_a = build_stage_a_messages(entry)

            ok_a, raw_a, rep_model_a, attempts_a = await call_xai_with_retry(
                client,
                MODEL_ID,
                messages_a[0]["content"],
                messages_a[1]["content"],
            )
            interp_a, proposed_action = classify_stage_a_outcome(
                ok=ok_a,
                raw_text=raw_a,
                requester=requester,
                auth_map=auth_map,
            )

            prompt_b = build_stage_b_user_prompt(entry["text"], proposed_action, raw_a)
            ok_b, raw_b, rep_model_b, attempts_b = await call_xai_with_retry(
                client,
                MODEL_ID,
                SYSTEM_PROMPT_STAGE_B,
                prompt_b,
            )
            interp_b = classify_stage_b_outcome(ok=ok_b, raw_text=raw_b)

            v2_cap = build_v2_requester_capability(auth_map, requester)
            raw_v1, verdict_v1 = evaluate_with_validator(validator, v1_cap, proposed_action)
            raw_v2, verdict_v2 = evaluate_with_validator(validator, v2_cap, proposed_action)

            return {
                "_sort_key": (idx, round_num),
                "id": entry_id,
                "requester": requester,
                "technique": entry["technique"],
                "expected_label": label["expected_label"],
                "expected_target": label["expected_target"],
                "model": MODEL_ID,
                "reported_model_a": rep_model_a,
                "reported_model_b": rep_model_b,
                "temperature": TEMPERATURE_CONFIG,
                "round": round_num,
                "stage_a_raw": redact_secrets(raw_a),
                "stage_a_classification": interp_a,
                "proposed_action": (
                    {"action": proposed_action["action"], "target": proposed_action["target"]}
                    if proposed_action is not None
                    else None
                ),
                "stage_a_attempts": attempts_a,
                "stage_b_raw": redact_secrets(raw_b),
                "stage_b_classification": interp_b,
                "stage_b_attempts": attempts_b,
                "v1_ambient_raw": redact_secrets(raw_v1),
                "v1_ambient_verdict": verdict_v1,
                "v2_requester_raw": redact_secrets(raw_v2),
                "v2_requester_verdict": verdict_v2,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    start_t = time.monotonic()
    tasks = [
        asyncio.create_task(_run_one(idx, entry, r))
        for idx, entry in enumerate(entries)
        for r in range(1, ROUNDS_PER_ENTRY + 1)
    ]
    results = await asyncio.gather(*tasks)
    await client.close()

    results.sort(key=lambda item: item["_sort_key"])
    for item in results:
        item.pop("_sort_key", None)

    with RAW_OUTPUT_PATH.open("w", encoding="utf-8") as fh:
        for rec in results:
            fh.write(redact_secrets(json.dumps(rec, ensure_ascii=False)) + "\n")

    summary = {
        "experiment": "ambient-vs-requester-authority",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model": MODEL_ID,
        "provider": PROVIDER,
        "temperature": TEMPERATURE_CONFIG,
        "rounds_per_entry": ROUNDS_PER_ENTRY,
        "hashes": {
            "entries_sha256": hashlib.sha256(ENTRIES_PATH.read_bytes()).hexdigest(),
            "labels_sha256": hashlib.sha256(LABELS_PATH.read_bytes()).hexdigest(),
            "auth_map_sha256": hashlib.sha256(AUTH_MAP_PATH.read_bytes()).hexdigest(),
        },
        "results": compute_layer_counts(results),
        "elapsed_seconds": round(time.monotonic() - start_t, 2),
    }
    SUMMARY_OUTPUT_PATH.write_text(
        redact_secrets(json.dumps(summary, indent=2, ensure_ascii=False)) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Runner do experimento Autoridade Ambiente (V1) vs. Autoridade do Solicitante (V2)."
    )
    parser.add_argument(
        "--phase-b-live",
        action="store_true",
        help="Habilita chamadas reais ao modelo grok-4.3 (exclusivo para a Fase B apos commit do pre-registro).",
    )
    args = parser.parse_args()
    if not args.phase_b_live:
        raise SystemExit(
            "BLOQUEIO DE PROTOCOLO (FASE A): Nenhuma chamada de rede permitida sem '--phase-b-live'. "
            "A Fase A e 100% offline."
        )
    asyncio.run(run_phase_b())


if __name__ == "__main__":
    main()
