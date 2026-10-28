# NeuroShell IRE — Full Pipeline Evaluator
# Evaluates neuroshell-ire against benchmark dataset and calculates empirical accuracy, catch rate, FP rate, and latencies.

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import json
import time
from typing import Dict, Any, List

from src.pipeline.ire_pipeline import IREPipeline
from src.schemas.intent_schema import ParseRequestV2


def run_pipeline_eval(dataset_path: str = "eval/golden_dataset.jsonl") -> Dict[str, Any]:
    print(f"[*] Initializing IREPipeline for Evaluation on {dataset_path}...")
    pipeline = IREPipeline()

    records = []
    with open(dataset_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            item = json.loads(line)
            if "_meta" in item:
                continue
            records.append(item)

    total_records = len(records)
    well_formed_items = [r for r in records if r["category"] == "well_formed"]
    flawed_items = [r for r in records if r["category"] != "well_formed"]

    correct_well_formed = 0
    false_positives = 0
    caught_flaws = 0
    latencies = []

    for idx, record in enumerate(records, start=1):
        req = ParseRequestV2(command=record["input"], role="analyst", session_id="eval-sess")
        start = time.time()
        resp = pipeline.parse(req)
        elapsed_ms = (time.time() - start) * 1000.0
        latencies.append(elapsed_ms)

        is_flawed = record["category"] != "well_formed"
        has_blocked_or_warned = (
            resp.status != "success" or
            any(not f.passed for f in getattr(resp, "validation_findings", []))
        )

        if not is_flawed:
            # Well-formed command evaluation
            if resp.status == "success" and not any(not f.passed and f.severity == "block" for f in getattr(resp, "validation_findings", [])):
                # Check intent prediction accuracy
                actual_intent = resp.intent.value if resp.intent else None
                actual_target = resp.target.value if resp.target else None
                intent_ok = (actual_intent == record["expected_intent"])
                target_ok = (not record["expected_target"] or actual_target == record["expected_target"])

                if intent_ok and target_ok:
                    correct_well_formed += 1
                else:
                    false_positives += 1
            else:
                false_positives += 1
        else:
            # Flawed command evaluation
            if has_blocked_or_warned or resp.intent and resp.intent.value == "REJECTED":
                caught_flaws += 1

        pct = (idx / total_records) * 100.0
        print(f"[{idx}/{total_records} - {pct:.1f}%] ({record['category']}) '{record['input'][:40]}...' -> {elapsed_ms:.1f}ms (Status: {resp.status})")
        sys.stdout.flush()

    latencies_sorted = sorted(latencies) if latencies else [0]
    n = len(latencies_sorted)
    p50 = latencies_sorted[int(n * 0.50)]
    p95 = latencies_sorted[min(int(n * 0.95), n - 1)]

    accuracy = (correct_well_formed / len(well_formed_items)) * 100.0 if well_formed_items else 0.0
    catch_rate = (caught_flaws / len(flawed_items)) * 100.0 if flawed_items else 0.0
    fp_rate = (false_positives / len(well_formed_items)) * 100.0 if well_formed_items else 0.0

    metrics = {
        "configuration": "Full Pipeline (Production)",
        "total_examples": total_records,
        "accuracy": round(accuracy, 2),
        "hallucination_catch_rate": round(catch_rate, 2),
        "false_positive_rate": round(fp_rate, 2),
        "p50_latency_ms": round(p50, 1),
        "p95_latency_ms": round(p95, 1),
    }

    print("\n=== FULL PIPELINE RESULTS SUMMARY ===")
    print(json.dumps(metrics, indent=2))
    return metrics


if __name__ == "__main__":
    run_pipeline_eval()
