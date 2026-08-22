"""
NeuroShell IRE — Config 4: Full Pipeline with Qwen 2.5 Coder 7B
FAIL-SAFE: Checkpoints + cache. Resume on re-run.
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import json
import time
import hashlib
from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict
from tqdm import tqdm

DATASET_PATH = os.path.join(os.path.dirname(__file__), "..", "golden_dataset.jsonl")
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")
CACHE_DIR = os.path.join(os.path.dirname(__file__), "cache")
CONFIG_NAME = "Full Pipeline (Qwen 2.5)"
MODEL = "qwen2.5-coder:7b"


# -- Cache & Checkpoint (same infra as exp1) --

def _cache_key(model, input_text):
    return hashlib.sha256(f"{model}::{input_text}".encode()).hexdigest()[:16]

def _cache_path(model):
    safe = model.replace(":", "_").replace(".", "_")
    return os.path.join(CACHE_DIR, f"llm_cache_{safe}.json")

def _load_cache(model):
    p = _cache_path(model)
    if os.path.exists(p):
        try:
            with open(p, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def _save_cache(model, cache):
    os.makedirs(CACHE_DIR, exist_ok=True)
    with open(_cache_path(model), "w", encoding="utf-8") as f:
        json.dump(cache, f, ensure_ascii=False, indent=1)

def _ckpt_path(name):
    safe = name.replace(" ", "_").replace("(", "").replace(")", "").lower()
    return os.path.join(RESULTS_DIR, f"checkpoint_{safe}.json")

def _load_ckpt(name):
    p = _ckpt_path(name)
    if os.path.exists(p):
        try:
            with open(p, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return None

def _save_ckpt(name, data):
    os.makedirs(RESULTS_DIR, exist_ok=True)
    with open(_ckpt_path(name), "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)


# -- Dataset --

def load_dataset(path):
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            item = json.loads(line)
            if "_meta" in item:
                continue
            records.append(item)
    return records


def main():
    from src.pipeline.ire_pipeline import IREPipeline
    from src.schemas.intent_schema import ParseRequestV2

    os.makedirs(RESULTS_DIR, exist_ok=True)
    os.makedirs(CACHE_DIR, exist_ok=True)

    print(f"[*] Loading dataset from {DATASET_PATH}...")
    dataset = load_dataset(DATASET_PATH)
    print(f"[*] Loaded {len(dataset)} records")

    # Check if already complete
    checkpoint = _load_ckpt(CONFIG_NAME)
    if checkpoint and checkpoint["completed"] >= len(dataset):
        print(f"[SKIP] {CONFIG_NAME} already complete.")
    else:
        print(f"\n{'='*60}")
        print(f"  Running: {CONFIG_NAME}")
        print(f"  Model: {MODEL}")
        print(f"  Dataset: {len(dataset)} records")
        print(f"{'='*60}")

        pipeline = IREPipeline()

        if checkpoint:
            row_details = checkpoint["row_details"]
            start_idx = checkpoint["completed"]
            latencies = checkpoint["latencies"]
            per_category = defaultdict(lambda: {"total": 0, "correct": 0}, checkpoint["per_category"])
            per_intent = defaultdict(lambda: {"total": 0, "correct": 0}, checkpoint["per_intent"])
            c = checkpoint["counters"]
            correct_wf = c["correct_wf"]
            false_positives = c["false_positives"]
            caught_flaws = c["caught_flaws"]
            print(f"  [RESUME] Starting from record {start_idx + 1}")
        else:
            row_details = []
            start_idx = 0
            latencies = []
            per_category = defaultdict(lambda: {"total": 0, "correct": 0})
            per_intent = defaultdict(lambda: {"total": 0, "correct": 0})
            correct_wf = 0
            false_positives = 0
            caught_flaws = 0

        well_formed = [r for r in dataset if r["category"] == "well_formed"]
        flawed = [r for r in dataset if r["category"] != "well_formed"]
        errors_count = 0

        pbar = tqdm(range(start_idx, len(dataset)), desc=f"  {CONFIG_NAME}", unit="rec",
                    initial=start_idx, total=len(dataset), ncols=100, leave=True,
                    mininterval=0.1)

        for idx in pbar:
            record = dataset[idx]
            is_flawed = record["category"] != "well_formed"

            try:
                req = ParseRequestV2(
                    command=record["input"],
                    role=record.get("expected_role", "analyst"),
                    session_id=f"exp1-{CONFIG_NAME}-{idx}",
                )
                start = time.time()
                resp = pipeline.parse(req)
                elapsed_ms = (time.time() - start) * 1000.0

                predicted_intent = resp.intent.value if resp.intent else None
                predicted_target = resp.target.value if resp.target else None
                predicted_cve = resp.cve_ids[0] if resp.cve_ids else None

                has_block = any(
                    not f.passed and f.severity == "block"
                    for f in getattr(resp, "validation_findings", [])
                )
                decision = "BLOCKED" if (resp.status != "success" or has_block or predicted_intent == "REJECTED") else "ALLOWED"

            except Exception as e:
                elapsed_ms = 0
                errors_count += 1
                print(f"\n    [ERROR] Record {idx+1} failed: {e}")
                predicted_intent = None
                predicted_target = None
                predicted_cve = None
                decision = "ERROR"

            latencies.append(elapsed_ms)

            cat = record["category"]
            per_category[cat]["total"] += 1
            row_correct = False

            if not is_flawed:
                intent_ok = (predicted_intent == record["expected_intent"])
                target_ok = (
                    not record.get("expected_target")
                    or predicted_target == record["expected_target"]
                )
                per_intent[record["expected_intent"]]["total"] += 1

                if decision == "ALLOWED" and intent_ok and target_ok:
                    correct_wf += 1
                    per_category[cat]["correct"] += 1
                    per_intent[record["expected_intent"]]["correct"] += 1
                    row_correct = True
                else:
                    false_positives += 1
            else:
                if decision == "BLOCKED":
                    caught_flaws += 1
                    per_category[cat]["correct"] += 1
                    row_correct = True

            row_details.append({
                "idx": idx,
                "input": record["input"][:80],
                "category": cat,
                "expected_intent": record.get("expected_intent"),
                "predicted_intent": predicted_intent,
                "decision": decision,
                "correct": row_correct,
                "latency_ms": round(elapsed_ms, 1),
            })

            total_done = correct_wf + caught_flaws + false_positives
            acc_pct = (total_done / (idx + 1)) * 100 if (idx + 1) > 0 else 0
            pbar.set_postfix_str(f"{cat[:8]:8s} {predicted_intent or 'None':20s} {elapsed_ms:6.0f}ms acc={acc_pct:.0f}%")

            if (idx + 1) % 5 == 0 or (idx + 1) == len(dataset):
                _save_ckpt(CONFIG_NAME, {
                    "config": CONFIG_NAME,
                    "model": MODEL,
                    "completed": idx + 1,
                    "total": len(dataset),
                    "row_details": row_details,
                    "latencies": latencies,
                    "per_category": dict(per_category),
                    "per_intent": dict(per_intent),
                    "counters": {
                        "correct_wf": correct_wf,
                        "false_positives": false_positives,
                        "caught_flaws": caught_flaws,
                    },
                    "errors": errors_count,
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                })

        pbar.close()

    # Compute results
    checkpoint = _load_ckpt(CONFIG_NAME)
    row_details = checkpoint["row_details"]
    latencies = checkpoint["latencies"]
    c = checkpoint["counters"]
    per_category = defaultdict(lambda: {"total": 0, "correct": 0}, checkpoint["per_category"])
    per_intent = defaultdict(lambda: {"total": 0, "correct": 0}, checkpoint["per_intent"])

    well_formed = [r for r in dataset if r["category"] == "well_formed"]
    flawed = [r for r in dataset if r["category"] != "well_formed"]

    latencies_sorted = sorted(latencies) if latencies else [0]
    n = len(latencies_sorted)
    accuracy = (c["correct_wf"] / len(well_formed)) * 100 if well_formed else 0
    catch_rate = (c["caught_flaws"] / len(flawed)) * 100 if flawed else 0
    fp_rate = (c["false_positives"] / len(well_formed)) * 100 if well_formed else 0

    results = {
        "config": CONFIG_NAME,
        "model": MODEL,
        "dataset": os.path.basename(DATASET_PATH),
        "total_records": len(dataset),
        "well_formed_count": len(well_formed),
        "flawed_count": len(flawed),
        "errors": checkpoint.get("errors", 0),
        "metrics": {
            "intent_accuracy_pct": round(accuracy, 2),
            "hallucination_catch_rate_pct": round(catch_rate, 2),
            "false_positive_rate_pct": round(fp_rate, 2),
            "p50_latency_ms": round(latencies_sorted[int(n * 0.50)], 1),
            "p95_latency_ms": round(latencies_sorted[min(int(n * 0.95), n - 1)], 1),
            "p99_latency_ms": round(latencies_sorted[min(int(n * 0.99), n - 1)], 1),
            "mean_latency_ms": round(sum(latencies) / len(latencies), 1) if latencies else 0,
        },
        "per_category": {
            cat: {
                "total": v["total"],
                "correct": v["correct"],
                "accuracy_pct": round((v["correct"] / v["total"]) * 100, 2) if v["total"] else 0,
            }
            for cat, v in sorted(per_category.items())
        },
        "per_intent": {
            intent: {
                "total": v["total"],
                "correct": v["correct"],
                "accuracy_pct": round((v["correct"] / v["total"]) * 100, 2) if v["total"] else 0,
            }
            for intent, v in sorted(per_intent.items())
        },
        "row_details": row_details,
    }

    safe = CONFIG_NAME.replace(" ", "_").replace("(", "").replace(")", "").lower()
    out_path = os.path.join(RESULTS_DIR, f"exp1_{safe}.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print(f"\n--- {CONFIG_NAME} Summary ---")
    print(f"  Intent Accuracy:    {accuracy:.2f}%")
    print(f"  Catch Rate:         {catch_rate:.2f}%")
    print(f"  False Positive:     {fp_rate:.2f}%")
    print(f"  p50 Latency:        {results['metrics']['p50_latency_ms']}ms")
    print(f"  p95 Latency:        {results['metrics']['p95_latency_ms']}ms")
    print(f"  [SAVED] {out_path}")


if __name__ == "__main__":
    main()
