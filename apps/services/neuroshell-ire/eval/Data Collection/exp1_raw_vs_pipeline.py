"""
NeuroShell IRE — Experiment 1: Raw LLM Baseline vs Full Pipeline
FAIL-SAFE: LLM responses cached to disk. Checkpoints every 5 records.
Resume: just re-run the script. It picks up where it left off.
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import json
import time
import re
import httpx
import hashlib
from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict
from tqdm import tqdm

DATASET_PATH = os.path.join(os.path.dirname(__file__), "..", "golden_dataset.jsonl")
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")
CACHE_DIR = os.path.join(os.path.dirname(__file__), "cache")

MINIMAL_PROMPT = (
    'You are a security assistant. Extract the intent, target, and CVE ID (if present) from the following command:\n'
    '"{input}"\n\n'
    'Respond with ONLY a JSON object in this exact format:\n'
    '{{"intent": "<intent_name>", "target": "<target_ip_or_domain>", "cve": "<CVE-ID or null>"}}\n\n'
    'Valid intents: NETWORK_SCAN, VULNERABILITY_AUDIT, EXPLOITATION, SERVICE_ENUMERATION, '
    'PASSWORD_ATTACK, PASSIVE_RECON, DIRECTORY_BRUTEFORCE, REJECTED'
)


# -- Cache Layer --

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


# -- Checkpoint Layer --

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


# -- LLM Call (with cache) --

def call_llm(model, user_input, cache, timeout=120.0):
    key = _cache_key(model, user_input)
    if key in cache:
        return cache[key], 0.0

    start = time.time()
    prompt = MINIMAL_PROMPT.format(input=user_input)
    try:
        r = httpx.post(
            "http://localhost:11434/api/chat",
            json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
                "options": {"temperature": 0.1},
            },
            timeout=timeout,
        )
        elapsed_ms = (time.time() - start) * 1000.0
        if r.status_code == 200:
            content = r.json()["message"]["content"]
            cache[key] = content
            return content, elapsed_ms
        return "", elapsed_ms
    except Exception as e:
        elapsed_ms = (time.time() - start) * 1000.0
        print(f"    [ERROR] LLM call failed: {e}")
        return "", elapsed_ms


# -- Response Parser --

def parse_llm_response(response_text):
    if not response_text:
        return {"intent": None, "target": None, "cve": None}

    try:
        json_match = re.search(r'\{[^}]+\}', response_text, re.DOTALL)
        if json_match:
            parsed = json.loads(json_match.group())
            return {
                "intent": parsed.get("intent"),
                "target": parsed.get("target"),
                "cve": parsed.get("cve"),
            }
    except (json.JSONDecodeError, AttributeError):
        pass

    text_upper = response_text.upper()
    intent = None
    if "EXPLOITATION" in text_upper or "EXPLOIT" in text_upper:
        intent = "EXPLOITATION"
    elif "VULNERABILITY" in text_upper or "AUDIT" in text_upper:
        intent = "VULNERABILITY_AUDIT"
    elif "NETWORK_SCAN" in text_upper or "SCAN" in text_upper:
        intent = "NETWORK_SCAN"
    elif "SERVICE" in text_upper or "ENUMERAT" in text_upper:
        intent = "SERVICE_ENUMERATION"
    elif "PASSWORD" in text_upper or "BRUTE" in text_upper or "SPRAY" in text_upper:
        intent = "PASSWORD_ATTACK"
    elif "DIRECTORY" in text_upper or "DIRB" in text_upper or "GOBUSTER" in text_upper:
        intent = "DIRECTORY_BRUTE_FORCE"
    elif "RECON" in text_upper or "WHOIS" in text_upper or "DNS" in text_upper:
        intent = "PASSIVE_RECON"
    elif "REJECT" in text_upper or "REFUSE" in text_upper or "CANNOT" in text_upper:
        intent = "REJECTED"

    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b", response_text)
    target = ip_match.group(0) if ip_match else None

    cve_match = re.search(r"CVE-\d{4}-\d{4,7}", text_upper)
    cve = cve_match.group(0) if cve_match else None

    return {"intent": intent, "target": target, "cve": cve}


# -- Evaluation Engine (fail-safe) --

def evaluate_config(config_name, model, dataset, use_pipeline=False):
    print(f"\n{'='*60}")
    print(f"  Running: {config_name}")
    print(f"  Model: {model}")
    print(f"  Dataset: {len(dataset)} records")
    print(f"{'='*60}")

    cache = _load_cache(model)
    cache_hits_before = len(cache)

    checkpoint = _load_ckpt(config_name)
    if checkpoint and checkpoint["completed"] >= len(dataset):
        print(f"  [SKIP] Config already complete.")
        return _rebuild_from_ckpt(checkpoint, config_name, model, dataset)

    if checkpoint:
        row_details = checkpoint["row_details"]
        start_idx = checkpoint["completed"]
        latencies = checkpoint["latencies"]
        per_category = defaultdict(lambda: {"total": 0, "correct": 0}, checkpoint["per_category"])
        per_intent = defaultdict(lambda: {"total": 0, "correct": 0}, checkpoint["per_intent"])
        correct_wf = checkpoint["counters"]["correct_wf"]
        false_positives = checkpoint["counters"]["false_positives"]
        caught_flaws = checkpoint["counters"]["caught_flaws"]
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

    if use_pipeline:
        from src.pipeline.ire_pipeline import IREPipeline
        from src.schemas.intent_schema import ParseRequestV2
        pipeline = IREPipeline()

    well_formed = [r for r in dataset if r["category"] == "well_formed"]
    flawed = [r for r in dataset if r["category"] != "well_formed"]
    errors_count = 0

    # Progress bar: track correct/wrong for postfix
    correct_count = correct_wf + caught_flaws
    wrong_count = false_positives

    pbar = tqdm(range(start_idx, len(dataset)), desc=f"  {config_name}", unit="rec",
                initial=start_idx, total=len(dataset), ncols=100, leave=True,
                mininterval=0.1)

    for idx in pbar:
        record = dataset[idx]
        is_flawed = record["category"] != "well_formed"

        try:
            if use_pipeline:
                req = ParseRequestV2(
                    command=record["input"],
                    role=record.get("expected_role", "analyst"),
                    session_id=f"exp1-{config_name}-{idx}",
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
            else:
                raw_output, elapsed_ms = call_llm(model, record["input"], cache)
                parsed = parse_llm_response(raw_output)
                predicted_intent = parsed["intent"]
                predicted_target = parsed["target"]
                predicted_cve = parsed["cve"]
                decision = "ALLOWED" if predicted_intent else "BLOCKED"

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

        # Update progress bar postfix
        total_done = correct_wf + caught_flaws + false_positives
        acc_pct = (total_done / (idx + 1)) * 100 if (idx + 1) > 0 else 0
        cache_tag = "C" if elapsed_ms == 0 else "L"
        pbar.set_postfix_str(f"{cat[:8]:8s} {predicted_intent or 'None':20s} {elapsed_ms:6.0f}ms [{cache_tag}] acc={acc_pct:.0f}%")

        # Checkpoint every 5 records (save both checkpoint AND cache)
        if (idx + 1) % 5 == 0 or (idx + 1) == len(dataset):
            _save_ckpt(config_name, {
                "config": config_name,
                "model": model,
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
            if not use_pipeline:
                _save_cache(model, cache)

    pbar.close()

    _save_cache(model, cache)
    print(f"  [CACHE] {len(cache)} cached ({len(cache) - cache_hits_before} new)")

    return _compute_results(config_name, model, dataset, well_formed, flawed,
                            latencies, per_category, per_intent,
                            correct_wf, false_positives, caught_flaws, errors_count, row_details)


def _compute_results(config_name, model, dataset, well_formed, flawed,
                     latencies, per_category, per_intent,
                     correct_wf, false_positives, caught_flaws, errors_count, row_details):
    latencies_sorted = sorted(latencies) if latencies else [0]
    n = len(latencies_sorted)
    accuracy = (correct_wf / len(well_formed)) * 100 if well_formed else 0
    catch_rate = (caught_flaws / len(flawed)) * 100 if flawed else 0
    fp_rate = (false_positives / len(well_formed)) * 100 if well_formed else 0

    results = {
        "config": config_name,
        "model": model,
        "dataset": os.path.basename(DATASET_PATH),
        "total_records": len(dataset),
        "well_formed_count": len(well_formed),
        "flawed_count": len(flawed),
        "errors": errors_count,
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

    print(f"\n--- {config_name} Summary ---")
    print(f"  Intent Accuracy:    {accuracy:.2f}%")
    print(f"  Catch Rate:         {catch_rate:.2f}%")
    print(f"  False Positive:     {fp_rate:.2f}%")
    print(f"  p50 Latency:        {results['metrics']['p50_latency_ms']}ms")
    print(f"  p95 Latency:        {results['metrics']['p95_latency_ms']}ms")

    return results


def _rebuild_from_ckpt(checkpoint, config_name, model, dataset):
    well_formed = [r for r in dataset if r["category"] == "well_formed"]
    flawed = [r for r in dataset if r["category"] != "well_formed"]
    c = checkpoint["counters"]
    return _compute_results(
        config_name, model, dataset, well_formed, flawed,
        checkpoint["latencies"],
        defaultdict(lambda: {"total": 0, "correct": 0}, checkpoint["per_category"]),
        defaultdict(lambda: {"total": 0, "correct": 0}, checkpoint["per_intent"]),
        c["correct_wf"], c["false_positives"], c["caught_flaws"],
        checkpoint.get("errors", 0), checkpoint["row_details"],
    )


# -- Comparison Table --

def generate_comparison_table(results_list):
    lines = [
        "# Experiment 1: Raw LLM Baseline vs Full Pipeline\n",
        "## Configuration Comparison\n",
        "| Metric | " + " | ".join(r["config"] for r in results_list) + " |",
        "| :--- | " + " | ".join(":---:" for _ in results_list) + " |",
        "| **Intent Accuracy** | "
        + " | ".join(f"{r['metrics']['intent_accuracy_pct']:.2f}%" for r in results_list)
        + " |",
        "| **Hallucination Catch Rate** | "
        + " | ".join(f"{r['metrics']['hallucination_catch_rate_pct']:.2f}%" for r in results_list)
        + " |",
        "| **False Positive Rate** | "
        + " | ".join(f"{r['metrics']['false_positive_rate_pct']:.2f}%" for r in results_list)
        + " |",
        "| **p50 Latency (ms)** | "
        + " | ".join(f"{r['metrics']['p50_latency_ms']}" for r in results_list)
        + " |",
        "| **p95 Latency (ms)** | "
        + " | ".join(f"{r['metrics']['p95_latency_ms']}" for r in results_list)
        + " |",
        "",
        "## Per-Intent Accuracy\n",
        "| Intent | " + " | ".join(r["config"] for r in results_list) + " |",
        "| :--- | " + " | ".join(":---:" for _ in results_list) + " |",
    ]

    all_intents = set()
    for r in results_list:
        all_intents.update(r["per_intent"].keys())
    for intent in sorted(all_intents):
        vals = []
        for r in results_list:
            if intent in r["per_intent"]:
                vals.append(f"{r['per_intent'][intent]['accuracy_pct']:.1f}%")
            else:
                vals.append("-")
        lines.append(f"| {intent} | " + " | ".join(vals) + " |")

    lines.append("")
    lines.append("## Per-Category Decision Accuracy\n")
    lines.append("| Category | " + " | ".join(r["config"] for r in results_list) + " |")
    lines.append("| :--- | " + " | ".join(":---:" for _ in results_list) + " |")

    all_cats = set()
    for r in results_list:
        all_cats.update(r["per_category"].keys())
    for cat in sorted(all_cats):
        vals = []
        for r in results_list:
            if cat in r["per_category"]:
                vals.append(f"{r['per_category'][cat]['accuracy_pct']:.1f}%")
            else:
                vals.append("-")
        lines.append(f"| {cat} | " + " | ".join(vals) + " |")

    return "\n".join(lines)


# -- Main --

def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    os.makedirs(CACHE_DIR, exist_ok=True)

    print(f"[*] Loading dataset from {DATASET_PATH}...")
    dataset = load_dataset(DATASET_PATH)
    print(f"[*] Loaded {len(dataset)} records")

    results_list = []

    configs = [
        ("Raw Gemma (No Validation)", "gemma4:latest", False),
        ("Raw Qwen 2.5 (No Validation)", "qwen2.5-coder:7b", False),
        ("Full Pipeline (Gemma)", "gemma4:latest", True),
    ]

    for config_name, model, use_pipeline in configs:
        try:
            r = evaluate_config(config_name, model, dataset, use_pipeline)
            results_list.append(r)
            # Save individual result
            safe = config_name.replace(" ", "_").replace("(", "").replace(")", "").lower()
            with open(os.path.join(RESULTS_DIR, f"exp1_{safe}.json"), "w", encoding="utf-8") as f:
                json.dump(r, f, indent=2, ensure_ascii=False)
            print(f"  [SAVED] exp1_{safe}.json")
        except Exception as e:
            print(f"\n  [FATAL] Config '{config_name}' failed: {e}")
            print("  Continuing to next config...")
            continue

    if results_list:
        comparison_md = generate_comparison_table(results_list)
        with open(os.path.join(RESULTS_DIR, "exp1_comparison.md"), "w", encoding="utf-8") as f:
            f.write(comparison_md)

        summary = {
            "experiment": "Exp1_Raw_Baseline_vs_Pipeline",
            "configs": [r["config"] for r in results_list],
            "results": {r["config"]: r["metrics"] for r in results_list},
        }
        with open(os.path.join(RESULTS_DIR, "exp1_summary.json"), "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

        print(f"\n{'='*60}")
        print("  EXPERIMENT 1 COMPLETE")
        print(f"{'='*60}")
        print(f"  Results saved to: {RESULTS_DIR}/")
    else:
        print("\n[FATAL] All configs failed. No results produced.")


if __name__ == "__main__":
    main()
