# NeuroShell IRE — Baseline Model Evaluator
# Calls raw Gemma model via Ollama API without schema constraints or validation stack.

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import re
import json
import time
import httpx
from typing import Dict, Any, Optional, Tuple


MINIMAL_PROMPT = """You are a security assistant. Extract the intent, target, and CVE ID (if present) from the following command:
"{input}"

Respond with the intent name (NETWORK_SCAN, VULNERABILITY_AUDIT, EXPLOITATION, SERVICE_ENUMERATION, PASSWORD_ATTACK, PASSIVE_RECON, DIRECTORY_BRUTE_FORCE), target IP/domain, and CVE ID if any."""


BASELINE_CACHE_FILE = os.path.join(os.path.dirname(__file__), ".baseline_cache.json")


def _load_baseline_cache() -> Dict[str, Tuple[str, float]]:
    if os.path.exists(BASELINE_CACHE_FILE):
        try:
            with open(BASELINE_CACHE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return {k: tuple(v) for k, v in data.items()}
        except Exception:
            pass
    return {}


def _save_baseline_cache(cache: Dict[str, Tuple[str, float]]) -> None:
    try:
        with open(BASELINE_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump({k: list(v) for k, v in cache.items()}, f, indent=2)
    except Exception:
        pass


def call_raw_gemma(user_input: str) -> Tuple[str, float]:
    """Call raw Gemma via local Ollama without prompt constraints, with disk caching."""
    cache = _load_baseline_cache()
    if user_input in cache:
        return cache[user_input]

    start = time.time()
    prompt = MINIMAL_PROMPT.format(input=user_input)
    try:
        r = httpx.post(
            "http://localhost:11434/api/chat",
            json={
                "model": "gemma4:latest",
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
                "options": {"temperature": 0.1},
            },
            timeout=120.0,
        )
        elapsed_ms = (time.time() - start) * 1000.0
        if r.status_code == 200:
            content = r.json()["message"]["content"]
            result = (content, elapsed_ms)
            cache[user_input] = result
            _save_baseline_cache(cache)
            return result
        return "", elapsed_ms
    except Exception as e:
        elapsed_ms = (time.time() - start) * 1000.0
        return "", elapsed_ms


def extract_heuristic(response_text: str) -> Dict[str, Any]:
    """Lenient regex/heuristic extractor for free-text output."""
    if not response_text:
        return {"intent": None, "target": None, "cve": None}

    text_upper = response_text.upper()

    # Heuristic intent matching
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

    # Target extraction (IP/CIDR or domain)
    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b", response_text)
    target = ip_match.group(0) if ip_match else None

    # CVE extraction
    cve_match = re.search(r"CVE-\d{4}-\d{4,7}", text_upper)
    cve = cve_match.group(0) if cve_match else None

    return {"intent": intent, "target": target, "cve": cve}


def evaluate_baseline(dataset_path: str = "eval/dataset_draft.jsonl") -> Dict[str, Any]:
    summary_path = os.path.join(os.path.dirname(__file__), ".baseline_summary.json")
    if os.path.exists(summary_path):
        try:
            with open(summary_path, "r", encoding="utf-8") as f:
                metrics = json.load(f)
                print(f"[*] Loaded Baseline Model Evaluation from {summary_path}...")
                print(json.dumps(metrics, indent=2))
                return metrics
        except Exception:
            pass

    print(f"[*] Running Baseline Model Evaluation on {dataset_path}...")

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
    false_positives = 0  # Well-formed items falsely rejected/unparsed
    caught_flaws = 0  # Deliberately flawed items correctly caught/refused
    latencies = []

    for idx, record in enumerate(records, start=1):
        raw_output, elapsed_ms = call_raw_gemma(record["input"])
        latencies.append(elapsed_ms)
        extracted = extract_heuristic(raw_output)

        is_flawed = record["category"] != "well_formed"

        # Well-formed matching
        if not is_flawed:
            intent_match = (extracted["intent"] == record["expected_intent"])
            target_match = (not record["expected_target"] or (extracted["target"] == record["expected_target"]))
            if intent_match and target_match:
                correct_well_formed += 1
            else:
                false_positives += 1
        else:
            # Flawed evaluation: raw model without validation stack fails to catch flaws (e.g. invalid CVE syntax, out of bounds ports)
            # Caught flaw if model explicitly refused or output failed to extract valid structure
            if not extracted["intent"] or not extracted["target"]:
                caught_flaws += 1

        pct = (idx / total_records) * 100.0
        print(f"[{idx}/{total_records} - {pct:.1f}%] ({record['category']}) '{record['input'][:40]}...' -> {elapsed_ms:.1f}ms")
        sys.stdout.flush()

    latencies_sorted = sorted(latencies) if latencies else [0]
    n = len(latencies_sorted)
    p50 = latencies_sorted[int(n * 0.50)]
    p95 = latencies_sorted[min(int(n * 0.95), n - 1)]

    accuracy = (correct_well_formed / len(well_formed_items)) * 100.0 if well_formed_items else 0.0
    catch_rate = (caught_flaws / len(flawed_items)) * 100.0 if flawed_items else 0.0
    fp_rate = (false_positives / len(well_formed_items)) * 100.0 if well_formed_items else 0.0

    metrics = {
        "configuration": "Raw Gemma Baseline (No Validation)",
        "total_examples": total_records,
        "accuracy": round(accuracy, 2),
        "hallucination_catch_rate": round(catch_rate, 2),
        "false_positive_rate": round(fp_rate, 2),
        "p50_latency_ms": round(p50, 1),
        "p95_latency_ms": round(p95, 1),
    }

    print("\n=== BASELINE RESULTS SUMMARY ===")
    print(json.dumps(metrics, indent=2))
    return metrics


if __name__ == "__main__":
    evaluate_baseline()
