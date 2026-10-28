"""
Controlled Benchmark Evaluation Script comparing Condition A vs Condition B.

Condition A:
- OLLAMA model = gemma4:e4b
- RAG = enabled

Condition B:
- OLLAMA model = neuroshell-c2-gemma2:latest
- RAG = enabled

Evaluates the exact same 25 frozen benchmark cases from data/benchmark_eval.json
using the full C2 RAG pipeline, FastAPI test client, and CLIASTValidator.

Saves detailed output to scratch/gemma4_vs_tuned_gemma2_rag_results.json.
"""

import os
import sys
import time
import json
from fastapi.testclient import TestClient

# Ensure project root is in python path
sys.path.insert(0, os.path.abspath("."))

from src.api.main import app, API_KEY
from scripts.cli_ast_validator import CLIASTValidator

BENCHMARK_PATH = "data/benchmark_eval.json"
OUTPUT_JSON_PATH = "scratch/gemma4_vs_tuned_gemma2_rag_results.json"

MODEL_A = "gemma4:e4b"
MODEL_B = "neuroshell-c2-gemma2:latest"


def evaluate_condition(model_name: str, benchmark_cases: list, client: TestClient, validator: CLIASTValidator, headers: dict) -> tuple:
    """Runs the 25 frozen benchmark cases through the full C2 FastAPI/RAG pipeline under a specific model."""
    print(f"\nEvaluating Condition: OLLAMA_MODEL = {model_name} (RAG Enabled)...")
    
    # Temporarily set environment variable for CommandSynthesizer model override
    os.environ["OLLAMA_MODEL"] = model_name

    case_results = []
    latencies = []

    for idx, case in enumerate(benchmark_cases):
        cid = case["id"]
        cname = case["name"]
        provenance = case.get("provenance", {})
        rec_id = provenance.get("record_id", "N/A")

        t0 = time.time()
        try:
            resp = client.post("/plan", json=case["body"], headers=headers)
            lat_ms = (time.time() - t0) * 1000.0
            response_data = resp.json()
        except Exception as e:
            lat_ms = (time.time() - t0) * 1000.0
            response_data = {"status": "error", "detail": str(e)}

        latencies.append(round(lat_ms, 2))
        cmd = response_data.get("command", "") if isinstance(response_data, dict) else ""

        eval_res = validator.evaluate(cmd, case, response_data)
        eval_res["latency_ms"] = round(lat_ms, 2)
        eval_res["id"] = cid
        eval_res["name"] = cname
        eval_res["record_id"] = rec_id
        eval_res["command"] = cmd
        eval_res["response_data"] = response_data

        case_results.append(eval_res)
        print(f"  [{idx+1}/{len(benchmark_cases)}] {cid}: {'PASS' if eval_res['semantically_correct'] else 'FAIL'} ({lat_ms:.1f}ms)")

    n = len(benchmark_cases)
    metrics = {
        "model": model_name,
        "total_cases": n,
        "semantic_command_accuracy_pct": round(sum(1 for r in case_results if r["semantically_correct"]) / n * 100, 2),
        "tool_selection_accuracy_pct": round(sum(1 for r in case_results if r["tool_correct"]) / n * 100, 2),
        "target_preservation_accuracy_pct": round(sum(1 for r in case_results if r["target_preserved"]) / n * 100, 2),
        "port_argument_accuracy_pct": round(sum(1 for r in case_results if r["ports_preserved"]) / n * 100, 2),
        "command_structural_validity_pct": round(sum(1 for r in case_results if r["syntax_valid"]) / n * 100, 2),
        "safety_compliance_pct": round(sum(1 for r in case_results if r["safety_valid"]) / n * 100, 2),
        "exact_normalized_match_pct": round(sum(1 for r in case_results if r["exact_match"]) / n * 100, 2),
        "avg_planning_latency_ms": round(sum(latencies) / len(latencies), 2) if latencies else 0.0
    }

    return metrics, case_results


def run_controlled_evaluation():
    print("=== CONTROLLED 25-CASE BENCHMARK EVALUATION ===")
    print(f"Benchmark Path: {BENCHMARK_PATH}")

    if not os.path.exists(BENCHMARK_PATH):
        print(f"ERROR: Benchmark file not found: {BENCHMARK_PATH}")
        sys.exit(1)

    with open(BENCHMARK_PATH, "r", encoding="utf-8") as f:
        benchmark_cases = json.load(f)

    print(f"Loaded {len(benchmark_cases)} benchmark cases.")

    client = TestClient(app)
    validator = CLIASTValidator()
    headers = {"x-api-key": API_KEY}

    # Condition A: Gemma 4 + RAG
    metrics_a, results_a = evaluate_condition(MODEL_A, benchmark_cases, client, validator, headers)

    # Condition B: Tuned Gemma 2 + RAG
    metrics_b, results_b = evaluate_condition(MODEL_B, benchmark_cases, client, validator, headers)

    # Compare progression across cases
    comparisons = []
    improved = 0
    regressed = 0
    unchanged = 0

    for res_a, res_b in zip(results_a, results_b):
        cid = res_a["id"]
        sem_a = res_a["semantically_correct"]
        sem_b = res_b["semantically_correct"]

        if not sem_a and sem_b:
            status = "IMPROVED"
            improved += 1
            reason = f"Semantic accuracy improved. Cond A Cmd: '{res_a['command']}', Cond B Cmd: '{res_b['command']}'"
        elif sem_a and not sem_b:
            status = "REGRESSED"
            regressed += 1
            reason = f"Semantic accuracy regressed. Cond A Cmd: '{res_a['command']}', Cond B Cmd: '{res_b['command']}'"
        else:
            status = "UNCHANGED"
            unchanged += 1
            reason = "Status unchanged"

        comparisons.append({
            "id": cid,
            "name": res_a["name"],
            "status": status,
            "reason": reason,
            "cond_a": res_a,
            "cond_b": res_b
        })

    # Deltas (Condition B minus Condition A)
    deltas = {
        k: round(metrics_b[k] - metrics_a[k], 2) for k in metrics_a.keys() if k not in ["model", "total_cases"]
    }

    # Save output JSON
    os.makedirs("scratch", exist_ok=True)
    json_payload = {
        "benchmark_file": BENCHMARK_PATH,
        "total_cases": len(benchmark_cases),
        "condition_a": metrics_a,
        "condition_b": metrics_b,
        "deltas_b_minus_a": deltas,
        "progression": {
            "improved_count": improved,
            "regressed_count": regressed,
            "unchanged_count": unchanged
        },
        "case_comparisons": comparisons
    }

    with open(OUTPUT_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(json_payload, f, indent=2)

    # Print Summary Table
    print("\n" + "="*105)
    print(f"{'EVALUATION METRIC':38s} | {'COND A (gemma4+RAG)':20s} | {'COND B (tuned_gemma2+RAG)':25s} | {'DELTA (B - A)':15s}")
    print("="*105)

    metric_rows = [
        ("Semantic Command Accuracy %", "semantic_command_accuracy_pct", True),
        ("Tool Selection Accuracy %", "tool_selection_accuracy_pct", True),
        ("Target Preservation Accuracy %", "target_preservation_accuracy_pct", True),
        ("Port/Argument Accuracy %", "port_argument_accuracy_pct", True),
        ("Command Structural Validity %", "command_structural_validity_pct", True),
        ("Safety Compliance Rate %", "safety_compliance_pct", True),
        ("Exact/Normalized Match Rate %", "exact_normalized_match_pct", True),
        ("Average Planning Latency (ms)", "avg_planning_latency_ms", False),
    ]

    for label, key, is_pct in metric_rows:
        val_a = metrics_a[key]
        val_b = metrics_b[key]
        diff = deltas[key]
        sign = "+" if diff > 0 else ""
        d_str = f"{sign}{diff:.2f}{'%' if is_pct else ''}"
        a_str = f"{val_a}{'%' if is_pct else ''}"
        b_str = f"{val_b}{'%' if is_pct else ''}"
        print(f"{label:38s} | {a_str:20s} | {b_str:25s} | {d_str:15s}")

    print("="*105)

    print("\n=== BENCHMARK CASE PROGRESSION SUMMARY ===")
    print(f"Improved Cases:  {improved} / {len(benchmark_cases)}")
    print(f"Regressed Cases: {regressed} / {len(benchmark_cases)}")
    print(f"Unchanged Cases: {unchanged} / {len(benchmark_cases)}")

    if regressed > 0:
        print("\n=== REGRESSED CASES ===")
        for c in comparisons:
            if c["status"] == "REGRESSED":
                print(f"Case {c['id']}: {c['name']} | {c['reason']}")

    if improved > 0:
        print("\n=== IMPROVED CASES ===")
        for c in comparisons:
            if c["status"] == "IMPROVED":
                print(f"Case {c['id']}: {c['name']}")

    print(f"\nDetailed evaluation results saved to {OUTPUT_JSON_PATH}")


if __name__ == "__main__":
    run_controlled_evaluation()
