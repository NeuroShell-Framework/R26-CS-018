"""
Base vs. Tuned Model Evaluation Script for NeuroShell Component 2 (C2).

Compares base model `gemma2:2b` against fine-tuned model `neuroshell-c2-gemma2:latest`
on the frozen held-out test dataset: data/synthesis_dataset/final/c2_sft_test.csv (81 records).

Evaluation Metrics:
- Executable / Tool Selection Accuracy
- Target Preservation
- Port Preservation
- Expected Flag Accuracy (tokenized via shlex)
- CommandValidator Pass Rate
- Semantic Command Accuracy
- Normalized Exact String Match
- SafetyFilter Pass Rate (reported separately)
- Latency (Mean & Median ms)

Saves detailed JSON trace to scratch/gemma2_base_vs_tuned_results.json.
"""

import os
import sys
import time
import json
import re
import shlex
import statistics
import pandas as pd
import ollama
from dotenv import load_dotenv

# Ensure project root is in python path
sys.path.insert(0, os.path.abspath("."))

from src.synthesis.command_synthesizer import CommandSynthesizer
from src.validation.command_validator import CommandValidator
from src.validation.safety_filter import SafetyFilter

load_dotenv()

BASE_MODEL = "gemma2:2b"
TUNED_MODEL = "neuroshell-c2-gemma2:latest"
TEST_DATASET_PATH = "data/synthesis_dataset/final/c2_sft_test.csv"
OUTPUT_JSON_PATH = "scratch/gemma2_base_vs_tuned_results.json"


def normalize_space(s: str) -> str:
    if not isinstance(s, str):
        return ""
    return re.sub(r"\s+", " ", s).strip()


def extract_primary_tool(cmd: str) -> str:
    tokens = cmd.strip().split()
    if not tokens:
        return ""
    first = tokens[0].lower()
    if first == "sudo" and len(tokens) > 1:
        first = tokens[1].lower()
    return os.path.basename(first)


def tokenize_cmd(cmd: str) -> list:
    """Safely tokenizes a command string using shlex for order-agnostic flag comparison."""
    try:
        return shlex.split(cmd)
    except Exception:
        return cmd.strip().split()


def evaluate_model_on_record(model_name: str, row: pd.Series, synthesizer: CommandSynthesizer, validator: CommandValidator, safety_filter: SafetyFilter) -> dict:
    record_id = str(row.get("record_id", ""))
    prompt_text = str(row.get("prompt", ""))
    expected_cmd = normalize_space(str(row.get("expected_command", "")))
    expected_tool = str(row.get("tool", "")).lower().strip()
    intent = str(row.get("intent", "")).upper().strip()
    target = str(row.get("target", "")).strip()
    ports_str = str(row.get("ports", "")).strip()
    expected_flags_str = str(row.get("expected_flags", "")).strip()

    prompt_formatted = (
        "Synthesize a valid Kali Linux C2 execution command for the following specification. Output ONLY the executable command.\n\n"
        f"Intent: {intent}\n"
        f"Target: {target}\n"
        f"Ports: {row.get('ports', '')}\n"
        f"Modifiers: {row.get('modifiers', '')}\n"
        f"Tool: {expected_tool}\n"
        f"Instruction: {prompt_text}"
    )

    t0 = time.time()
    try:
        res = ollama.chat(
            model=model_name,
            messages=[
                {
                    "role": "system",
                    "content": "You are a Kali Linux command generator for NeuroShell C2. Output ONLY valid, executable commands for the requested tool and target. Do not explain."
                },
                {
                    "role": "user",
                    "content": prompt_formatted
                }
            ]
        )
        raw_output = res["message"]["content"].strip()
    except Exception as e:
        raw_output = f"ERROR: Inference failed: {str(e)}"

    latency_ms = (time.time() - t0) * 1000.0

    parsed = synthesizer.parse_command_output(raw_output, multi_step=False)
    generated_cmd = normalize_space(parsed[0]) if parsed else normalize_space(raw_output)

    # Metric 1: Executable / Tool Correctness
    gen_tool = extract_primary_tool(generated_cmd)
    tool_correct = (gen_tool == expected_tool)

    # Metric 2: Normalized Exact Match
    normalized_exact_match = (generated_cmd == expected_cmd)

    # Metric 3: Target Preservation
    target_preserved = False
    if target and target.lower() != "nan":
        # Check if target IP/domain substring is present in command
        target_preserved = (target.lower() in generated_cmd.lower())
    else:
        target_preserved = True

    # Metric 4: Port Preservation
    port_preserved = True
    if ports_str and ports_str != "nan" and ports_str != "[]" and ports_str != "None":
        # Extract digits/port specs from ports_str e.g. "80", "80,8080", "[80]"
        port_digits = re.findall(r"\d+", ports_str)
        if port_digits:
            port_preserved = all(p in generated_cmd for p in port_digits)

    # Metric 5: Expected Flag Preservation (tokenized via shlex)
    gen_tokens = tokenize_cmd(generated_cmd)
    exp_flags = [f.strip() for f in expected_flags_str.split(",") if f.strip() and f.strip() != "nan"]
    if exp_flags:
        flags_correct = all(any(flag == tok or tok.startswith(flag) for tok in gen_tokens) for flag in exp_flags)
    else:
        flags_correct = True

    # Metric 6: CommandValidator Pass Rate
    validator_passed, validator_issues = validator.validate(generated_cmd, expected_tool=expected_tool)

    # Metric 7: Semantic Command Accuracy (Tool Correct + Target Preserved + Expected Flags Correct + Validator Passed)
    semantic_correct = (tool_correct and target_preserved and flags_correct and validator_passed)

    # Metric 8: SafetyFilter Pass Rate (Evaluated and reported separately)
    safety_passed, safety_flags = safety_filter.validate(generated_cmd, target=target)

    return {
        "record_id": record_id,
        "model": model_name,
        "expected_command": expected_cmd,
        "generated_command": generated_cmd,
        "expected_tool": expected_tool,
        "generated_tool": gen_tool,
        "tool_correct": tool_correct,
        "normalized_exact_match": normalized_exact_match,
        "target_preserved": target_preserved,
        "port_preserved": port_preserved,
        "expected_flags_correct": flags_correct,
        "validator_passed": validator_passed,
        "validator_issues": validator_issues,
        "semantic_correct": semantic_correct,
        "safety_passed": safety_passed,
        "safety_flags": safety_flags,
        "latency_ms": round(latency_ms, 2)
    }


def run_evaluation():
    print(f"=== C2 BASE VS TUNED MODEL EVALUATION ===")
    print(f"Base Model:  {BASE_MODEL}")
    print(f"Tuned Model: {TUNED_MODEL}")
    print(f"Test Dataset: {TEST_DATASET_PATH}")

    if not os.path.exists(TEST_DATASET_PATH):
        print(f"ERROR: Test dataset file not found at {TEST_DATASET_PATH}")
        sys.exit(1)

    df_test = pd.read_csv(TEST_DATASET_PATH)
    total_records = len(df_test)
    print(f"Total Test Records: {total_records}")

    synthesizer = CommandSynthesizer()
    validator = CommandValidator()
    safety_filter = SafetyFilter()

    base_results = []
    tuned_results = []
    comparisons = []

    print("\nRunning inference across 81 test records...")
    for idx, row in df_test.iterrows():
        rec_id = str(row.get("record_id", f"REC-{idx}"))
        
        # 1. Base model inference
        res_base = evaluate_model_on_record(BASE_MODEL, row, synthesizer, validator, safety_filter)
        base_results.append(res_base)

        # 2. Tuned model inference
        res_tuned = evaluate_model_on_record(TUNED_MODEL, row, synthesizer, validator, safety_filter)
        tuned_results.append(res_tuned)

        # Categorize record progression (Improved, Regressed, Unchanged)
        # Based on semantic correctness improvement
        base_sem = res_base["semantic_correct"]
        tuned_sem = res_tuned["semantic_correct"]

        if not base_sem and tuned_sem:
            status = "IMPROVED"
            reason = "Semantic accuracy improved from Fail to Pass"
        elif base_sem and not tuned_sem:
            status = "REGRESSED"
            reason = f"Semantic accuracy regressed. Base: '{res_base['generated_command']}', Tuned: '{res_tuned['generated_command']}'"
        else:
            status = "UNCHANGED"
            reason = "Semantic accuracy status unchanged"

        comparisons.append({
            "record_id": rec_id,
            "status": status,
            "reason": reason,
            "base": res_base,
            "tuned": res_tuned
        })

        if (idx + 1) % 10 == 0 or (idx + 1) == total_records:
            print(f"  Processed {idx + 1}/{total_records} records...")

    # Aggregate Metrics Calculation
    def calc_metrics(res_list):
        n = len(res_list)
        latencies = [r["latency_ms"] for r in res_list]
        return {
            "total_records": n,
            "tool_accuracy_pct": round(sum(1 for r in res_list if r["tool_correct"]) / n * 100, 2),
            "target_preservation_pct": round(sum(1 for r in res_list if r["target_preserved"]) / n * 100, 2),
            "port_preservation_pct": round(sum(1 for r in res_list if r["port_preserved"]) / n * 100, 2),
            "expected_flag_accuracy_pct": round(sum(1 for r in res_list if r["expected_flags_correct"]) / n * 100, 2),
            "validator_pass_rate_pct": round(sum(1 for r in res_list if r["validator_passed"]) / n * 100, 2),
            "semantic_accuracy_pct": round(sum(1 for r in res_list if r["semantic_correct"]) / n * 100, 2),
            "normalized_exact_match_pct": round(sum(1 for r in res_list if r["normalized_exact_match"]) / n * 100, 2),
            "safety_pass_rate_pct": round(sum(1 for r in res_list if r["safety_passed"]) / n * 100, 2),
            "avg_latency_ms": round(statistics.mean(latencies), 2),
            "median_latency_ms": round(statistics.median(latencies), 2)
        }

    m_base = calc_metrics(base_results)
    m_tuned = calc_metrics(tuned_results)

    # Save detailed evaluation JSON to scratch/
    os.makedirs("scratch", exist_ok=True)
    json_payload = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "base_model": BASE_MODEL,
        "tuned_model": TUNED_MODEL,
        "test_dataset": TEST_DATASET_PATH,
        "base_metrics": m_base,
        "tuned_metrics": m_tuned,
        "deltas": {
            k: round(m_tuned[k] - m_base[k], 2) for k in m_base.keys() if k != "total_records"
        },
        "comparisons": comparisons
    }

    with open(OUTPUT_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(json_payload, f, indent=2)

    # Display Summary Table
    print("\n" + "="*95)
    print(f"{'EVALUATION METRIC':35s} | {'BASE (gemma2:2b)':18s} | {'TUNED (neuroshell-c2)':20s} | {'DELTA (Tuned - Base)':20s}")
    print("="*95)

    metrics_keys = [
        ("Total Records", "total_records", False),
        ("Tool Selection Accuracy %", "tool_accuracy_pct", True),
        ("Target Preservation %", "target_preservation_pct", True),
        ("Port Preservation %", "port_preservation_pct", True),
        ("Expected Flag Accuracy %", "expected_flag_accuracy_pct", True),
        ("CommandValidator Pass Rate %", "validator_pass_rate_pct", True),
        ("Semantic Command Accuracy %", "semantic_accuracy_pct", True),
        ("Normalized Exact Match %", "normalized_exact_match_pct", True),
        ("SafetyFilter Pass Rate %", "safety_pass_rate_pct", True),
        ("Average Latency (ms)", "avg_latency_ms", False),
        ("Median Latency (ms)", "median_latency_ms", False),
    ]

    for label, key, is_pct in metrics_keys:
        v_b = m_base[key]
        v_t = m_tuned[key]
        if key == "total_records":
            delta_str = "0"
        else:
            diff = round(v_t - v_b, 2)
            sign = "+" if diff > 0 else ""
            delta_str = f"{sign}{diff:.2f}"
            if is_pct:
                delta_str += "%"

        b_str = f"{v_b}{'%' if is_pct else ''}"
        t_str = f"{v_t}{'%' if is_pct else ''}"
        print(f"{label:35s} | {b_str:18s} | {t_str:20s} | {delta_str:20s}")

    print("="*95)

    # Display Progression Summary
    n_improved = sum(1 for c in comparisons if c["status"] == "IMPROVED")
    n_regressed = sum(1 for c in comparisons if c["status"] == "REGRESSED")
    n_unchanged = sum(1 for c in comparisons if c["status"] == "UNCHANGED")

    print("\n=== RECORD PROGRESSION SUMMARY ===")
    print(f"Improved Records:  {n_improved} / {total_records}")
    print(f"Regressed Records: {n_regressed} / {total_records}")
    print(f"Unchanged Records: {n_unchanged} / {total_records}")

    if n_regressed > 0:
        print("\n=== REGRESSION DETAILS ===")
        for c in comparisons:
            if c["status"] == "REGRESSED":
                print(f"Record ID: {c['record_id']} | Reason: {c['reason']}")

    print(f"\nDetailed evaluation results saved to {OUTPUT_JSON_PATH}")


if __name__ == "__main__":
    run_evaluation()
