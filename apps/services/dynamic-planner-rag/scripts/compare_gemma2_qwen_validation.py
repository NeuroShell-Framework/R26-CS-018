"""
Comparative Evaluation Script: gemma2:2b vs qwen2.5:1.5b on C2 SFT Validation Dataset.

Model-by-Model execution strategy:
1. Evaluates ALL 392 validation records for gemma2:2b first with keep_alive enabled.
2. Evaluates ALL 392 validation records for qwen2.5:1.5b second with keep_alive enabled.

Supports incremental checkpointing to scratch/gemma2_vs_qwen_validation_checkpoint.json.

Metrics:
1. Tool correctness
2. Target preservation
3. Normalized exact command match
4. CommandValidator pass rate
5. SafetyFilter pass rate
6. Expected option/flag preservation
7. Semantic correctness (tool correct + target preserved + expected options preserved + CommandValidator passed)
8. Mean latency (ms)
9. Median latency (ms)

Reports overall side-by-side raw metrics, as well as per-tool breakdowns (nmap, nikto, gobuster).
Saves detailed JSON trace to scratch/gemma2_vs_qwen_validation_results.json
Saves text summary to scratch/gemma2_vs_qwen_validation_summary.txt
"""

import os
import sys
import time
import json
import re
import shlex
import statistics
from typing import Dict, List, Tuple, Any, Optional

import ollama

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath("."))

from src.validation.command_validator import CommandValidator
from src.validation.safety_filter import SafetyFilter

DATASET_PATH = os.path.join("data", "synthesis_dataset", "final", "c2_sft_validation.jsonl")
CHECKPOINT_JSON_PATH = os.path.join("scratch", "gemma2_vs_qwen_validation_checkpoint.json")
RESULTS_JSON_PATH = os.path.join("scratch", "gemma2_vs_qwen_validation_results.json")
SUMMARY_TXT_PATH = os.path.join("scratch", "gemma2_vs_qwen_validation_summary.txt")

MODEL_GEMMA = "gemma2:2b"
MODEL_QWEN = "qwen2.5:1.5b"


def normalize_space(s: str) -> str:
    """Normalize consecutive whitespace characters into single spaces."""
    if not isinstance(s, str):
        return ""
    return re.sub(r"\s+", " ", s).strip()


def clean_model_output(raw_output: str) -> str:
    """
    Clean model output by:
    - stripping whitespace
    - removing markdown ``` fences if present
    - taking the actual single command line only
    Does not silently repair command syntax.
    """
    if not raw_output:
        return ""
    
    text = raw_output.strip()
    
    # Strip markdown fences if present
    if "```" in text:
        fence_match = re.search(r"```(?:[a-zA-Z0-9_-]+)?\s*\n?(.*?)\n?```", text, re.DOTALL)
        if fence_match:
            text = fence_match.group(1).strip()
        else:
            text = text.replace("```", "").strip()
            
    # Take first non-empty line
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if lines:
        text = lines[0]
        
    return text.strip()


def extract_primary_tool(cmd: str) -> str:
    """
    Extract primary executable binary basename, correctly handling:
    - sudo prefix
    - absolute/relative paths (/tmp/nmap, /usr/bin/nmap)
    - sudo /usr/bin/nmap
    """
    if not cmd or not isinstance(cmd, str):
        return ""
    
    tokens = cmd.strip().split()
    if not tokens:
        return ""
    
    first = tokens[0]
    if first.lower() == "sudo" and len(tokens) > 1:
        first = tokens[1]
        
    basename = os.path.basename(first.lower()).rstrip(":")
    return basename


def parse_cli_tokens(cmd_str: str) -> List[str]:
    """Safely tokenize command string using shlex, falling back to split."""
    try:
        return shlex.split(cmd_str)
    except Exception:
        return cmd_str.strip().split()


def check_expected_option_preservation(generated_cmd: str, expected_cmd: str, target_str: str) -> bool:
    """
    Conservatively evaluate whether expected CLI options/flags from expected_cmd are preserved in generated_cmd.
    Ignores:
    - executable token
    - target token
    """
    exp_tokens = parse_cli_tokens(expected_cmd)
    if not exp_tokens:
        return True
        
    # Strip sudo prefix if present
    if exp_tokens[0].lower() == "sudo":
        exp_tokens = exp_tokens[1:]
    if exp_tokens:
        exp_tokens = exp_tokens[1:]  # strip executable token
        
    target_clean = str(target_str).strip().lower() if target_str else ""
    
    # Filter target tokens from expected tokens
    exp_filtered = []
    for tok in exp_tokens:
        tok_clean = tok.lower()
        if target_clean and target_clean not in ("nan", "none", ""):
            if target_clean in tok_clean or tok_clean in f"http://{target_clean}/" or tok_clean in f"https://{target_clean}/":
                continue
        exp_filtered.append(tok)
        
    if not exp_filtered:
        return True
        
    gen_tokens = parse_cli_tokens(generated_cmd)
    gen_str_lower = generated_cmd.lower()
    
    expected_flags = []
    expected_values = []
    
    i = 0
    while i < len(exp_filtered):
        tok = exp_filtered[i]
        if tok.startswith("-"):
            expected_flags.append(tok)
            if i + 1 < len(exp_filtered) and not exp_filtered[i+1].startswith("-"):
                val = exp_filtered[i+1]
                val_clean = val.lower()
                if not (target_clean and target_clean not in ("nan", "none", "") and target_clean in val_clean):
                    expected_values.append(val)
                i += 2
                continue
        elif tok.lower() in ("dir", "dns", "vhost", "fuzz"):  # gobuster subcommands
            expected_flags.append(tok)
        i += 1
        
    if not expected_flags and not expected_values:
        return True
        
    # Verify expected flags exist in generated command
    for flag in expected_flags:
        flag_lower = flag.lower()
        matched = False
        for gt in gen_tokens:
            gt_lower = gt.lower()
            if gt_lower == flag_lower:
                matched = True
                break
            if flag.startswith("-") and len(flag) > 1 and gt_lower.startswith(flag_lower):
                matched = True
                break
        if not matched:
            return False
            
    # Verify expected option values (conservatively)
    for val in expected_values:
        val_lower = val.lower()
        base_val = os.path.basename(val).lower()
        if val_lower in gen_str_lower or base_val in gen_str_lower:
            continue
        else:
            return False
            
    return True


def construct_prompt(tool: str, target: str, subintent: str, modifiers: str) -> str:
    """Construct non-leaking prompt for NeuroShell C2 command synthesis."""
    return (
        "You are the NeuroShell C2 command synthesis engine.\n"
        "Generate one valid executable Kali Linux command.\n"
        "Output ONLY the command, with no markdown and no explanation.\n\n"
        f"Tool: {tool}\n"
        f"Target: {target}\n"
        f"Sub-intent: {subintent}\n"
        f"Modifiers: {modifiers}"
    )


def evaluate_model_record(
    model_name: str,
    record: Dict[str, Any],
    validator: CommandValidator,
    safety_filter: SafetyFilter
) -> Dict[str, Any]:
    """Evaluate a single record for a given model."""
    tool = str(record.get("tool", "")).lower().strip()
    target_norm = str(record.get("target_normalized", "")).strip()
    subintent = str(record.get("subintent_guess", "")).strip()
    modifiers = str(record.get("modifier_signature", "")).strip()
    expected_cmd = normalize_space(str(record.get("command", "")))
    
    prompt_text = construct_prompt(tool, target_norm, subintent, modifiers)
    
    t0 = time.time()
    inference_error = None
    try:
        response = ollama.chat(
            model=model_name,
            messages=[{"role": "user", "content": prompt_text}],
            options={"temperature": 0},
            keep_alive="1h"
        )
        raw_output = response["message"]["content"]
    except Exception as e:
        raw_output = ""
        inference_error = str(e)
        
    latency_ms = (time.time() - t0) * 1000.0
    
    cleaned_cmd = clean_model_output(raw_output)
    gen_cmd_norm = normalize_space(cleaned_cmd)
    
    # 1. Tool correctness
    gen_tool = extract_primary_tool(gen_cmd_norm)
    tool_correct = (gen_tool == tool)
    
    # 2. Target preservation
    if target_norm and target_norm.lower() not in ("nan", "none", ""):
        target_preserved = (target_norm.lower() in gen_cmd_norm.lower())
    else:
        target_preserved = True
        
    # 3. Normalized exact command match
    exact_match = (gen_cmd_norm == expected_cmd)
    
    # 4. CommandValidator pass rate
    val_passed, val_issues = validator.validate(gen_cmd_norm, expected_tool=tool)
    
    # 5. SafetyFilter pass rate
    safety_passed, safety_flags = safety_filter.validate(gen_cmd_norm, target=target_norm)
    
    # 6. Expected option/flag preservation
    options_preserved = check_expected_option_preservation(gen_cmd_norm, expected_cmd, target_norm)
    
    # 7. Semantic correctness
    semantic_correct = bool(tool_correct and target_preserved and options_preserved and val_passed)
    
    return {
        "record_id": record.get("id", ""),
        "model": model_name,
        "expected_tool": tool,
        "target_normalized": target_norm,
        "expected_command": expected_cmd,
        "raw_output": raw_output,
        "generated_command": gen_cmd_norm,
        "generated_tool": gen_tool,
        "tool_correct": tool_correct,
        "target_preserved": target_preserved,
        "normalized_exact_match": exact_match,
        "validator_passed": val_passed,
        "validator_issues": val_issues,
        "safety_passed": safety_passed,
        "safety_flags": safety_flags,
        "options_preserved": options_preserved,
        "semantic_correct": semantic_correct,
        "latency_ms": round(latency_ms, 2),
        "inference_error": inference_error
    }


def compute_metrics(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute aggregate metrics for a list of record results."""
    n = len(results)
    if n == 0:
        return {}
    
    latencies = [r["latency_ms"] for r in results]
    inference_errors = [r for r in results if r.get("inference_error")]
    
    return {
        "count": n,
        "tool_correctness_pct": round(sum(1 for r in results if r["tool_correct"]) / n * 100, 2),
        "target_preservation_pct": round(sum(1 for r in results if r["target_preserved"]) / n * 100, 2),
        "normalized_exact_match_pct": round(sum(1 for r in results if r["normalized_exact_match"]) / n * 100, 2),
        "validator_pass_rate_pct": round(sum(1 for r in results if r["validator_passed"]) / n * 100, 2),
        "safety_pass_rate_pct": round(sum(1 for r in results if r["safety_passed"]) / n * 100, 2),
        "options_preservation_pct": round(sum(1 for r in results if r["options_preserved"]) / n * 100, 2),
        "semantic_correctness_pct": round(sum(1 for r in results if r["semantic_correct"]) / n * 100, 2),
        "mean_latency_ms": round(statistics.mean(latencies), 2),
        "median_latency_ms": round(statistics.median(latencies), 2),
        "inference_failure_count": len(inference_errors)
    }


def save_checkpoint(gemma_results: List[Dict[str, Any]], qwen_results: List[Dict[str, Any]]):
    """Save intermediate results to checkpoint JSON."""
    os.makedirs("scratch", exist_ok=True)
    payload = {
        "gemma_results": gemma_results,
        "qwen_results": qwen_results
    }
    with open(CHECKPOINT_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def load_checkpoint() -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Load intermediate results from checkpoint JSON if present."""
    if os.path.exists(CHECKPOINT_JSON_PATH):
        try:
            with open(CHECKPOINT_JSON_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data.get("gemma_results", []), data.get("qwen_results", [])
        except Exception as e:
            print(f"Warning: Failed to load checkpoint: {e}", flush=True)
    return [], []


def run_benchmark():
    print("=" * 80, flush=True)
    print("C2 BASE MODEL COMPARISON BENCHMARK (MODEL-BY-MODEL): gemma2:2b vs qwen2.5:1.5b", flush=True)
    print(f"Dataset: {DATASET_PATH}", flush=True)
    print("=" * 80, flush=True)
    
    if not os.path.exists(DATASET_PATH):
        print(f"ERROR: Validation dataset not found at {DATASET_PATH}", flush=True)
        sys.exit(1)
        
    records = []
    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))
                
    total_records = len(records)
    print(f"Loaded {total_records} validation records.", flush=True)
    
    validator = CommandValidator()
    safety_filter = SafetyFilter()
    
    # 1-RECORD INFERENCE SMOKE TEST FOR EACH MODEL
    print("\n" + "-" * 80, flush=True)
    print("RUNNING 1-RECORD SMOKE TEST FOR EACH MODEL...", flush=True)
    print("-" * 80, flush=True)
    
    smoke_rec = records[0]
    s_tool = str(smoke_rec.get("tool", "")).lower().strip()
    s_target = str(smoke_rec.get("target_normalized", "")).strip()
    s_subintent = str(smoke_rec.get("subintent_guess", "")).strip()
    s_modifiers = str(smoke_rec.get("modifier_signature", "")).strip()
    s_prompt = construct_prompt(s_tool, s_target, s_subintent, s_modifiers)
    
    print(f"Smoke Record Expected: {smoke_rec.get('command', '')}", flush=True)
    
    res_g_smoke = ollama.chat(model=MODEL_GEMMA, messages=[{"role": "user", "content": s_prompt}], options={"temperature": 0}, keep_alive="1h")
    clean_g_smoke = clean_model_output(res_g_smoke["message"]["content"])
    print(f"[{MODEL_GEMMA} Smoke]: {clean_g_smoke!r}", flush=True)
    
    res_q_smoke = ollama.chat(model=MODEL_QWEN, messages=[{"role": "user", "content": s_prompt}], options={"temperature": 0}, keep_alive="1h")
    clean_q_smoke = clean_model_output(res_q_smoke["message"]["content"])
    print(f"[{MODEL_QWEN} Smoke]: {clean_q_smoke!r}", flush=True)
    
    print("1-record smoke test verified!", flush=True)
    
    # Load any existing checkpoints
    gemma_results, qwen_results = load_checkpoint()
    
    # -------------------------------------------------------------
    # STAGE 1: EVALUATE ALL RECORDS WITH GEMMA2:2B
    # -------------------------------------------------------------
    print("\n" + "=" * 80, flush=True)
    print(f"STAGE 1: EVALUATING ALL {total_records} RECORDS WITH {MODEL_GEMMA}...", flush=True)
    print("=" * 80, flush=True)
    
    for idx in range(len(gemma_results), total_records):
        r = records[idx]
        res = evaluate_model_record(MODEL_GEMMA, r, validator, safety_filter)
        gemma_results.append(res)
        
        # Save checkpoint per record
        save_checkpoint(gemma_results, qwen_results)
        
        curr_num = idx + 1
        if curr_num == 1 or curr_num % 10 == 0 or curr_num == total_records:
            print(f"[Gemma] {curr_num}/{total_records}", flush=True)
            
    # -------------------------------------------------------------
    # STAGE 2: EVALUATE ALL RECORDS WITH QWEN2.5:1.5B
    # -------------------------------------------------------------
    print("\n" + "=" * 80, flush=True)
    print(f"STAGE 2: EVALUATING ALL {total_records} RECORDS WITH {MODEL_QWEN}...", flush=True)
    print("=" * 80, flush=True)
    
    for idx in range(len(qwen_results), total_records):
        r = records[idx]
        res = evaluate_model_record(MODEL_QWEN, r, validator, safety_filter)
        qwen_results.append(res)
        
        # Save checkpoint per record
        save_checkpoint(gemma_results, qwen_results)
        
        curr_num = idx + 1
        if curr_num == 1 or curr_num % 10 == 0 or curr_num == total_records:
            print(f"[Qwen] {curr_num}/{total_records}", flush=True)
            
    # Aggregate metrics
    gemma_metrics = compute_metrics(gemma_results)
    qwen_metrics = compute_metrics(qwen_results)
    
    # Tool breakdown
    tools = sorted(list(set(r.get("tool", "").lower() for r in records if r.get("tool"))))
    per_tool_results = {}
    for t in tools:
        g_tool_res = [r for r in gemma_results if r["expected_tool"] == t]
        q_tool_res = [r for r in qwen_results if r["expected_tool"] == t]
        per_tool_results[t] = {
            MODEL_GEMMA: compute_metrics(g_tool_res),
            MODEL_QWEN: compute_metrics(q_tool_res)
        }
        
    # Save detailed JSON output
    os.makedirs("scratch", exist_ok=True)
    json_output = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "dataset": DATASET_PATH,
        "total_records": total_records,
        "models": [MODEL_GEMMA, MODEL_QWEN],
        "gemma_metrics": gemma_metrics,
        "qwen_metrics": qwen_metrics,
        "per_tool_metrics": per_tool_results,
        "records_detailed": [
            {
                "id": records[i].get("id", f"rec_{i}"),
                "tool": records[i].get("tool", ""),
                "target_normalized": records[i].get("target_normalized", ""),
                "subintent_guess": records[i].get("subintent_guess", ""),
                "modifier_signature": records[i].get("modifier_signature", ""),
                "expected_command": records[i].get("command", ""),
                "gemma_result": gemma_results[i],
                "qwen_result": qwen_results[i]
            }
            for i in range(total_records)
        ]
    }
    
    with open(RESULTS_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(json_output, f, indent=2)
        
    # Build text summary
    summary_lines = []
    summary_lines.append("=" * 85)
    summary_lines.append("C2 BASE MODEL VALIDATION EVALUATION SUMMARY: gemma2:2b vs qwen2.5:1.5b")
    summary_lines.append(f"Dataset: {DATASET_PATH} (Records Evaluated: {total_records})")
    summary_lines.append("=" * 85)
    summary_lines.append("")
    summary_lines.append(f"{'EVALUATION METRIC':32s} | {'gemma2:2b':22s} | {'qwen2.5:1.5b':22s}")
    summary_lines.append("-" * 85)
    
    metric_fields = [
        ("Evaluated Record Count", "count", False),
        ("Tool Correctness %", "tool_correctness_pct", True),
        ("Target Preservation %", "target_preservation_pct", True),
        ("Normalized Exact Match %", "normalized_exact_match_pct", True),
        ("CommandValidator Pass Rate %", "validator_pass_rate_pct", True),
        ("SafetyFilter Pass Rate %", "safety_pass_rate_pct", True),
        ("Expected Option Preservation %", "options_preservation_pct", True),
        ("Semantic Correctness %", "semantic_correctness_pct", True),
        ("Mean Latency (ms)", "mean_latency_ms", False),
        ("Median Latency (ms)", "median_latency_ms", False),
        ("Inference Failures", "inference_failure_count", False),
    ]
    
    for label, field, is_pct in metric_fields:
        vg = gemma_metrics.get(field, 0)
        vq = qwen_metrics.get(field, 0)
        g_str = f"{vg:.2f}%" if is_pct else str(vg)
        q_str = f"{vq:.2f}%" if is_pct else str(vq)
        summary_lines.append(f"{label:32s} | {g_str:22s} | {q_str:22s}")
        
    summary_lines.append("-" * 85)
    summary_lines.append("")
    summary_lines.append("=" * 85)
    summary_lines.append("PER-TOOL BREAKDOWN")
    summary_lines.append("=" * 85)
    
    for t in tools:
        m_g = per_tool_results[t][MODEL_GEMMA]
        m_q = per_tool_results[t][MODEL_QWEN]
        summary_lines.append(f"\n--- TOOL: {t.upper()} (Count: {m_g['count']}) ---")
        summary_lines.append(f"{'METRIC':32s} | {'gemma2:2b':22s} | {'qwen2.5:1.5b':22s}")
        summary_lines.append("-" * 85)
        for label, field, is_pct in metric_fields[1:]:  # skip count
            vg = m_g.get(field, 0)
            vq = m_q.get(field, 0)
            g_str = f"{vg:.2f}%" if is_pct else str(vg)
            q_str = f"{vq:.2f}%" if is_pct else str(vq)
            summary_lines.append(f"{label:32s} | {g_str:22s} | {q_str:22s}")
            
    summary_content = "\n".join(summary_lines)
    with open(SUMMARY_TXT_PATH, "w", encoding="utf-8") as f:
        f.write(summary_content)
        
    # Print to stdout as required
    print("\n" + summary_content, flush=True)
    print("\n" + "=" * 85, flush=True)
    print("EVALUATION COMPLETE", flush=True)
    print(f"Number evaluated: {total_records}", flush=True)
    print(f"Detailed JSON results saved to: {RESULTS_JSON_PATH}", flush=True)
    print(f"Readable summary saved to:      {SUMMARY_TXT_PATH}", flush=True)
    print("=" * 85, flush=True)


if __name__ == "__main__":
    run_benchmark()
