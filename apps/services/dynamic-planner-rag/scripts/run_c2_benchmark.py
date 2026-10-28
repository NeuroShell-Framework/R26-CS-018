"""
Run the C2 pipeline benchmark (evaluate_component.run_evaluation) and persist
the full metrics JSON plus a human-readable summary under data/eval_results/.

Usage (from the service root, with the service venv):
    python scripts/run_c2_benchmark.py
"""

import os
import sys
import json
import datetime

sys.path.insert(0, os.path.abspath("."))

from scripts.evaluate_component import run_evaluation

OUT_DIR = os.path.join("data", "eval_results")


def _pct(metrics, group, key):
    return metrics.get(group, {}).get(key, {}).get("percentage_pct", "N/A")


def main():
    metrics = run_evaluation(verbose=True)

    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(OUT_DIR, exist_ok=True)

    json_path = os.path.join(OUT_DIR, f"c2_benchmark_{stamp}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    summary = metrics["benchmark_summary"]
    cg = metrics["command_generation_metrics"]
    rej = metrics["expected_rejection_metrics"]
    rec = metrics["session_recovery_metrics"]

    lines = [
        "NEUROSHELL C2 — PIPELINE BENCHMARK RESULT",
        f"Run: {stamp} (uuid {summary['run_uuid']})",
        "",
        f"Total cases:              {summary['total_cases']}",
        f"  command generation:     {summary['command_generation_cases']}",
        f"  expected rejection:     {summary['expected_rejection_cases']}",
        f"  session recovery:       {summary['session_recovery_cases']}",
        f"  excluded:               {summary['excluded_cases']}",
        f"Transport exceptions:     {summary['transport_exceptions']}",
        f"Infrastructure failures:  {summary['infrastructure_failures']}",
        f"Avg planning latency:     {summary['avg_planning_latency_ms']} ms",
        "",
        "COMMAND GENERATION",
        f"  semantic command accuracy: {_pct(metrics,'command_generation_metrics','semantic_command_accuracy')}%",
        f"  tool selection:            {_pct(metrics,'command_generation_metrics','tool_selection_accuracy')}%",
        f"  target preservation:       {_pct(metrics,'command_generation_metrics','target_preservation_accuracy')}%",
        f"  port argument:             {_pct(metrics,'command_generation_metrics','port_argument_accuracy')}%",
        f"  option value:              {_pct(metrics,'command_generation_metrics','option_value_accuracy')}%",
        f"  structural validity:       {_pct(metrics,'command_generation_metrics','command_structural_validity')}%",
        f"  safety compliance:         {_pct(metrics,'command_generation_metrics','safety_compliance')}%",
        f"  exact normalized match:    {_pct(metrics,'command_generation_metrics','exact_normalized_match_secondary')}%",
        "",
        "EXPECTED REJECTION",
        f"  status code correctness:   {_pct(metrics,'expected_rejection_metrics','status_code_correctness')}%",
        f"  safety guard compliance:   {_pct(metrics,'expected_rejection_metrics','safety_guard_compliance')}%",
        "",
        "SESSION RECOVERY",
        f"  target recovery accuracy:  {_pct(metrics,'session_recovery_metrics','target_recovery_accuracy')}%",
        "",
        f"Full metrics JSON: {json_path}",
    ]

    txt_path = os.path.join(OUT_DIR, f"c2_benchmark_{stamp}.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print("\n".join(lines))
    print(f"SAVED_JSON={json_path}")
    print(f"SAVED_TXT={txt_path}")


if __name__ == "__main__":
    main()
