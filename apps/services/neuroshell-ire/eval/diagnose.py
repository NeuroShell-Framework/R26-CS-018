# NeuroShell IRE — Diagnostic Eval Runner
# Runs the full pipeline on the dataset and logs per-row debug info to JSONL.
# After the run, calls metrics.py to produce the per-category breakdown.

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import json
import time
from typing import Dict, Any, List

from src.pipeline.ire_pipeline import IREPipeline
from src.schemas.intent_schema import ParseRequestV2


def classify_decision(resp) -> str:
    """Classify pipeline response into ALLOWED / BLOCKED / ESCALATED."""
    if resp.status == "error":
        return "BLOCKED"

    findings = getattr(resp, "validation_findings", []) or []
    has_block = any(not f.passed and f.severity == "block" for f in findings)
    has_escalate = any(not f.passed and f.severity == "escalate" for f in findings)
    has_warn = any(not f.passed and f.severity == "warn" for f in findings)

    intent_val = resp.intent.value if resp.intent else None

    if has_escalate:
        return "ESCALATED"
    if has_block:
        return "BLOCKED"
    if intent_val == "REJECTED":
        return "BLOCKED"
    if has_warn:
        return "BLOCKED"
    return "ALLOWED"


def extract_violation_codes(resp) -> List[str]:
    """Extract violation codes from validation findings."""
    codes = []
    for f in getattr(resp, "validation_findings", []) or []:
        if not f.passed:
            hc = f.hallucination_class.value if f.hallucination_class else None
            if hc:
                codes.append(hc)
            else:
                codes.append(f.validator)
    return codes


def run_diagnostic(dataset_path: str = "eval/dataset_draft.jsonl",
                   output_path: str = "eval/full_pipeline_debug.jsonl",
                   limit: int = 0) -> None:
    print(f"[*] Initializing IREPipeline for Diagnostic Run on {dataset_path}...")
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

    if limit > 0:
        records = records[:limit]
    total = len(records)
    print(f"[*] Loaded {total} records. Running pipeline...\n")

    debug_rows = []
    # Clear any previous partial run
    if os.path.exists(output_path):
        os.remove(output_path)

    for idx, record in enumerate(records, start=1):
        req = ParseRequestV2(
            command=record["input"],
            role="analyst",
            session_id=f"diag-{idx}"
        )
        start = time.time()
        resp = pipeline.parse(req)
        elapsed_ms = (time.time() - start) * 1000.0

        decision = classify_decision(resp)
        violation_codes = extract_violation_codes(resp)

        predicted_intent = resp.intent.value if resp.intent else None
        predicted_target = resp.target.value if resp.target else None
        predicted_cves = list(resp.cve_ids) if resp.cve_ids else []

        # Build debug row
        debug_row = {
            "row_idx": idx,
            "category": record["category"],
            "input": record["input"],
            "expected_intent": record.get("expected_intent"),
            "expected_target": record.get("expected_target"),
            "expected_cve": record.get("expected_cve_or_null"),
            "predicted_intent": predicted_intent,
            "predicted_target": predicted_target,
            "predicted_cves": predicted_cves,
            "cache_hit": resp.cache_hit,
            "final_decision": decision,
            "violation_codes": violation_codes,
            "status": resp.status,
            "confidence": resp.confidence,
            "uncertainty_band": resp.uncertainty_band,
            "tier_triggered": resp.tier_triggered,
            "latency_ms": round(elapsed_ms, 1),
        }

        # Correctness flags
        if record["category"] == "well_formed":
            intent_ok = (predicted_intent == record.get("expected_intent"))
            target_ok = (
                not record.get("expected_target")
                or predicted_target == record["expected_target"]
            )
            debug_row["intent_correct"] = intent_ok
            debug_row["target_correct"] = target_ok
            debug_row["row_correct"] = (decision == "ALLOWED" and intent_ok and target_ok)
        else:
            debug_row["row_correct"] = decision in ("BLOCKED", "ESCALATED")

        debug_rows.append(debug_row)

        # Write incrementally so partial runs are preserved
        with open(output_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(debug_row) + "\n")

        pct = (idx / total) * 100.0
        marker = "OK" if debug_row["row_correct"] else "!!"
        print(
            f"  [{idx}/{total} - {pct:.1f}%] [{marker}] "
            f"({record['category']}) decision={decision} "
            f"cache={resp.cache_hit or 'none'} "
            f"intent={predicted_intent} "
            f"violations={violation_codes or 'none'} "
            f"{elapsed_ms:.0f}ms"
        )
        sys.stdout.flush()

    # Write debug JSONL (already written incrementally; this overwrites with final set)
    with open(output_path, "w", encoding="utf-8") as f:
        for row in debug_rows:
            f.write(json.dumps(row) + "\n")
    print(f"\n[+] Debug rows written to {output_path} ({len(debug_rows)} rows)")

    # Summary counts
    from collections import Counter
    decisions = Counter(r["final_decision"] for r in debug_rows)
    cache_hits = sum(1 for r in debug_rows if r["cache_hit"] is not None)
    correct = sum(1 for r in debug_rows if r["row_correct"])
    print(f"\n=== QUICK SUMMARY ===")
    print(f"Total rows:     {len(debug_rows)}")
    print(f"Correct:        {correct}/{len(debug_rows)} ({correct/len(debug_rows)*100:.1f}%)")
    print(f"Cache hits:     {cache_hits}/{len(debug_rows)} ({cache_hits/len(debug_rows)*100:.1f}%)")
    print(f"Decisions:      {dict(decisions)}")

    # Run per-category metrics
    print(f"\n[*] Computing per-category breakdown...")
    from eval.metrics import compute_category_metrics, print_category_report
    metrics = compute_category_metrics(debug_rows)
    print_category_report(metrics)

    metrics_path = output_path.replace(".jsonl", "_category_metrics.json")
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(f"\n[+] Category metrics written to {metrics_path}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Diagnostic eval runner")
    parser.add_argument("dataset", nargs="?", default="eval/dataset_draft.jsonl", help="Dataset JSONL path")
    parser.add_argument("--limit", type=int, default=0, help="Max rows to process (0=all)")
    args = parser.parse_args()
    run_diagnostic(args.dataset, limit=args.limit)
