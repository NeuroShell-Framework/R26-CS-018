"""
NeuroShell IRE — Fresh model A/B benchmark (cold cache, live /parse)
Runs a fixed stratified slice of the golden dataset through the live
daemon and scores intent accuracy + catch behaviour + latency.

The daemon must be freshly restarted for the model under test so both the
in-memory semantic cache and the inference L1 cache are empty. Each record
uses a unique session id. Responses with cache_hit != null are treated as
contamination and counted separately (never silently used).

Usage:
    python eval/model_ab_benchmark.py --model qwen2.5-coder:7b --out qwen_fresh.json
    python eval/model_ab_benchmark.py --model gemma4:latest  --out gemma_fresh.json
"""

import argparse
import json
import random
import sys
import time
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DS = ROOT / "eval" / "golden_dataset.jsonl"
SLICE_FILE = ROOT / "eval" / "Data Collection" / "results" / "ab_slice.json"
BASE = "http://127.0.0.1:8001/parse"
SEED = 20260828

CAPS = {
    "well_formed": 10,
    "adversarial_injection": 5,
    "ambiguous": 5,
    "hallucination_contradictory_action_target": 5,
    "hallucination_fabricated_cve": 4,
    "hallucination_fabricated_parameter": 4,
    "hallucination_target_type_mismatch": 4,
    "out_of_scope": 5,
    "rbac_violation": 2,
}


def load_records():
    return [json.loads(l) for l in open(DS, encoding="utf-8")]


def build_slice(records):
    rng = random.Random(SEED)
    by_cat = defaultdict(list)
    for r in records:
        by_cat[r["category"]].append(r)
    chosen = []
    for cat, cap in CAPS.items():
        pool = by_cat.get(cat, [])
        rng.shuffle(pool)
        chosen.extend(pool[:cap])
    chosen.sort(key=lambda r: int(r.get("idx", 0)))
    return chosen


def parse_correct(row, resp):
    """Match the decision criterion used by the Exp scripts."""
    status = resp.get("status")
    intent = resp.get("intent") or resp.get("error")
    if row.get("expected_blocked_reason"):
        return status == "error"
    if row["category"] == "adversarial_injection":
        return status == "error" or intent == "REJECTED"
    return status == "success" and intent == row["expected_intent"]


def call_parse(record, model, idx):
    session_id = f"ab-{model}-{idx}"
    body = json.dumps({
        "command": record["input"],
        "session_id": session_id,
        "schema_version": 2,
        "role": record.get("expected_role") or "analyst",
    }).encode("utf-8")
    req = urllib.request.Request(
        BASE, data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    t0 = time.time()
    with urllib.request.urlopen(req, timeout=600) as r:
        payload = json.loads(r.read().decode("utf-8"))
    wall_ms = round((time.time() - t0) * 1000, 1)
    payload["_wall_ms"] = wall_ms
    return payload


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    records = load_records()
    if SLICE_FILE.exists():
        chosen = [json.loads(x) if isinstance(x, str) else x
                  for x in json.loads(SLICE_FILE.read_text(encoding="utf-8"))]
        # rehydrate from full record list to recover fields
        by_input = {r["input"]: r for r in records}
        chosen = [by_input[c["input"]] for c in chosen]
    else:
        chosen = build_slice(records)
        SLICE_FILE.write_text(
            json.dumps([{"input": r["input"]} for r in chosen], indent=2),
            encoding="utf-8",
        )

    rows, contaminated = [], []
    t_start = time.time()
    total = len(chosen)
    bar_w = 24
    for idx, rec in enumerate(chosen):
        step = idx + 1
        resp = call_parse(rec, args.model, idx)
        ok = parse_correct(rec, resp)
        cache_hit = resp.get("cache_hit")
        item = {
            "idx": idx,
            "category": rec["category"],
            "difficulty": rec.get("difficulty"),
            "input": rec["input"],
            "expected_intent": rec["expected_intent"],
            "predicted_intent": resp.get("intent"),
            "status": resp.get("status"),
            "error": resp.get("error"),
            "stage": resp.get("stage"),
            "correct": bool(ok),
            "cache_hit": cache_hit,
            "tier": resp.get("tier_triggered"),
            "band": resp.get("uncertainty_band"),
            "latency_ms": resp.get("latency_ms"),
            "wall_ms": resp.get("_wall_ms"),
            "validation_findings": len(resp.get("validation_findings") or []),
        }
        if cache_hit not in (None, "none"):
            contaminated.append(item)
        rows.append(item)
        elapsed = time.time() - t_start
        eta_s = (elapsed / step) * (total - step)
        filled = int(bar_w * step / total)
        bar = "#" * filled + "-" * (bar_w - filled)
        got = str(item["predicted_intent"] or item["error"] or "ERR")
        print(
            f"[{bar}] {step}/{total} {100*step/total:4.1f}% "
            f"eta {eta_s/60:5.1f}m | {rec['category'][:26]:26s} "
            f"exp={rec['expected_intent'][:14]:14s} got={got[:14]:14s} "
            f"ok={int(ok)} lat={resp.get('latency_ms') or 0:7.0f}ms "
            f"tier={resp.get('tier_triggered')}",
            flush=True,
        )

    rows[-1]["_total_elapsed_s"] = round(time.time() - t_start, 1)
    accurate = sum(1 for r in rows if r["correct"])
    by_cat = defaultdict(lambda: [0, 0])
    for r in rows:
        by_cat[r["category"]][0] += 1
        by_cat[r["category"]][1] += int(r["correct"])
    latencies = [r["latency_ms"] for r in rows if r.get("latency_ms") not in (None, 0)]
    latencies.sort()
    def pct(p):
        return latencies[int(p * (len(latencies) - 1))]
    result = {
        "model": args.model,
        "n": len(rows),
        "intent_accuracy_pct": round(100 * accurate / len(rows), 2),
        "contaminated_count": len(contaminated),
        "latency_s": {
            "count": len(latencies),
            "p50_ms": round(pct(0.50), 1),
            "p95_ms": round(pct(0.95), 1),
            "mean_ms": round(sum(latencies) / len(latencies), 1) if latencies else 0,
            "min_ms": round(min(latencies), 1) if latencies else 0,
            "max_ms": round(max(latencies), 1) if latencies else 0,
        },
        "tier_counts": dict(Counter(r["tier"] for r in rows)),
        "by_category": {c: {"n": n, "correct": ok, "pct": round(100 * ok / n, 1)}
                        for c, (n, ok) in sorted(by_cat.items())},
        "rows": rows,
        "contaminated": contaminated,
    }
    out = ROOT / "eval" / "Data Collection" / "results" / args.out
    Path(out.parent).mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({
        "model": args.model,
        "n": len(rows),
        "accuracy_pct": result["intent_accuracy_pct"],
        "latency": result["latency_s"],
        "contaminated": len(contaminated),
        "tiers": result["tier_counts"],
    }, indent=2))


if __name__ == "__main__":
    main()