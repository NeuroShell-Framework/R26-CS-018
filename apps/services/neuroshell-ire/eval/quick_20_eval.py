"""NeuroShell IRE — quick 20-request spot check under the active model.
Picks a deterministic sample EXCLUDING the 44-record A/B slice inputs so every
call is a real inference (no disk-cache hits). Reports cache_hit and tier."""
import json
import random
import time
import urllib.request
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DS = ROOT / "golden_dataset.jsonl"
SLICE_FILE = ROOT / "Data Collection" / "results" / "ab_slice.json"
BASE = "http://127.0.0.1:8001/parse"
SEED = 20260828
ORDER = [
    "well_formed",
    "well_formed",
    "well_formed",
    "well_formed",
    "well_formed",
    "well_formed",
    "well_formed",
    "well_formed",
    "well_formed",
    "well_formed",
    "well_formed",
    "well_formed",
    "rbac_violation",
    "rbac_violation",
    "adversarial_injection",
    "adversarial_injection",
    "out_of_scope",
    "out_of_scope",
    "hallucination_contradictory_action_target",
    "hallucination_contradictory_action_target",
]
N = len(ORDER)


def load_records():
    return [json.loads(l) for l in open(DS, encoding="utf-8")]


def build_pool(records):
    slice_inputs = {c["input"] for c in json.loads(SLICE_FILE.read_text(encoding="utf-8"))}
    pool = {}
    for r in records:
        if r["input"] not in slice_inputs:
            pool.setdefault(r["category"], []).append(r)
    return pool


def parse_correct(cat, resp, expected, blocked_reason):
    status = resp.get("status")
    intent = resp.get("intent") or resp.get("error")
    if blocked_reason:
        return status == "error"
    if cat == "adversarial_injection":
        return status == "error" or intent == "REJECTED"
    return status == "success" and intent == expected


def call_parse(record, idx):
    body = json.dumps({
        "command": record["input"],
        "session_id": f"quick-{idx}",
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
        return json.loads(r.read().decode("utf-8")), round((time.time() - t0) * 1000, 1)


def main():
    pool = build_pool(load_records())
    rng = random.Random(SEED)
    chosen = []
    for cat in ORDER:
        cands = [r for r in pool.get(cat, []) if r not in chosen]
        if not cands:
            continue
        chosen.append(rng.choice(cands))

    rows = []
    t_start = time.time()
    for idx, rec in enumerate(chosen):
        resp, wall = call_parse(rec, idx)
        ok = parse_correct(
            rec["category"], resp, rec["expected_intent"], rec.get("expected_blocked_reason")
        )
        chat = resp.get("chat_response") or ""
        got = resp.get("intent") or resp.get("error") or "none"
        row = {
            "idx": idx,
            "category": rec["category"],
            "input": rec["input"],
            "expected_intent": rec["expected_intent"],
            "predicted_intent": resp.get("intent"),
            "status": resp.get("status"),
            "error": resp.get("error"),
            "stage": resp.get("stage"),
            "correct": bool(ok),
            "cache_hit": resp.get("cache_hit"),
            "tier": resp.get("tier_triggered"),
            "band": resp.get("uncertainty_band"),
            "latency_ms": resp.get("latency_ms"),
            "wall_ms": wall,
            "chat_atoms": len(chat) if chat else 0,
        }
        rows.append(row)
        filled = int(24 * (idx + 1) / N)
        bar = "#" * filled + "-" * (24 - filled)
        print(
            f"[{bar}] {idx + 1}/{N} {rec['category'][:22]:22s} "
            f"exp={rec['expected_intent'][:13]:13s} got={str(got)[:13]:13s} "
            f"ok={int(ok)} lat={resp.get('latency_ms') or 0:6.0f}ms "
            f"tier={resp.get('tier_triggered')}", flush=True,
        )

    accurate = sum(1 for r in rows if r["correct"])
    by_cat = Counter()
    by_cat_n = Counter()
    for r in rows:
        by_cat[r["category"]] += int(r["correct"])
        by_cat_n[r["category"]] += 1
    lats = [r["latency_ms"] for r in rows if r.get("latency_ms") not in (None, 0)]
    lats.sort()
    def pct(p):
        return lats[int(p * (len(lats) - 1))]
    result = {
        "n": len(rows),
        "intent_accuracy_pct": round(100 * accurate / len(rows), 2),
        "cache_hits": [r for r in rows if r.get("cache_hit")],
        "latency_s": {
            "count": len(lats),
            "p50_ms": round(pct(0.50), 1),
            "p95_ms": round(pct(0.95), 1),
            "mean_ms": round(sum(lats) / len(lats), 1) if lats else 0,
        },
        "tier_counts": dict(Counter(r["tier"] for r in rows)),
        "by_category": {c: {"n": by_cat_n[c], "correct": by_cat[c]} for c in ORDER},
        "rows": rows,
    }
    out = ROOT / "Data Collection" / "results" / "quick_qwen20.json"
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({
        "n": result["n"],
        "accuracy_pct": result["intent_accuracy_pct"],
        "latency": result["latency_s"],
        "cache_hits": [r for r in rows if r.get("cache_hit")],
        "tiers": result["tier_counts"],
    }, indent=2))


if __name__ == "__main__":
    main()