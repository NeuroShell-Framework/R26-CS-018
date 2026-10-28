"""
Full-chain runner.

Drives every case in cases.json through the running stack via C1's /execute
endpoint, which synchronously fans out to C2 -> C3 -> C4. Raw responses are
persisted to results/raw_<timestamp>.json for the evaluator to consume.

Usage:
    python tests/full_chain/run_full_chain.py
    python tests/full_chain/run_full_chain.py --c1 http://127.0.0.1:8001 --timeout 300
"""

import os
import sys
import json
import time
import argparse
import datetime
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
CASES_PATH = os.path.join(HERE, "cases.json")
RESULTS_DIR = os.path.join(HERE, "results")


def http_post_json(url, payload, timeout):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
            status = resp.status
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        status = e.code
    except Exception as e:  # noqa: BLE001
        return status_none(e), round(time.perf_counter() - started, 2)
    elapsed = round(time.perf_counter() - started, 2)
    try:
        parsed = json.loads(body)
    except Exception:  # noqa: BLE001
        parsed = {"_raw": body[:4000]}
    return {"http_status": status, "body": parsed}, elapsed


def status_none(exc):
    return {"http_status": 0, "body": {"_error": f"{type(exc).__name__}: {exc}"}}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--c1", default="http://127.0.0.1:8001")
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--only", default=None, help="comma-separated case ids")
    ap.add_argument("--role", default="analyst", help="RBAC role sent to C1 (default: analyst)")
    args = ap.parse_args()

    with open(CASES_PATH, "r", encoding="utf-8") as f:
        suite = json.load(f)

    cases = suite["cases"]
    if args.only:
        wanted = {c.strip() for c in args.only.split(",")}
        cases = [c for c in cases if c["id"] in wanted]

    os.makedirs(RESULTS_DIR, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(RESULTS_DIR, f"raw_{stamp}.json")

    results = []
    t_start = time.perf_counter()
    print(f"Full-chain suite: {len(cases)} cases -> {args.c1}/execute")
    for i, case in enumerate(cases, 1):
        payload = {
            "command": case["command"],
            "session_id": f"fc-{case['id'].lower()}",
            "role": case.get("role", args.role),
        }
        resp, elapsed = http_post_json(f"{args.c1}/execute", payload, args.timeout)
        results.append({
            "case": case,
            "response": resp,
            "wall_seconds": elapsed,
        })
        ok = "ERR" if resp["http_status"] != 200 else "ok"
        print(f"  [{i:02d}/{len(cases)}] {case['id']:7s} {ok:3s} {elapsed:6.1f}s  {case['command']}")

    total_seconds = round(time.perf_counter() - t_start, 1)
    artifact = {
        "suite": suite.get("suite"),
        "generated_at": stamp,
        "c1_url": args.c1,
        "timeout_seconds": args.timeout,
        "case_count": len(cases),
        "total_seconds": total_seconds,
        "results": results,
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2)

    print(f"\nRaw results: {out_path}")
    print(f"Total wall time: {total_seconds}s")
    print(f"RAW={out_path}")


if __name__ == "__main__":
    main()
