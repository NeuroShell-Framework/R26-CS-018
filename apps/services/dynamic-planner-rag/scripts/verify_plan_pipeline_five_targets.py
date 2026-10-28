import json
import os
import sys
import time
import ollama
from fastapi.testclient import TestClient

# Ensure project root is in python path
sys.path.insert(0, os.path.abspath("."))

from src.api.main import app, API_KEY

captured = {
    "raw_output": None,
    "model": None
}

orig_chat = ollama.chat

def capturing_chat(*args, **kwargs):
    res = orig_chat(*args, **kwargs)
    captured["model"] = kwargs.get("model")
    try:
        captured["raw_output"] = res["message"]["content"].strip()
    except Exception:
        captured["raw_output"] = None
    return res

ollama.chat = capturing_chat


def verify_live_pipeline():
    print("=" * 85)
    print("LIVE /plan ENDPOINT VERIFICATION (neuroshell-c2-gemma2-final)")
    print("=" * 85)

    client = TestClient(app)

    test_targets = [
        {"target": "http://192.168.1.50", "ports": [80], "desc": "1. Original failing target (.50)"},
        {"target": "http://10.0.0.15", "ports": [80], "desc": "2. Class A 10.x private target"},
        {"target": "http://172.16.0.25", "ports": [80], "desc": "3. Class B 172.16.x private target"},
        {"target": "http://192.168.1.1", "ports": [80], "desc": "4. Gateway 192.168.1.1 private target"},
        {"target": "http://192.168.10.88:8080", "ports": [8080], "desc": "5. Custom port :8080 private target"},
    ]

    wordlist = "common.txt"
    summaries = []

    for idx, tc in enumerate(test_targets, 1):
        target = tc["target"]
        ports = tc["ports"]
        desc = tc["desc"]

        print(f"\n[{idx}/5] CASE: {desc}")
        print(f"Target: {target} | Ports: {ports} | Wordlist: {wordlist}")
        print("-" * 75)

        payload = {
            "session_id": f"verify-live-{idx}",
            "intent": "DIRECTORY_BRUTEFORCE",
            "target_value": target,
            "target_type": "URL",
            "ports": ports,
            "primary_tool": "gobuster",
            "tool_parameters": {
                "wordlist": wordlist
            }
        }

        captured["raw_output"] = None
        captured["model"] = None

        t0 = time.time()
        res = client.post("/plan", json=payload, headers={"x-api-key": API_KEY})
        latency = (time.time() - t0) * 1000

        status_code = res.status_code
        body = res.json()
        raw_cmd = captured["raw_output"]

        print(f"  Model Used:       {captured['model']}")
        print(f"  Raw Model Output: {raw_cmd}")
        print(f"  HTTP Status Code: {status_code}")

        if status_code == 200:
            final_cmd = body.get("command")
            val_passed = body.get("validation_passed")
            print(f"  Final API Command:{final_cmd}")
            print(f"  Validation Passed:{val_passed}")
            print(f"  API Latency:      {body.get('latency_ms')} ms")
            summaries.append({
                "target": target,
                "ports": ports,
                "raw": raw_cmd,
                "command": final_cmd,
                "status": status_code,
                "passed": val_passed,
                "success": (status_code == 200 and val_passed is True)
            })
        else:
            print(f"  REJECTION DETAIL:\n{json.dumps(body.get('detail'), indent=4)}")
            summaries.append({
                "target": target,
                "ports": ports,
                "raw": raw_cmd,
                "command": None,
                "status": status_code,
                "passed": False,
                "success": False,
                "detail": body.get("detail")
            })

    print("\n" + "=" * 105)
    print(f"{'TARGET':<30} | {'PORTS':<7} | {'HTTP':<5} | {'VALID':<6} | {'FINAL COMMAND':<45}")
    print("-" * 105)
    for s in summaries:
        cmd_str = s["command"] or "REJECTED"
        print(f"{s['target']:<30} | {str(s['ports']):<7} | {s['status']:<5} | {str(s['passed']):<6} | {cmd_str:<45}")
    print("=" * 105)


if __name__ == "__main__":
    verify_live_pipeline()
