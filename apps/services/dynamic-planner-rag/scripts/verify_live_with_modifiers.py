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
    "model": None,
    "prompt": None
}

orig_chat = ollama.chat

def capturing_chat(*args, **kwargs):
    res = orig_chat(*args, **kwargs)
    captured["model"] = kwargs.get("model")
    for msg in kwargs.get("messages", []):
        if msg.get("role") == "user":
            captured["prompt"] = msg.get("content")
    try:
        captured["raw_output"] = res["message"]["content"].strip()
    except Exception:
        captured["raw_output"] = None
    return res

ollama.chat = capturing_chat


def run_live_modifier_test():
    print("=" * 85)
    print("LIVE /plan ENDPOINT VERIFICATION WITH REQUESTED EXTRA MODIFIERS")
    print("=" * 85)

    client = TestClient(app)

    # Request with explicit extra modifier -t 50
    payload = {
        "session_id": "live-modifiers-verify-001",
        "intent": "DIRECTORY_BRUTEFORCE",
        "target_value": "http://192.168.1.50",
        "target_type": "URL",
        "ports": [80],
        "primary_tool": "gobuster",
        "modifiers": ["-t 50"],
        "tool_parameters": {
            "wordlist": "common.txt"
        }
    }

    print("INPUT PAYLOAD:")
    print(json.dumps(payload, indent=2))

    t0 = time.time()
    res = client.post("/plan", json=payload, headers={"x-api-key": API_KEY})
    elapsed = (time.time() - t0) * 1000

    status = res.status_code
    body = res.json()
    raw_cmd = captured["raw_output"]

    print(f"\nOLLAMA MODEL USED: {captured['model']}")
    print(f"RAW MODEL OUTPUT:  {raw_cmd}")
    print(f"HTTP STATUS CODE:  {status}")

    if status == 200:
        final_cmd = body.get("command")
        print(f"FINAL API COMMAND: {final_cmd}")
        print(f"VALIDATION PASSED: {body.get('validation_passed')}")
        print(f"API LATENCY:       {body.get('latency_ms')} ms")

        # Verify preservation of requested components
        has_target = "http://192.168.1.50" in raw_cmd and "http://192.168.1.50" in final_cmd
        has_wordlist = "common.txt" in raw_cmd and "common.txt" in final_cmd
        has_modifier = "-t 50" in raw_cmd and "-t 50" in final_cmd
        has_dir = "gobuster dir" in raw_cmd and "gobuster dir" in final_cmd

        print("\nVERIFICATION OF REQUESTED COMPONENTS:")
        print(f"  - gobuster dir mode preserved: {has_dir}")
        print(f"  - Target (http://192.168.1.50) preserved: {has_target}")
        print(f"  - Wordlist (common.txt) preserved: {has_wordlist}")
        print(f"  - Requested modifier (-t 50) preserved: {has_modifier}")

        all_ok = has_dir and has_target and has_wordlist and has_modifier and (body.get("validation_passed") is True)
        print(f"\nOVERALL RESULT: {'SUCCESS' if all_ok else 'FAILURE'}")
        return all_ok
    else:
        print(f"REJECTION DETAIL:\n{json.dumps(body.get('detail'), indent=2)}")
        print("\nOVERALL RESULT: FAILURE")
        return False


if __name__ == "__main__":
    success = run_live_modifier_test()
    sys.exit(0 if success else 1)
