import json
import os
import ollama
from fastapi.testclient import TestClient
from src.api.main import app, API_KEY

client = TestClient(app)

last_captured_chat = {"content": None, "model": None}
orig_chat = ollama.chat

def wrapped_chat(*args, **kwargs):
    res = orig_chat(*args, **kwargs)
    last_captured_chat["model"] = kwargs.get("model", os.getenv("OLLAMA_MODEL", "neuroshell-c2-gemma2-final"))
    try:
        last_captured_chat["content"] = res["message"]["content"].strip()
    except Exception:
        last_captured_chat["content"] = None
    return res

ollama.chat = wrapped_chat

def run_case(title: str, payload: dict):
    print(f"\n==================================================")
    print(f"CASE: {title}")
    print("INPUT PAYLOAD:")
    print(json.dumps(payload, indent=2))

    last_captured_chat["content"] = None
    last_captured_chat["model"] = None

    res = client.post("/plan", json=payload, headers={"x-api-key": API_KEY})
    body = res.json()

    raw = last_captured_chat["content"]
    model_used = last_captured_chat["model"]

    print(f"\nOLLAMA MODEL USED: {model_used or 'Unknown/Capture Unavailable'}")
    if raw is not None:
        print(f"RAW MODEL OUTPUT:\n{raw}")
    else:
        print("RAW MODEL OUTPUT: Capture Unavailable")

    print(f"\nHTTP STATUS: {res.status_code}")
    if res.status_code == 200:
        final_cmd = body.get("command")
        print(f"FINAL API COMMAND: {final_cmd}")
        print(f"RAW VS FINAL COMPARISON: ")
        if raw is None:
            print("  - Raw model output capture unavailable")
        elif raw == final_cmd:
            print("  - Identical (raw model output equals final API command)")
        else:
            print(f"  - Differences detected:\n    Raw:   {raw}\n    Final: {final_cmd}")
        print(f"VALIDATION PASSED: {body.get('validation_passed')}")
        print(f"LATENCY: {body.get('latency_ms')} ms")
    else:
        print(f"REJECTION DETAIL:\n{json.dumps(body.get('detail'), indent=2)}")

if __name__ == "__main__":
    # Case 1: Nmap
    run_case("1. Nmap Network Stealth Scan", {
        "session_id": "c1-live-nmap",
        "intent": "NETWORK_SCAN",
        "target_value": "192.168.1.50",
        "target_type": "IP",
        "ports": [80, 443],
        "modifiers": ["stealth"],
        "primary_tool": "nmap"
    })

    # Case 2: Nikto
    run_case("2. Nikto Vulnerability Audit", {
        "session_id": "c1-live-nikto",
        "intent": "VULNERABILITY_AUDIT",
        "target_value": "10.0.0.5",
        "target_type": "IP",
        "ports": [8080],
        "primary_tool": "nikto"
    })

    # Case 3: Original Gobuster 192.168.1.50 Case
    run_case("3. Original Gobuster (Target http://192.168.1.50)", {
        "session_id": "c1-live-gobuster-orig",
        "intent": "DIRECTORY_BRUTEFORCE",
        "target_value": "http://192.168.1.50",
        "target_type": "URL",
        "ports": [80],
        "primary_tool": "gobuster",
        "tool_parameters": {
            "wordlist": "common.txt"
        }
    })

    # Case 4: Rich C1 IntentContract Payload
    run_case("4. Rich C1 Payload Format (IREIntentContract)", {
        "session_id": "c1-live-rich-payload",
        "intent_contract": {
            "intent": "DIRECTORY_BRUTEFORCE",
            "sub_intent": "wordlist_scan",
            "target_type": "URL",
            "target_value": "http://192.168.1.1",
            "primary_tool": "gobuster",
            "ports": [80],
            "modifiers": ["silent"],
            "tool_parameters": {
                "target": "http://192.168.1.1",
                "flags": ["-q"],
                "wordlist": "common.txt"
            },
            "confidence": 0.98
        }
    })
