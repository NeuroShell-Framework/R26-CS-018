import json
from fastapi.testclient import TestClient
from src.api.main import app, API_KEY

client = TestClient(app)

def run_test(name: str, payload: dict):
    print(f"\n==================================================")
    print(f"TEST: {name}")
    print(f"INPUT PAYLOAD:")
    print(json.dumps(payload, indent=2))

    res = client.post("/plan", json=payload, headers={"x-api-key": API_KEY})
    print(f"\nHTTP STATUS: {res.status_code}")
    print("API RESPONSE DATA:")
    print(json.dumps(res.json(), indent=2))

if __name__ == "__main__":
    # Test 3B: Gobuster with matching target 192.168.1.1
    run_test("Gobuster Directory Bruteforce with Wordlist (Target 192.168.1.1)", {
        "session_id": "live-test-gobuster-2",
        "intent": "DIRECTORY_BRUTEFORCE",
        "target_value": "http://192.168.1.1",
        "target_type": "URL",
        "ports": [80],
        "primary_tool": "gobuster",
        "tool_parameters": {
            "wordlist": "common.txt"
        }
    })
