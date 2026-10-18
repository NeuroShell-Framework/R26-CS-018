import json, time, urllib.request

API = "http://localhost:8003/execute"

# (expected_class, command, tool, intent_ref)
PILOT = [
    ("TOOL_NOT_INSTALLED",  "nmapp -sV 192.168.1.1",                              "nmapp",   "NETWORK_SCAN"),
    ("WRONG_SYNTAX",        "nmap --totally-invalid-flag-xyz 192.168.1.1",        "nmap",    "NETWORK_SCAN"),
    ("PERMISSION_DENIED",   "nmap -sV 192.168.1.1 -oN /root/../etc/shadow_x",     "nmap",    "NETWORK_SCAN"),
    ("NETWORK_UNREACHABLE", "nmap -sV -Pn --host-timeout 5s 10.255.255.1",        "nmap",    "NETWORK_SCAN"),
    ("TIMEOUT",             "curl --max-time 2 http://10.255.255.1",              "curl",    "VULNERABILITY_AUDIT"),
    ("RESOURCE_EXHAUSTION", "nmap -sV --min-parallelism 100000 192.168.1.1",      "nmap",    "NETWORK_SCAN"),
    ("AUTH_FAILURE",        "hydra -l baduser -p badpass ssh://192.168.1.1",      "hydra",   "PASSWORD_ATTACK"),
    ("VERSION_MISMATCH",    "nmap --datadir /nonexistent --deprecated-xyz 192.168.1.1", "nmap", "NETWORK_SCAN"),
]

def call(cmd, tool, intent, sid):
    body = json.dumps({
        "command": cmd, "tool": tool, "session_id": sid,
        "intent_ref": intent, "estimated_duration": "short"
    }).encode()
    req = urllib.request.Request(API, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=180) as resp:
        return json.loads(resp.read().decode())

results = []
print("EXPECTED".ljust(22) + "PREDICTED".ljust(22) + "STATUS".ljust(12) + "MATCH")
print("-" * 70)
for i, (expected, cmd, tool, intent) in enumerate(PILOT):
    sid = "pilot-" + str(i+1)
    try:
        r = call(cmd, tool, intent, sid)
        rlog = r.get("recovery_log", [])
        predicted = rlog[0]["error_class"] if rlog else (r.get("failure_report") or {}).get("final_error_class", "NONE")
        status = r.get("status", "?")
        latency = r.get("latency_ms", 0)
    except Exception as e:
        predicted, status, latency, r = "ERROR:" + type(e).__name__, "error", 0, {"error": str(e)}
    match = "OK" if predicted == expected else "XX <-- MISMATCH"
    print(expected.ljust(22) + str(predicted).ljust(22) + str(status).ljust(12) + match)
    results.append({"expected": expected, "predicted": predicted, "status": status,
                    "latency_ms": latency, "command": cmd, "full_response": r})

with open("pilot_results.json", "w") as f:
    json.dump(results, f, indent=2)

correct = sum(1 for x in results if x["predicted"] == x["expected"])
print("-" * 70)
print("Pilot: " + str(correct) + "/8 classes correctly triggered + classified")
print("Full results written to pilot_results.json")
