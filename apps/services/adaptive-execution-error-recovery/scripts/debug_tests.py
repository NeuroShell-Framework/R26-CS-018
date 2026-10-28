"""Debug test script — test nmap, nikto, gobuster error recovery."""
import urllib.request
import json
import sys

SEP = "=" * 60

def test(name, payload):
    print(f"\n{SEP}")
    print(f"TEST: {name}")
    print(SEP)
    try:
        data_bytes = json.dumps(payload).encode()
        req = urllib.request.Request(
            "http://localhost:8003/execute",
            data=data_bytes,
            headers={"Content-Type": "application/json"},
        )
        resp = urllib.request.urlopen(req, timeout=180)
        data = json.loads(resp.read())
        print(f"  Status: {data['status']}")
        print(f"  Exit Code: {data['exit_code']}")
        print(f"  Command Executed: {data['command_executed'][:120]}")
        print(f"  Corrections: {len(data.get('correction_history', []))}")
        for c in data.get("correction_history", []):
            print(f"    Attempt {c['attempt']}:")
            print(f"      Original : {c['original_command'][:80]}")
            print(f"      Corrected: {c['corrected_command'][:80]}")
            print(f"      Source: {c['correction_source']}, Strategy: {c['strategy']}, Approved: {c['approved']}")
        if data.get("stderr"):
            print(f"  STDERR: {data['stderr'][:200]}")
        if data.get("failure_report"):
            print(f"  Failure: {json.dumps(data['failure_report'], indent=4)}")
        return data
    except Exception as e:
        print(f"  ERROR: {e}")
        return None


# ── NMAP TESTS ──
test("nmap: wrong syntax (--invalidflag)", {
    "command": "nmap --invalidflag 192.168.1.1",
    "tool": "nmap", "session_id": "dbg-nmap-01",
    "intent_ref": "NETWORK_SCAN", "estimated_duration": "short",
})

test("nmap: sudo prefix", {
    "command": "sudo nmap -sS 192.168.1.1",
    "tool": "nmap", "session_id": "dbg-nmap-02",
    "intent_ref": "NETWORK_SCAN", "estimated_duration": "short",
})

test("nmap: aggressive params -T5 -t 100", {
    "command": "nmap -T5 -t 100 192.168.1.0/24",
    "tool": "nmap", "session_id": "dbg-nmap-03",
    "intent_ref": "NETWORK_SCAN", "estimated_duration": "medium",
})

# ── NIKTO TESTS ──
test("nikto: tool not installed", {
    "command": "nikto -h http://192.168.1.10",
    "tool": "nikto", "session_id": "dbg-nikto-01",
    "intent_ref": "VULNERABILITY_AUDIT", "estimated_duration": "medium",
})

# ── GOBUSTER TESTS ──
test("gobuster: tool not installed", {
    "command": "gobuster dir -u http://192.168.1.10 -w /usr/share/wordlists/common.txt",
    "tool": "gobuster", "session_id": "dbg-gob-01",
    "intent_ref": "DIRECTORY_BRUTEFORCE", "estimated_duration": "medium",
})

test("gobuster: wrong syntax", {
    "command": "gobuster dir --invalidmode -u http://192.168.1.10",
    "tool": "gobuster", "session_id": "dbg-gob-02",
    "intent_ref": "DIRECTORY_BRUTEFORCE", "estimated_duration": "short",
})

# ── SUCCESS BASELINE ──
test("echo: should succeed", {
    "command": "echo hello_from_kali",
    "tool": "echo", "session_id": "dbg-echo-01",
    "intent_ref": "TEST", "estimated_duration": "short",
})

print(f"\n{SEP}")
print("ALL TESTS COMPLETE")
print(SEP)
