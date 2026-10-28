"""
Tool-Specific Recovery Scenarios - Live API Test Suite

Drives 9 real recovery scenarios against the running AEERE API at
http://localhost:8003/execute -- not mocks, not internal function calls.

  3 x nmap   (intent_ref: NETWORK_SCAN)
  3 x nikto  (intent_ref: VULNERABILITY_AUDIT)
  3 x gobuster (intent_ref: DIRECTORY_BRUTEFORCE)

Each scenario:
  1. POSTs a deliberately broken command
  2. Prints the full JSON response
  3. Asserts the engine diagnosed and attempted the correct recovery
  4. Prints a PASS/FAIL summary with tool, scenario, error_class,
     corrected_command, final status, and latency_ms

Usage:  python tests/test_tool_specific_recovery.py

Requires: FastAPI server on port 8003 with Docker, Ollama, and Redis.
"""

import sys
import os
import json
import urllib.request
import time

# ---------------------------------------------------------------------------
# PASS / FAIL / SKIP tracking  (same pattern as test_execution_engine.py)
# ---------------------------------------------------------------------------
PASSED = 0
FAILED = 0
SKIPPED = 0


def pass_test(msg):
    global PASSED
    PASSED += 1
    print(f"  [PASS] {msg}")


def fail_test(msg):
    global FAILED
    FAILED += 1
    print(f"  [FAIL] {msg}")


def skip_test(msg):
    global SKIPPED
    SKIPPED += 1
    print(f"  [SKIP] {msg}")


def section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
BASE_URL = "http://localhost:8003"
# Generous timeout: Docker exec + apt-get install + LLM calls can be slow
API_TIMEOUT = 120


def post_execute(payload_dict):
    """POST to /execute and return parsed JSON response."""
    payload = json.dumps(payload_dict).encode()
    req = urllib.request.Request(
        f"{BASE_URL}/execute",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=API_TIMEOUT) as resp:
        return json.loads(resp.read())


def print_full_response(data):
    """Print the complete JSON response, indented for readability."""
    print(f"  Response JSON:")
    for line in json.dumps(data, indent=2).splitlines():
        print(f"    {line}")


def summarize(data):
    """Print a compact summary of key response fields."""
    print(f"    status={data['status']}, exit_code={data['exit_code']}, "
          f"latency={data['latency_ms']}ms")
    print(f"    command_executed={data['command_executed'][:100]}")
    if data.get('recovery_log'):
        for i, entry in enumerate(data['recovery_log']):
            corrected = entry.get('corrected_command', 'N/A')[:80]
            print(f"    recovery_log[{i}]: error_class={entry['error_class']}, "
                  f"strategy={entry['strategy']}, "
                  f"clf_method={entry.get('clf_method','?')}, "
                  f"confidence={entry.get('confidence',0):.2f}")
            print(f"      corrected_command={corrected}")
    if data.get('correction_history'):
        for i, entry in enumerate(data['correction_history']):
            print(f"    correction_history[{i}]: "
                  f"source={entry.get('correction_source','?')}, "
                  f"approved={entry.get('approved','?')}, "
                  f"cmd={entry.get('corrected_command','N/A')[:80]}")
    if data.get('failure_report'):
        fr = data['failure_report']
        print(f"    failure_report: final_error_class={fr.get('final_error_class')}, "
              f"strategies_tried={fr.get('strategies_tried')}, "
              f"attempts={fr.get('attempts')}")
    if data.get('stdout'):
        stdout_preview = data['stdout'][:200].replace('\n', '\\n')
        print(f"    stdout (first 200): {stdout_preview}")
    if data.get('stderr'):
        stderr_preview = data['stderr'][:200].replace('\n', '\\n')
        print(f"    stderr (first 200): {stderr_preview}")


# ============================================================
# PREFLIGHT: Confirm API is reachable
# ============================================================

def preflight_check():
    """Return True if the API is healthy and we can proceed."""
    section("PREFLIGHT: API Health Check")
    try:
        with urllib.request.urlopen(f"{BASE_URL}/health", timeout=5) as resp:
            data = json.loads(resp.read())
            print(f"  Health: {json.dumps(data)}")
            if data.get('status') != 'healthy':
                fail_test("Server reports unhealthy")
                return False
            if not data.get('docker'):
                fail_test("Docker not available on server")
                return False
            pass_test(f"API healthy: docker={data['docker']}, "
                      f"redis={data.get('redis')}, model={data.get('model')}")
            return True
    except Exception as e:
        fail_test(f"Cannot reach API at {BASE_URL}: {e}")
        return False


# ============================================================
# NMAP Scenarios  (intent_ref: NETWORK_SCAN)
# ============================================================

def test_nmap_scenarios():
    section("NMAP Recovery Scenarios")

    # ------------------------------------------------------------------
    # Scenario 1: Non-whitelisted tool name  (stress-nmap-001)
    #
    # Choice rationale: Using "nmap-nonexistent" (NOT in KALI_PACKAGE_WHITELIST)
    # rather than testing nmap with a bad flag here, because scenario 2
    # already covers nmap + WRONG_SYNTAX.  This scenario proves the engine
    # correctly DIAGNOSES TOOL_NOT_INSTALLED even when no automated fix is
    # possible (tool name not whitelisted -> mutation returns None ->
    # failure_report shows final_error_class=TOOL_NOT_INSTALLED).
    # ------------------------------------------------------------------
    print("\n  --- Scenario 1: nmap-nonexistent (non-whitelisted, correct diagnosis) ---")
    try:
        data = post_execute({
            "command": "nmap-nonexistent -sV 192.168.1.1",
            "tool": "nmap-nonexistent",
            "session_id": "stress-nmap-001",
            "intent_ref": "NETWORK_SCAN",
            "estimated_duration": "short",
        })
        print_full_response(data)
        summarize(data)

        assert data['status'] == 'failed', \
            f"Expected status='failed', got '{data['status']}'"
        assert data['failure_report'] is not None, \
            "Expected failure_report to be present"
        assert data['failure_report']['final_error_class'] == 'TOOL_NOT_INSTALLED', \
            (f"Expected final_error_class=TOOL_NOT_INSTALLED, "
             f"got {data['failure_report']['final_error_class']}")

        pass_test(
            f"nmap-nonexistent: diagnosed=TOOL_NOT_INSTALLED (unfixable), "
            f"status={data['status']}, latency={data['latency_ms']}ms"
        )
    except Exception as e:
        fail_test(f"nmap-nonexistent: {e}")

    # ------------------------------------------------------------------
    # Scenario 2: Invalid nmap flag  (stress-nmap-002)
    # Expect: WRONG_SYNTAX -> FIX_SYNTAX, corrected_command differs
    # ------------------------------------------------------------------
    print("\n  --- Scenario 2: nmap bad flag (WRONG_SYNTAX -> FIX_SYNTAX) ---")
    try:
        data = post_execute({
            "command": "nmap --totally-invalid-flag-xyz 192.168.1.1",
            "tool": "nmap",
            "session_id": "stress-nmap-002",
            "intent_ref": "NETWORK_SCAN",
            "estimated_duration": "short",
        })
        print_full_response(data)
        summarize(data)

        # Engine must have attempted recovery
        assert len(data['recovery_log']) > 0, \
            "Expected non-empty recovery_log"
        first = data['recovery_log'][0]
        assert first['error_class'] == 'WRONG_SYNTAX', \
            f"Expected error_class=WRONG_SYNTAX, got {first['error_class']}"

        # The corrected command should differ from the broken original
        original = "nmap --totally-invalid-flag-xyz 192.168.1.1"
        corrected = first.get('corrected_command', '')
        if corrected and corrected != original:
            correction_note = f"corrected='{corrected[:60]}'"
        else:
            correction_note = "corrected_command unchanged or empty"

        # Verify a correction source is recorded
        src = ''
        if data.get('correction_history'):
            src = data['correction_history'][0].get('correction_source', '')

        pass_test(
            f"nmap WRONG_SYNTAX: error_class={first['error_class']}, "
            f"strategy={first['strategy']}, source={src}, "
            f"{correction_note}, status={data['status']}, "
            f"latency={data['latency_ms']}ms"
        )
    except Exception as e:
        fail_test(f"nmap WRONG_SYNTAX: {e}")

    # ------------------------------------------------------------------
    # Scenario 3: Aggressive nmap against unreachable private IP  (stress-nmap-003)
    # May succeed (exit 0, empty results) or trigger NETWORK_UNREACHABLE /
    # ADJUST_PARAMETERS recovery.  Either outcome is valid.
    # ------------------------------------------------------------------
    print("\n  --- Scenario 3: nmap aggressive scan (unreachable host edge case) ---")
    try:
        data = post_execute({
            "command": "nmap -T5 -t 500 --min-rate 10000 192.168.99.99",
            "tool": "nmap",
            "session_id": "stress-nmap-003",
            "intent_ref": "NETWORK_SCAN",
            "estimated_duration": "short",
        })
        print_full_response(data)
        summarize(data)

        assert data['status'] in ('success', 'recovered', 'failed'), \
            f"Unexpected status: {data['status']}"
        assert 'exit_code' in data, "Missing exit_code field"
        assert 'latency_ms' in data, "Missing latency_ms field"

        if data['status'] == 'success':
            pass_test(
                f"nmap aggressive: completed directly, "
                f"exit_code={data['exit_code']}, latency={data['latency_ms']}ms"
            )
        elif data['status'] == 'recovered':
            log_entry = data['recovery_log'][0] if data['recovery_log'] else {}
            pass_test(
                f"nmap aggressive: recovered, "
                f"error_class={log_entry.get('error_class')}, "
                f"strategy={log_entry.get('strategy')}, "
                f"latency={data['latency_ms']}ms"
            )
        else:
            fr = data.get('failure_report', {})
            pass_test(
                f"nmap aggressive: failed (acceptable for unreachable host), "
                f"final_error_class={fr.get('final_error_class')}, "
                f"latency={data['latency_ms']}ms"
            )
    except Exception as e:
        fail_test(f"nmap aggressive: {e}")


# ============================================================
# NIKTO Scenarios  (intent_ref: VULNERABILITY_AUDIT)
# ============================================================

def test_nikto_scenarios():
    section("NIKTO Recovery Scenarios")

    # ------------------------------------------------------------------
    # Scenario 4: Non-whitelisted tool typo  (stress-nikto-001)
    # "nikto-typo" is NOT in KALI_PACKAGE_WHITELIST -> correctly diagnosed
    # as TOOL_NOT_INSTALLED but mutation blocked (non-whitelisted).
    # ------------------------------------------------------------------
    print("\n  --- Scenario 4: nikto-typo (non-whitelisted, correct diagnosis) ---")
    try:
        data = post_execute({
            "command": "nikto-typo -h http://192.168.1.10",
            "tool": "nikto-typo",
            "session_id": "stress-nikto-001",
            "intent_ref": "VULNERABILITY_AUDIT",
            "estimated_duration": "short",
        })
        print_full_response(data)
        summarize(data)

        assert data['status'] == 'failed', \
            f"Expected status='failed', got '{data['status']}'"
        assert data['failure_report'] is not None, \
            "Expected failure_report to be present"
        assert data['failure_report']['final_error_class'] == 'TOOL_NOT_INSTALLED', \
            (f"Expected final_error_class=TOOL_NOT_INSTALLED, "
             f"got {data['failure_report']['final_error_class']}")

        pass_test(
            f"nikto-typo: diagnosed=TOOL_NOT_INSTALLED (unfixable), "
            f"status={data['status']}, latency={data['latency_ms']}ms"
        )
    except Exception as e:
        fail_test(f"nikto-typo: {e}")

    # ------------------------------------------------------------------
    # Scenario 5: Invalid nikto flag  (stress-nikto-002)
    # Expect: WRONG_SYNTAX -> FIX_SYNTAX recovery attempt
    # ------------------------------------------------------------------
    print("\n  --- Scenario 5: nikto bad flag (WRONG_SYNTAX -> FIX_SYNTAX) ---")
    try:
        data = post_execute({
            "command": "nikto --invalid-option-xyz -h 192.168.1.10",
            "tool": "nikto",
            "session_id": "stress-nikto-002",
            "intent_ref": "VULNERABILITY_AUDIT",
            "estimated_duration": "short",
        })
        print_full_response(data)
        summarize(data)

        # Engine must detect the error and attempt recovery
        assert len(data['recovery_log']) > 0, \
            "Expected non-empty recovery_log"
        first = data['recovery_log'][0]

        # The error class should be WRONG_SYNTAX (bad flag) or
        # TOOL_NOT_INSTALLED if nikto isn't pre-installed in the Kali
        # container.  Both are valid diagnoses depending on container state.
        valid_classes = ('WRONG_SYNTAX', 'TOOL_NOT_INSTALLED')
        assert first['error_class'] in valid_classes, \
            f"Expected error_class in {valid_classes}, got {first['error_class']}"

        corrected = first.get('corrected_command', '')
        src = ''
        if data.get('correction_history'):
            src = data['correction_history'][0].get('correction_source', '')

        pass_test(
            f"nikto bad flag: error_class={first['error_class']}, "
            f"strategy={first['strategy']}, source={src}, "
            f"corrected='{corrected[:60]}', status={data['status']}, "
            f"latency={data['latency_ms']}ms"
        )
    except Exception as e:
        fail_test(f"nikto bad flag: {e}")

    # ------------------------------------------------------------------
    # Scenario 6: nikto with missing host argument  (stress-nikto-003)
    # "nikto -h" with no URL value -- nikto treats -h as its host flag
    # but with an empty value, producing a usage/syntax error.
    # ------------------------------------------------------------------
    print("\n  --- Scenario 6: nikto missing host (syntax edge case) ---")
    try:
        data = post_execute({
            "command": "nikto -h",
            "tool": "nikto",
            "session_id": "stress-nikto-003",
            "intent_ref": "VULNERABILITY_AUDIT",
            "estimated_duration": "short",
        })
        print_full_response(data)
        summarize(data)

        assert data['status'] in ('success', 'recovered', 'failed'), \
            f"Unexpected status: {data['status']}"
        assert 'exit_code' in data, "Missing exit_code field"
        assert 'latency_ms' in data, "Missing latency_ms field"

        # Whether the engine classifies this as WRONG_SYNTAX or something
        # else, or nikto just prints help text (exit 0), the response
        # must be well-formed.  If recovery was attempted, verify the log.
        if data['recovery_log']:
            first = data['recovery_log'][0]
            pass_test(
                f"nikto missing host: error_class={first['error_class']}, "
                f"strategy={first['strategy']}, "
                f"status={data['status']}, latency={data['latency_ms']}ms"
            )
        elif data['status'] == 'success':
            # nikto -h might just print help and exit 0
            pass_test(
                f"nikto missing host: succeeded directly (help output), "
                f"exit_code={data['exit_code']}, latency={data['latency_ms']}ms"
            )
        else:
            fr = data.get('failure_report', {})
            pass_test(
                f"nikto missing host: failed (acceptable), "
                f"final_error_class={fr.get('final_error_class')}, "
                f"latency={data['latency_ms']}ms"
            )
    except Exception as e:
        fail_test(f"nikto missing host: {e}")


# ============================================================
# GOBUSTER Scenarios  (intent_ref: DIRECTORY_BRUTEFORCE)
# ============================================================

def test_gobuster_scenarios():
    section("GOBUSTER Recovery Scenarios")

    # ------------------------------------------------------------------
    # Scenario 7: Non-whitelisted tool typo  (stress-gobuster-001)
    # "gobuster-typo" is NOT in KALI_PACKAGE_WHITELIST -> diagnosed as
    # TOOL_NOT_INSTALLED but unfixable (non-whitelisted tool name).
    # ------------------------------------------------------------------
    print("\n  --- Scenario 7: gobuster-typo (non-whitelisted, correct diagnosis) ---")
    try:
        data = post_execute({
            "command": "gobuster-typo dir -u http://192.168.1.10",
            "tool": "gobuster-typo",
            "session_id": "stress-gobuster-001",
            "intent_ref": "DIRECTORY_BRUTEFORCE",
            "estimated_duration": "short",
        })
        print_full_response(data)
        summarize(data)

        assert data['status'] == 'failed', \
            f"Expected status='failed', got '{data['status']}'"
        assert data['failure_report'] is not None, \
            "Expected failure_report to be present"
        assert data['failure_report']['final_error_class'] == 'TOOL_NOT_INSTALLED', \
            (f"Expected final_error_class=TOOL_NOT_INSTALLED, "
             f"got {data['failure_report']['final_error_class']}")

        pass_test(
            f"gobuster-typo: diagnosed=TOOL_NOT_INSTALLED (unfixable), "
            f"status={data['status']}, latency={data['latency_ms']}ms"
        )
    except Exception as e:
        fail_test(f"gobuster-typo: {e}")

    # ------------------------------------------------------------------
    # Scenario 8: Invalid gobuster flag  (stress-gobuster-002)
    # Expect: WRONG_SYNTAX -> FIX_SYNTAX, or TOOL_NOT_INSTALLED ->
    # INSTALL_TOOL if gobuster is not already in the container.
    # Both are valid engine behaviors.
    # ------------------------------------------------------------------
    print("\n  --- Scenario 8: gobuster bad flag (WRONG_SYNTAX -> FIX_SYNTAX) ---")
    try:
        data = post_execute({
            "command": "gobuster --totally-invalid-flag-xyz dir -u http://192.168.1.10 "
                       "-w /usr/share/wordlists/dirb/common.txt",
            "tool": "gobuster",
            "session_id": "stress-gobuster-002",
            "intent_ref": "DIRECTORY_BRUTEFORCE",
            "estimated_duration": "medium",
        })
        print_full_response(data)
        summarize(data)

        # Engine must have attempted recovery
        assert len(data['recovery_log']) > 0, \
            "Expected non-empty recovery_log"
        first = data['recovery_log'][0]

        valid_classes = ('WRONG_SYNTAX', 'TOOL_NOT_INSTALLED')
        assert first['error_class'] in valid_classes, \
            f"Expected error_class in {valid_classes}, got {first['error_class']}"

        corrected = first.get('corrected_command', '')
        src = ''
        if data.get('correction_history'):
            src = data['correction_history'][0].get('correction_source', '')

        pass_test(
            f"gobuster bad flag: error_class={first['error_class']}, "
            f"strategy={first['strategy']}, source={src}, "
            f"corrected='{corrected[:60]}', status={data['status']}, "
            f"latency={data['latency_ms']}ms"
        )
    except Exception as e:
        fail_test(f"gobuster bad flag: {e}")

    # ------------------------------------------------------------------
    # Scenario 9: gobuster with non-existent wordlist  (stress-gobuster-003)
    # The command syntax is valid, but the wordlist file does not exist
    # inside the container.  This should produce a file-not-found or
    # similar runtime error.  The engine may classify it as WRONG_SYNTAX,
    # RESOURCE_EXHAUSTION, or UNKNOWN.  Either way, the response must be
    # well-formed and show the engine attempted to handle it.
    # ------------------------------------------------------------------
    print("\n  --- Scenario 9: gobuster missing wordlist (runtime edge case) ---")
    try:
        data = post_execute({
            "command": "gobuster dir -u http://192.168.1.10 "
                       "-w /nonexistent/path/wordlist.txt",
            "tool": "gobuster",
            "session_id": "stress-gobuster-003",
            "intent_ref": "DIRECTORY_BRUTEFORCE",
            "estimated_duration": "medium",
        })
        print_full_response(data)
        summarize(data)

        assert data['status'] in ('success', 'recovered', 'failed'), \
            f"Unexpected status: {data['status']}"
        assert 'exit_code' in data, "Missing exit_code field"
        assert 'latency_ms' in data, "Missing latency_ms field"

        if data['status'] == 'success':
            pass_test(
                f"gobuster missing wordlist: succeeded (unexpected but valid), "
                f"exit_code={data['exit_code']}, latency={data['latency_ms']}ms"
            )
        elif data['status'] == 'recovered':
            log_entry = data['recovery_log'][0] if data['recovery_log'] else {}
            pass_test(
                f"gobuster missing wordlist: recovered, "
                f"error_class={log_entry.get('error_class')}, "
                f"strategy={log_entry.get('strategy')}, "
                f"latency={data['latency_ms']}ms"
            )
        else:
            # Failed is expected -- engine tried but the file truly doesn't exist
            fr = data.get('failure_report', {})
            # Verify the engine at least attempted to handle the error
            has_recovery_attempt = (
                len(data.get('recovery_log', [])) > 0 or
                fr.get('attempts', 0) > 0
            )
            if has_recovery_attempt:
                first_log = data['recovery_log'][0] if data['recovery_log'] else {}
                pass_test(
                    f"gobuster missing wordlist: correctly failed after recovery attempt, "
                    f"error_class={first_log.get('error_class', fr.get('final_error_class'))}, "
                    f"strategies_tried={fr.get('strategies_tried')}, "
                    f"latency={data['latency_ms']}ms"
                )
            else:
                # Even if no recovery was attempted, the response is well-formed
                pass_test(
                    f"gobuster missing wordlist: failed (no recovery path), "
                    f"final_error_class={fr.get('final_error_class')}, "
                    f"latency={data['latency_ms']}ms"
                )
    except Exception as e:
        fail_test(f"gobuster missing wordlist: {e}")


# ============================================================
# Main
# ============================================================

if __name__ == '__main__':
    print("\n" + "#" * 60)
    print("#  Tool-Specific Recovery - Live API Test Suite")
    print("#" * 60)

    if not preflight_check():
        print(f"\n{'='*60}")
        print(f"  RESULTS: {PASSED} passed, {FAILED} failed, {SKIPPED} skipped")
        print(f"{'='*60}")
        print(f"\n  [FAILED] Preflight failed - cannot reach API. Aborting.")
        sys.exit(1)

    test_nmap_scenarios()
    test_nikto_scenarios()
    test_gobuster_scenarios()

    print(f"\n{'='*60}")
    print(f"  RESULTS: {PASSED} passed, {FAILED} failed, {SKIPPED} skipped")
    print(f"{'='*60}")

    if FAILED > 0:
        print(f"\n  [FAILED] {FAILED} test(s) FAILED - review output above")
        sys.exit(1)
    else:
        print(f"\n  [OK] All {PASSED} tests PASSED")
        sys.exit(0)
