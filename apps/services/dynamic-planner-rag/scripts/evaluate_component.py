import os
import json
import time
import uuid
import copy
import re
from typing import Any, Dict, List, Tuple

BENCHMARK_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "benchmark_eval.json")

def sanitize_diagnostic_data(data: Any, api_key: str = None) -> Any:
    if isinstance(data, str):
        s = data
        if api_key:
            s = s.replace(api_key, "[REDACTED_API_KEY]")
        s = re.sub(r'(x-api-key|x-admin-key|authorization)\s*[:=]\s*["\']?[^\s\'",]+', r'\1: [REDACTED]', s, flags=re.IGNORECASE)
        return s
    elif isinstance(data, dict):
        return {k: sanitize_diagnostic_data(v, api_key=api_key) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_diagnostic_data(item, api_key=api_key) for item in data]
    return data

def load_benchmark(path: str = BENCHMARK_PATH) -> list:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def run_evaluation(
    benchmark_cases: list = None,
    verbose: bool = True,
    client: Any = None,
    validator: Any = None,
    session_mgr: Any = None,
    headers: dict = None
) -> dict:
    if benchmark_cases is None:
        benchmark_cases = load_benchmark()

    # Lazy import of production components only when injected dependencies are not supplied
    if client is None or headers is None:
        from src.api.main import app, API_KEY
        if client is None:
            from fastapi.testclient import TestClient
            client = TestClient(app)
            if session_mgr is None:
                # Share the API's in-memory fallback when Redis is unavailable.
                from src.api.main import session_mgr as api_session_mgr
                session_mgr = api_session_mgr
        if headers is None:
            headers = {"x-api-key": API_KEY}

    if session_mgr is None:
        from src.session.session_context_manager import SessionContextManager
        session_mgr = SessionContextManager()

    if validator is None:
        from scripts.cli_ast_validator import CLIASTValidator
        validator = CLIASTValidator()

    run_uuid = uuid.uuid4().hex[:8]
    total_cases = len(benchmark_cases)

    cmd_gen_cases = []
    rejection_cases = []
    recovery_cases = []
    excluded_cases = []

    for case in benchmark_cases:
        if case.get("excluded", False):
            excluded_cases.append(case)
        elif case.get("category") == "session_recovery" or case.get("id") == "BENCH-024":
            recovery_cases.append(case)
        elif not case.get("expect_success", True):
            rejection_cases.append(case)
        else:
            cmd_gen_cases.append(case)

    # Category-specific counters
    gen_total = len(cmd_gen_cases)
    gen_tool_correct = 0
    gen_target_preserved = 0
    gen_ports_preserved = 0
    gen_options_valid = 0
    gen_syntax_valid = 0
    gen_safety_valid = 0
    gen_semantics_valid = 0
    gen_exact_match = 0
    gen_transport_exceptions = 0
    gen_infra_failures = 0

    rej_total = len(rejection_cases)
    rej_status_correct = 0
    rej_safety_valid = 0
    rej_transport_exceptions = 0
    rej_infra_failures = 0

    rec_total = len(recovery_cases)
    rec_success = 0
    rec_transport_exceptions = 0
    rec_infra_failures = 0

    latencies = []
    per_case_results = []

    if verbose:
        print(f"\n=======================================================")
        print(f" NeuroShell C2 Evaluation Pipeline Benchmark (Run: {run_uuid})")
        print(f" (Generation: {gen_total}, Rejection: {rej_total}, Recovery: {rec_total}, Excluded: {len(excluded_cases)})")
        print(f"=======================================================\n")

    # 1. Process Command Generation Cases
    for case in cmd_gen_cases:
        cid = case["id"]
        cname = case["name"]
        provenance = case.get("provenance", {})
        prov_type = provenance.get("type", "unknown")
        rec_id = provenance.get("record_id", "N/A")

        req_body = copy.deepcopy(case["body"])
        sess_id = f"{req_body.get('session_id', 'bench-sess')}-{run_uuid}"
        req_body["session_id"] = sess_id

        eval_details = []
        t0 = time.time()
        try:
            try:
                resp = client.post("/plan", json=req_body, headers=headers)
                lat_ms = int((time.time() - t0) * 1000)
                latencies.append(lat_ms)
                status_code = resp.status_code
                try:
                    response_data = resp.json()
                except Exception:
                    response_data = {"status": "error", "detail": resp.text}
            except Exception as e:
                gen_transport_exceptions += 1
                lat_ms = int((time.time() - t0) * 1000)
                latencies.append(lat_ms)
                status_code = 500
                response_data = {"status": "error", "detail": f"Transport exception: {e}"}

            cmd = response_data.get("command", "") if isinstance(response_data, dict) else ""
            eval_res = validator.evaluate(cmd, case, response_data, status_code=status_code)
            eval_details.extend(eval_res["details"])

            if eval_res["tool_correct"]: gen_tool_correct += 1
            if eval_res["target_preserved"]: gen_target_preserved += 1
            if eval_res["ports_preserved"]: gen_ports_preserved += 1
            if eval_res["options_valid"]: gen_options_valid += 1
            if eval_res["syntax_valid"]: gen_syntax_valid += 1
            if eval_res["safety_valid"]: gen_safety_valid += 1
            if eval_res["semantically_correct"]: gen_semantics_valid += 1
            if eval_res["exact_match"]: gen_exact_match += 1

            per_case_results.append({
                "id": cid,
                "name": cname,
                "category": "command_generation",
                "session_id": sess_id,
                "status_code": status_code,
                "latency_ms": lat_ms,
                "semantically_correct": eval_res["semantically_correct"],
                "generated_command": cmd,
                "check_outcomes": eval_res,
                "details": sanitize_diagnostic_data(eval_details)
            })

            if verbose:
                status_symbol = "[PASS]" if eval_res["semantically_correct"] else "[FAIL]"
                print(f"{status_symbol} {cid} [{prov_type}:{rec_id}] {cname}")
                print(f"       Generated: {cmd}")
                if eval_details:
                    print(f"       Issues: {sanitize_diagnostic_data(eval_details)}")
        finally:
            try:
                session_mgr.clear_session(sess_id)
            except Exception as cleanup_err:
                gen_infra_failures += 1
                eval_details.append(f"Session cleanup failure: {cleanup_err}")

    # 2. Process Expected Rejection Cases
    for case in rejection_cases:
        cid = case["id"]
        cname = case["name"]
        provenance = case.get("provenance", {})
        prov_type = provenance.get("type", "unknown")
        rec_id = provenance.get("record_id", "N/A")

        req_body = copy.deepcopy(case["body"])
        sess_id = f"{req_body.get('session_id', 'bench-sess')}-{run_uuid}"
        req_body["session_id"] = sess_id

        eval_details = []
        t0 = time.time()
        try:
            try:
                resp = client.post("/plan", json=req_body, headers=headers)
                lat_ms = int((time.time() - t0) * 1000)
                latencies.append(lat_ms)
                status_code = resp.status_code
                try:
                    response_data = resp.json()
                except Exception:
                    response_data = {"status": "error", "detail": resp.text}
            except Exception as e:
                rej_transport_exceptions += 1
                lat_ms = int((time.time() - t0) * 1000)
                latencies.append(lat_ms)
                status_code = 500
                response_data = {"status": "error", "detail": f"Transport exception: {e}"}

            cmd = response_data.get("command", "") if isinstance(response_data, dict) else ""
            eval_res = validator.evaluate(cmd, case, response_data, status_code=status_code)
            eval_details.extend(eval_res["details"])

            if eval_res["status_code_correct"]: rej_status_correct += 1
            if eval_res["safety_valid"]: rej_safety_valid += 1

            per_case_results.append({
                "id": cid,
                "name": cname,
                "category": "expected_rejection",
                "session_id": sess_id,
                "status_code": status_code,
                "latency_ms": lat_ms,
                "semantically_correct": eval_res["semantically_correct"],
                "sanitized_response": sanitize_diagnostic_data(str(response_data.get("detail", response_data))),
                "check_outcomes": eval_res,
                "details": sanitize_diagnostic_data(eval_details)
            })

            if verbose:
                status_symbol = "[PASS]" if eval_res["semantically_correct"] else "[FAIL]"
                print(f"{status_symbol} {cid} [{prov_type}:{rec_id}] {cname}")
                print(f"       Blocked Response (HTTP {status_code}): {sanitize_diagnostic_data(response_data.get('detail') or response_data)}")
                if eval_details:
                    print(f"       Issues: {sanitize_diagnostic_data(eval_details)}")
        finally:
            try:
                session_mgr.clear_session(sess_id)
            except Exception as cleanup_err:
                rej_infra_failures += 1
                eval_details.append(f"Session cleanup failure: {cleanup_err}")

    # 3. Process Session Recovery Cases (BENCH-024)
    for case in recovery_cases:
        cid = case["id"]
        cname = case["name"]
        provenance = case.get("provenance", {})
        prov_type = provenance.get("type", "unknown")
        rec_id = provenance.get("record_id", "N/A")

        req_body = copy.deepcopy(case["body"])
        base_sess = req_body.get("session_id", "bench-sess-rec-024")
        sess_id = f"{base_sess}-{run_uuid}"
        req_body["session_id"] = sess_id

        expected_recovered_target = case.get("expected_semantics", {}).get("target_value") or "192.168.1.50"
        eval_details = []
        setup_ok = False

        try:
            try:
                session_mgr.update_session(sess_id, f"nmap -sS {expected_recovered_target}", "nmap", expected_recovered_target)
                stored_target = session_mgr.get_last_target(sess_id)
                if stored_target == expected_recovered_target:
                    setup_ok = True
                else:
                    rec_infra_failures += 1
                    eval_details.append(f"Session recovery setup target mismatch: expected {expected_recovered_target}, got {stored_target}")
            except Exception as setup_err:
                rec_infra_failures += 1
                eval_details.append(f"Infrastructure setup error for session recovery: {setup_err}")

            if not setup_ok:
                per_case_results.append({
                    "id": cid,
                    "name": cname,
                    "category": "session_recovery",
                    "session_id": sess_id,
                    "semantically_correct": False,
                    "details": sanitize_diagnostic_data(eval_details)
                })
                continue

            t0 = time.time()
            try:
                resp = client.post("/plan", json=req_body, headers=headers)
                lat_ms = int((time.time() - t0) * 1000)
                latencies.append(lat_ms)
                status_code = resp.status_code
                try:
                    response_data = resp.json()
                except Exception:
                    response_data = {"status": "error", "detail": resp.text}
            except Exception as e:
                rec_transport_exceptions += 1
                lat_ms = int((time.time() - t0) * 1000)
                latencies.append(lat_ms)
                status_code = 500
                response_data = {"status": "error", "detail": f"Transport exception: {e}"}

            cmd = response_data.get("command", "") if isinstance(response_data, dict) else ""
            eval_res = validator.evaluate(cmd, case, response_data, status_code=status_code)
            eval_details.extend(eval_res["details"])

            if eval_res["semantically_correct"]:
                rec_success += 1

            per_case_results.append({
                "id": cid,
                "name": cname,
                "category": "session_recovery",
                "session_id": sess_id,
                "status_code": status_code,
                "latency_ms": lat_ms,
                "semantically_correct": eval_res["semantically_correct"],
                "generated_command": cmd,
                "check_outcomes": eval_res,
                "details": sanitize_diagnostic_data(eval_details)
            })

            if verbose:
                status_symbol = "[PASS]" if eval_res["semantically_correct"] else "[FAIL]"
                print(f"{status_symbol} {cid} [{prov_type}:{rec_id}] {cname}")
                print(f"       Recovered Command: {cmd}")
                if eval_details:
                    print(f"       Issues: {sanitize_diagnostic_data(eval_details)}")

        finally:
            try:
                session_mgr.clear_session(sess_id)
            except Exception as cleanup_err:
                rec_infra_failures += 1
                eval_details.append(f"Session cleanup failure: {cleanup_err}")

    # 4. Process Excluded / Unresolved Cases
    for case in excluded_cases:
        cid = case["id"]
        cname = case["name"]
        reason = case.get("exclusion_reason", "Unresolved case")
        per_case_results.append({
            "id": cid,
            "name": cname,
            "category": "excluded",
            "excluded": True,
            "reason": reason
        })
        if verbose:
            print(f"[EXCLUDED] {cid} {cname}")
            print(f"           Reason: {reason}")

    # Helper function to compute honest metric dicts
    def make_metric(numerator: int, denominator: int, exclusions: int = len(excluded_cases), infra_failures: int = 0) -> dict:
        if denominator == 0:
            return {
                "numerator": numerator,
                "denominator": 0,
                "percentage_pct": "N/A",
                "exclusions": exclusions,
                "infrastructure_failures": infra_failures
            }
        pct = round((numerator / denominator) * 100, 2)
        return {
            "numerator": numerator,
            "denominator": denominator,
            "percentage_pct": pct,
            "exclusions": exclusions,
            "infrastructure_failures": infra_failures
        }

    avg_latency = sum(latencies) / len(latencies) if latencies else 0.0

    total_transport_exceptions = gen_transport_exceptions + rej_transport_exceptions + rec_transport_exceptions
    total_infra_failures = gen_infra_failures + rej_infra_failures + rec_infra_failures

    metrics = {
        "legacy_baseline": {
            "preliminary_score_pct": 68.0,
            "notes": "Uncorrected legacy score using non-rigorous substring matching. Not directly comparable."
        },
        "domain_policy_mismatches": [
            {
                "id": "BENCH-018",
                "notes": "BENCH-018 expects success for domain target0.local, but production SafetyFilter strictly requires RFC-1918 IPv4 ranges and returns HTTP 400."
            }
        ],
        "benchmark_summary": {
            "run_uuid": run_uuid,
            "total_cases": total_cases,
            "command_generation_cases": gen_total,
            "expected_rejection_cases": rej_total,
            "session_recovery_cases": rec_total,
            "excluded_cases": len(excluded_cases),
            "transport_exceptions": total_transport_exceptions,
            "infrastructure_failures": total_infra_failures,
            "avg_planning_latency_ms": round(avg_latency, 2)
        },
        "category_failure_counts": {
            "command_generation": {"transport_exceptions": gen_transport_exceptions, "infrastructure_failures": gen_infra_failures},
            "expected_rejection": {"transport_exceptions": rej_transport_exceptions, "infrastructure_failures": rej_infra_failures},
            "session_recovery": {"transport_exceptions": rec_transport_exceptions, "infrastructure_failures": rec_infra_failures}
        },
        "command_generation_metrics": {
            "tool_selection_accuracy": make_metric(gen_tool_correct, gen_total, infra_failures=gen_infra_failures),
            "target_preservation_accuracy": make_metric(gen_target_preserved, gen_total, infra_failures=gen_infra_failures),
            "port_argument_accuracy": make_metric(gen_ports_preserved, gen_total, infra_failures=gen_infra_failures),
            "option_value_accuracy": make_metric(gen_options_valid, gen_total, infra_failures=gen_infra_failures),
            "command_structural_validity": make_metric(gen_syntax_valid, gen_total, infra_failures=gen_infra_failures),
            "safety_compliance": make_metric(gen_safety_valid, gen_total, infra_failures=gen_infra_failures),
            "semantic_command_accuracy": make_metric(gen_semantics_valid, gen_total, infra_failures=gen_infra_failures),
            "exact_normalized_match_secondary": make_metric(gen_exact_match, gen_total, infra_failures=gen_infra_failures)
        },
        "expected_rejection_metrics": {
            "status_code_correctness": make_metric(rej_status_correct, rej_total, infra_failures=rej_infra_failures),
            "safety_guard_compliance": make_metric(rej_safety_valid, rej_total, infra_failures=rej_infra_failures)
        },
        "session_recovery_metrics": {
            "target_recovery_accuracy": make_metric(rec_success, rec_total, infra_failures=rec_infra_failures)
        },
        "per_case_results": per_case_results
    }

    if verbose:
        print("\n-------------------------------------------------------")
        print(" Quantitative Evaluation Summary (Defensible Metrics)")
        print("-------------------------------------------------------")
        print(f" Legacy Baseline Score (Preliminary) : {metrics['legacy_baseline']['preliminary_score_pct']}%")
        print(f" Total Benchmark Cases             : {total_cases} (Exclusions: {len(excluded_cases)})")
        print(f" Transport Exceptions / Infra Fail : {total_transport_exceptions} / {total_infra_failures}")
        print(f" Command Generation Accuracy       : {metrics['command_generation_metrics']['semantic_command_accuracy']['percentage_pct']}% ({gen_semantics_valid}/{gen_total})")
        print(f"   - Tool Selection Accuracy       : {metrics['command_generation_metrics']['tool_selection_accuracy']['percentage_pct']}% ({gen_tool_correct}/{gen_total})")
        print(f"   - Target Preservation Accuracy  : {metrics['command_generation_metrics']['target_preservation_accuracy']['percentage_pct']}% ({gen_target_preserved}/{gen_total})")
        print(f"   - Port Argument Accuracy        : {metrics['command_generation_metrics']['port_argument_accuracy']['percentage_pct']}% ({gen_ports_preserved}/{gen_total})")
        print(f"   - Option Value Accuracy         : {metrics['command_generation_metrics']['option_value_accuracy']['percentage_pct']}% ({gen_options_valid}/{gen_total})")
        print(f"   - Structural Validity           : {metrics['command_generation_metrics']['command_structural_validity']['percentage_pct']}% ({gen_syntax_valid}/{gen_total})")
        print(f"   - Safety Compliance             : {metrics['command_generation_metrics']['safety_compliance']['percentage_pct']}% ({gen_safety_valid}/{gen_total})")
        print(f" Expected Rejection Safety Rate    : {metrics['expected_rejection_metrics']['safety_guard_compliance']['percentage_pct']}% ({rej_safety_valid}/{rej_total})")
        print(f" Session Target Recovery Accuracy  : {metrics['session_recovery_metrics']['target_recovery_accuracy']['percentage_pct']}% ({rec_success}/{rec_total})")
        print(f" Avg Planning Latency              : {metrics['benchmark_summary']['avg_planning_latency_ms']} ms")
        print("=======================================================\n")

    return metrics

if __name__ == "__main__":
    run_evaluation()