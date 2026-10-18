import json
import os
import sys
import time
import shlex
import ollama
from typing import List, Dict, Tuple, Optional, Set

# Ensure project root is in python path
sys.path.insert(0, os.path.abspath("."))

from src.schemas.models import IREIntentContract
from src.intent.intent_interpreter import IntentInterpreter
from src.intent.query_constructor import QueryConstructor
from src.rag.vector_retriever import VectorRetriever
from src.rag.context_assembler import ContextAssembler
from src.synthesis.command_synthesizer import CommandSynthesizer
from src.validation.command_validator import CommandValidator
from src.validation.safety_filter import SafetyFilter

EXPECTED_BASE_NAME = "neuroshell-c2-gemma2-final"
ACTIVE_MODEL = os.getenv("OLLAMA_MODEL", EXPECTED_BASE_NAME)

SYSTEM_PROMPT = (
    "You are NeuroShell Component 2, a Dynamic Planner for authorized cybersecurity tasks. "
    "Output ONLY valid executable commands. Do not explain."
)

GENERATION_OPTIONS = {
    "temperature": 0,
    "num_predict": 96
}

OUTPUT_DIAGNOSTIC_JSON = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "prompt_hypothesis_diagnostic_results.json"
)


def verify_active_model() -> str:
    """Strictly requires ACTIVE_MODEL to equal neuroshell-c2-gemma2-final (or :latest),
    and verifies its presence in Ollama installed models.
    """
    valid_exact_names = {EXPECTED_BASE_NAME, f"{EXPECTED_BASE_NAME}:latest"}
    if ACTIVE_MODEL not in valid_exact_names:
        raise ValueError(
            f"ACTIVE_MODEL configuration error: must strictly equal '{EXPECTED_BASE_NAME}' "
            f"or '{EXPECTED_BASE_NAME}:latest'. Currently configured: '{ACTIVE_MODEL}'"
        )

    models_info = ollama.list()
    installed = [
        m.get("name", m.get("model", "")) for m in models_info.get("models", [])
    ]
    matching = [m for m in installed if m in valid_exact_names or m.startswith(f"{EXPECTED_BASE_NAME}:")]
    if not matching:
        raise RuntimeError(
            f"Model '{ACTIVE_MODEL}' is not installed in local Ollama instance. Available: {installed}"
        )
    print(f"[MODEL VERIFIED] ACTIVE_MODEL: '{ACTIVE_MODEL}' (Confirmed installed: {matching})")
    return ACTIVE_MODEL


def check_wordlist_tokens(tokens: List[str], expected_wordlist: str = "common.txt") -> Tuple[bool, str]:
    """Checks for exactly one -w/--wordlist argument with expected value using parsed tokens."""
    wordlist_vals = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in ["-w", "--wordlist"]:
            if i + 1 < len(tokens):
                wordlist_vals.append(tokens[i + 1])
                i += 2
                continue
            else:
                return False, "Option -w/--wordlist is missing an argument"
        elif tok.startswith("-w=") or tok.startswith("--wordlist="):
            val = tok.split("=", 1)[1]
            wordlist_vals.append(val)
        i += 1

    if len(wordlist_vals) == 0:
        return False, "Missing -w/--wordlist flag"
    if len(wordlist_vals) > 1:
        return False, f"Multiple wordlist flags found ({len(wordlist_vals)}): {wordlist_vals}"
    if wordlist_vals[0] != expected_wordlist:
        return False, f"Wordlist value '{wordlist_vals[0]}' does not match expected '{expected_wordlist}'"
    return True, f"Exactly one wordlist argument verified: {wordlist_vals[0]}"


def check_unrequested_options(tokens: List[str], requested_modifiers: List[str]) -> Tuple[bool, List[str]]:
    """Checks whether the command contains unrequested options copied from documentation examples,
    specifically -m/--method, -x/--extensions, -k, or other flags not present in requested modifiers.
    """
    known_flags_with_args = {
        "-u", "--url", "-w", "--wordlist", "-x", "--extensions",
        "-t", "--threads", "-m", "-o", "--output", "-b", "-s",
        "-a", "-H", "-c", "-U", "-P", "-d", "--domain", "-r"
    }

    unrequested = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in ["gobuster", "dir", "dns", "vhost", "fuzz"]:
            i += 1
            continue

        if tok in ["-u", "--url"]:
            i += 2
            continue

        if tok in ["-w", "--wordlist"]:
            i += 2
            continue

        # Any other flag
        if tok.startswith("-"):
            is_requested = any(tok in mod for mod in requested_modifiers)
            flag_str = tok
            if tok in known_flags_with_args and i + 1 < len(tokens) and not tokens[i + 1].startswith("-"):
                flag_str = f"{tok} {tokens[i + 1]}"
                i += 2
            else:
                i += 1

            if not is_requested:
                unrequested.append(flag_str)
        else:
            i += 1

    is_clean = len(unrequested) == 0
    return is_clean, unrequested


def build_revised_prompt(
    header: str,
    doc_blocks: List[str],
    json_payload: str,
    target_value: str,
    wordlist: str = None,
    modifiers: List[str] = None,
    multi_step: bool = False
) -> str:
    """Builds revised prompt keeping target/mode rules, requiring only gobuster dir -u <URL> -w <wordlist>
    when no extra modifiers are requested, while preserving requested modifiers when provided.
    """
    rules = [
        "RULES:",
        "1. Output ONLY the executable command — no markdown code fences, no explanations.",
        "2. For DIRECTORY_BRUTEFORCE directory enumeration, you MUST use 'gobuster dir' mode with the '-u' flag.",
        f"3. Use the exact target URL and port from Planner input ({target_value}) with the '-u' flag. Replace any example or placeholder IPs or URLs with this exact target.",
    ]
    if wordlist:
        rules.append(f"4. Use the exact wordlist specified ({wordlist}) with the '-w' flag. Output exactly one '-w' flag.")

    # Filter extra modifiers beyond wordlist
    extra_modifiers = [
        m for m in (modifiers or [])
        if not m.startswith("-w") and not m.startswith("--wordlist")
    ]

    if not extra_modifiers:
        # Diagnostic cases with only target and wordlist requested
        rules.append(
            f"5. Because no additional modifiers were requested, the command must contain ONLY 'gobuster dir -u {target_value} -w {wordlist}' with NO additional flags or options (do NOT include -k, -m, -x, -t, or any other option)."
        )
    else:
        # Requests containing modifiers: preserve requested modifiers
        mod_str = " ".join(extra_modifiers)
        rules.append(
            f"5. Include the requested modifiers ({mod_str}). Do NOT add any unrequested flags or options from the documentation examples."
        )

    rules_block = "\n".join(rules)
    docs_block = "\n\n".join(doc_blocks) if doc_blocks else ""

    sections = [header]
    if docs_block:
        sections.append(docs_block)
    sections.append(rules_block)
    sections.append(f"Planner input:\n{json_payload}")
    sections.append("COMMAND SEQUENCE:" if multi_step else "COMMAND:")

    return "\n\n".join(sections)


def run_ollama_synthesis(prompt: str, model_name: str) -> str:
    """Invokes Ollama using identical system prompt and generation options as production CommandSynthesizer."""
    try:
        response = ollama.chat(
            model=model_name,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ],
            options=GENERATION_OPTIONS
        )
        return response["message"]["content"].strip()
    except Exception as e:
        return f"ERROR: Ollama invocation failed: {e}"


def evaluate_generated_output(
    cmd_str: str,
    target_value: str,
    expected_ports: List[int],
    expected_wordlist: str,
    requested_modifiers: List[str],
    validator: CommandValidator,
    safety_filter: SafetyFilter
) -> Dict:
    """Evaluates generated command across separate mode, target, port, wordlist, unrequested-options,
    safety, and validator checks.
    """
    if not cmd_str or cmd_str.startswith("ERROR:"):
        return {
            "parsed_command": cmd_str,
            "mode_correct": False,
            "target_preserved": False,
            "ports_preserved": False,
            "wordlist_valid": False,
            "unrequested_options_clean": False,
            "unrequested_options": [],
            "safety_passed": False,
            "validator_passed": False,
            "overall_success": False,
            "issues": [cmd_str or "Empty command output"],
            "safety_flags": []
        }

    try:
        tokens = shlex.split(cmd_str)
    except Exception as e:
        return {
            "parsed_command": cmd_str,
            "mode_correct": False,
            "target_preserved": False,
            "ports_preserved": False,
            "wordlist_valid": False,
            "unrequested_options_clean": False,
            "unrequested_options": [],
            "safety_passed": False,
            "validator_passed": False,
            "overall_success": False,
            "issues": [f"shlex tokenization error: {e}"],
            "safety_flags": []
        }

    # 1. Mode check: executable binary is 'gobuster' and subcommand is 'dir'
    tool_binary = tokens[0] if len(tokens) > 0 else ""
    subcommand = tokens[1] if len(tokens) > 1 else ""
    mode_ok = (tool_binary == "gobuster" and subcommand == "dir")

    # 2. Target preservation via AST validator
    target_ok = validator.ast_validator._check_target_position(
        tokens=tokens,
        target_value=target_value,
        target_type="URL",
        tool="gobuster",
        gobuster_mode=subcommand
    )

    # 3. Port preservation via AST validator
    port_ok = validator.ast_validator._check_ports_preservation(
        tokens=tokens,
        expected_ports=expected_ports,
        tool="gobuster",
        cmd=cmd_str
    )

    # 4. Wordlist flag & value check
    wl_ok, wl_msg = check_wordlist_tokens(tokens, expected_wordlist)

    # 5. Unrequested options check (e.g. -m POST, -x php, -k)
    clean_options, unrequested_list = check_unrequested_options(tokens, requested_modifiers)

    # 6. Safety filter
    safe, s_flags = safety_filter.validate(cmd_str, target=target_value)

    # 7. Full CommandValidator
    valid, v_issues = validator.validate(
        cmd_str,
        expected_tool="gobuster",
        target_value=target_value,
        target_type="URL",
        expected_ports=expected_ports
    )

    # Overall success requires all individual checks to pass
    overall = bool(mode_ok and target_ok and port_ok and wl_ok and clean_options and safe and valid)

    all_issues = list(v_issues)
    if not mode_ok:
        all_issues.append(f"Subcommand mode mismatch: expected 'gobuster dir', got '{tool_binary} {subcommand}'")
    if not target_ok and not any("target" in iss.lower() for iss in all_issues):
        all_issues.append(f"Target '{target_value}' missing or misplaced")
    if not port_ok and not any("port" in iss.lower() for iss in all_issues):
        all_issues.append(f"Port {expected_ports} missing or mismatched")
    if not wl_ok:
        all_issues.append(wl_msg)
    if not clean_options:
        all_issues.append(f"Unrequested options copied from examples: {unrequested_list}")

    return {
        "parsed_command": cmd_str,
        "mode_correct": mode_ok,
        "target_preserved": target_ok,
        "ports_preserved": port_ok,
        "wordlist_valid": wl_ok,
        "unrequested_options_clean": clean_options,
        "unrequested_options": unrequested_list,
        "safety_passed": safe,
        "validator_passed": valid,
        "overall_success": overall,
        "issues": all_issues,
        "safety_flags": s_flags
    }


def run_diagnostic():
    print("=" * 80)
    print("GOBUSTER TARGET & MINIMAL OPTION PRESERVATION DIAGNOSTIC")
    print("=" * 80)

    model_name = verify_active_model()
    print(f"[CONFIGURATION] SYSTEM_PROMPT:\n  {SYSTEM_PROMPT}")
    print(f"[CONFIGURATION] GENERATION_OPTIONS: {GENERATION_OPTIONS}")

    interpreter = IntentInterpreter()
    constructor = QueryConstructor()
    retriever = VectorRetriever()
    assembler = ContextAssembler()
    synthesizer = CommandSynthesizer()
    validator = CommandValidator()
    safety_filter = SafetyFilter()

    # Load previous runs history if file exists to retain previous results
    existing_history = []
    if os.path.exists(OUTPUT_DIAGNOSTIC_JSON):
        try:
            with open(OUTPUT_DIAGNOSTIC_JSON, "r", encoding="utf-8") as f:
                prev_data = json.load(f)
                if isinstance(prev_data, dict):
                    if "history" in prev_data:
                        existing_history = prev_data["history"]
                    else:
                        existing_history.append({
                            "timestamp": prev_data.get("timestamp", "unknown"),
                            "results": prev_data.get("results", [])
                        })
        except Exception as e:
            print(f"Note: Could not parse previous diagnostic file: {e}")

    # Private targets to test with port specifications
    test_cases = [
        {"target": "http://192.168.1.50", "ports": [80], "desc": "Original failing case (.50)"},
        {"target": "http://10.0.0.15", "ports": [80], "desc": "Class A 10.x private target"},
        {"target": "http://172.16.0.25", "ports": [80], "desc": "Class B 172.16.x private target"},
        {"target": "http://192.168.1.1", "ports": [80], "desc": "Gateway 192.168.1.1 private target"},
        {"target": "http://192.168.10.88:8080", "ports": [8080], "desc": "Custom port :8080 private target"},
    ]

    wordlist = "common.txt"
    all_results = []

    for idx, tc in enumerate(test_cases, 1):
        target = tc["target"]
        ports = tc["ports"]
        desc = tc["desc"]

        print(f"\n[{idx}/{len(test_cases)}] CASE: {desc}")
        print(f"Target: {target} | Ports: {ports} | Wordlist: {wordlist}")
        print("-" * 75)

        try:
            contract = IREIntentContract(
                intent="DIRECTORY_BRUTEFORCE",
                target_value=target,
                target_type="URL",
                ports=ports,
                primary_tool="gobuster",
                tool_parameters={"wordlist": wordlist}
            )

            params = interpreter.interpret(contract)
            query = constructor.build_query(params)
            docs = retriever.retrieve(query, tool_hint=params.get("tool_hint"), top_k=3)

            # ── BASELINE PROMPT ──
            baseline_prompt = assembler.assemble(docs, params)

            # ── REVISED PROMPT (v2 with minimal-options rule) ──
            target_val = params.get("target_value") or target
            planner_input = {
                "intent": params.get("intent", ""),
                "sub_intent": params.get("sub_intent", "directory_enumeration"),
                "target": {"type": "URL", "value": target_val},
                "ports": params.get("ports", ports),
                "modifiers": params.get("modifiers", []),
                "tool_hint": "gobuster"
            }
            json_payload = json.dumps(planner_input, ensure_ascii=False, sort_keys=True)

            header = (
                "You are NeuroShell Component 2, a Dynamic Planner for authorized cybersecurity tasks.\n"
                "Generate exactly one valid shell command using the requested tool.\n"
                "Return only the command. Do not explain it."
            )

            doc_blocks = []
            if docs:
                tool_sections = {}
                for doc in docs:
                    t = doc.get("tool", "unknown")
                    tool_sections.setdefault(t, []).append(doc.get("content", ""))
                context_parts = []
                for t, contents in tool_sections.items():
                    context_parts.append(f"=== {t.upper()} DOCUMENTATION ===")
                    for c in contents:
                        context_parts.append(c)
                doc_blocks.append("TOOL DOCUMENTATION:\n" + "\n\n".join(context_parts))

            revised_prompt = build_revised_prompt(
                header=header,
                doc_blocks=doc_blocks,
                json_payload=json_payload,
                target_value=target_val,
                wordlist=wordlist,
                modifiers=params.get("modifiers", []),
                multi_step=False
            )

            # ── RUN BASELINE SYNTHESIS ──
            t0 = time.time()
            raw_base = run_ollama_synthesis(baseline_prompt, model_name)
            dt_base = (time.time() - t0) * 1000
            parsed_base_list = synthesizer.parse_command_output(raw_base, multi_step=False)
            parsed_base = parsed_base_list[0] if parsed_base_list else ""
            base_eval = evaluate_generated_output(
                parsed_base, target_val, ports, wordlist, params.get("modifiers", []), validator, safety_filter
            )
            base_eval["raw_output"] = raw_base
            base_eval["latency_ms"] = round(dt_base, 1)
            base_eval["prompt"] = baseline_prompt

            # ── RUN REVISED SYNTHESIS (v2) ──
            t1 = time.time()
            raw_rev = run_ollama_synthesis(revised_prompt, model_name)
            dt_rev = (time.time() - t1) * 1000
            parsed_rev_list = synthesizer.parse_command_output(raw_rev, multi_step=False)
            parsed_rev = parsed_rev_list[0] if parsed_rev_list else ""
            rev_eval = evaluate_generated_output(
                parsed_rev, target_val, ports, wordlist, params.get("modifiers", []), validator, safety_filter
            )
            rev_eval["raw_output"] = raw_rev
            rev_eval["latency_ms"] = round(dt_rev, 1)
            rev_eval["prompt"] = revised_prompt

            # Report individual case findings
            print(f"  [BASELINE] Raw: {raw_base}")
            print(f"             Mode OK: {base_eval['mode_correct']} | Target OK: {base_eval['target_preserved']} | Ports OK: {base_eval['ports_preserved']} | Wordlist OK: {base_eval['wordlist_valid']} | Clean: {base_eval['unrequested_options_clean']}")
            print(f"             Unrequested: {base_eval['unrequested_options']}")
            print(f"             OVERALL SUCCESS: {base_eval['overall_success']}")
            if base_eval["issues"]:
                print(f"             Issues: {base_eval['issues']}")

            print(f"  [REVISED]  Raw: {raw_rev}")
            print(f"             Mode OK: {rev_eval['mode_correct']} | Target OK: {rev_eval['target_preserved']} | Ports OK: {rev_eval['ports_preserved']} | Wordlist OK: {rev_eval['wordlist_valid']} | Clean: {rev_eval['unrequested_options_clean']}")
            print(f"             Unrequested: {rev_eval['unrequested_options']}")
            print(f"             OVERALL SUCCESS: {rev_eval['overall_success']}")
            if rev_eval["issues"]:
                print(f"             Issues: {rev_eval['issues']}")

            all_results.append({
                "target": target,
                "ports": ports,
                "desc": desc,
                "baseline": base_eval,
                "revised": rev_eval
            })

        except Exception as e:
            print(f"  ERROR executing test case for {target}: {e}")
            all_results.append({
                "target": target,
                "ports": ports,
                "desc": desc,
                "error": str(e)
            })

    # Save complete results with history retained in JSON file
    os.makedirs(os.path.dirname(OUTPUT_DIAGNOSTIC_JSON), exist_ok=True)
    existing_history.append({
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "description": "Revised prompt with minimal options rule for un-modified Gobuster requests",
        "results": all_results
    })

    with open(OUTPUT_DIAGNOSTIC_JSON, "w", encoding="utf-8") as f:
        json.dump(
            {
                "model": model_name,
                "system_prompt": SYSTEM_PROMPT,
                "generation_options": GENERATION_OPTIONS,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "current_run_results": all_results,
                "history": existing_history
            },
            f,
            indent=2
        )
    print(f"\n[EVIDENCE RETAINED] Detailed diagnostic results (with history) saved to: {OUTPUT_DIAGNOSTIC_JSON}")

    # Summary table
    print("\n" + "=" * 115)
    print(f"{'TARGET':<28} | {'PORTS':<7} | {'BASELINE (MODE/TGT/PRT/WL/CLN)':<32} | {'REVISED (MODE/TGT/PRT/WL/CLN)':<32} | {'REV OVERALL':<11}")
    print("-" * 115)
    for r in all_results:
        if "error" in r:
            print(f"{r['target']:<28} | {str(r['ports']):<7} | ERROR: {r['error']}")
        else:
            b = r["baseline"]
            rv = r["revised"]
            b_summary = f"{'Y' if b['mode_correct'] else 'N'}/{'Y' if b['target_preserved'] else 'N'}/{'Y' if b['ports_preserved'] else 'N'}/{'Y' if b['wordlist_valid'] else 'N'}/{'Y' if b['unrequested_options_clean'] else 'N'}"
            rv_summary = f"{'Y' if rv['mode_correct'] else 'N'}/{'Y' if rv['target_preserved'] else 'N'}/{'Y' if rv['ports_preserved'] else 'N'}/{'Y' if rv['wordlist_valid'] else 'N'}/{'Y' if rv['unrequested_options_clean'] else 'N'}"
            rv_status = "PASS" if rv["overall_success"] else "FAIL"
            print(f"{r['target']:<28} | {str(r['ports']):<7} | {b_summary:<32} | {rv_summary:<32} | {rv_status:<11}")
    print("=" * 115)

    return all_results


if __name__ == "__main__":
    run_diagnostic()
