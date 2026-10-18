"""
Post-Training Verification Script for NeuroShell C2 Gemma-2 LoRA Model.

Evaluates the tuned model (or base model fallback) on:
1. One known training sample (df_train.iloc[0] -> C2SFT-0001)
2. One held-out test sample (df_test.iloc[0] -> C2SFT-0002)

Reports:
- Expected command vs Generated command
- Normalized exact match
- Expected tool vs Generated tool
- Tool correctness
- CommandValidator pass/fail & issues
- SafetyFilter pass/fail & flags
- Inference latency (ms)
"""

import os
import sys
import time
import json
import re
import pandas as pd
import ollama
from dotenv import load_dotenv

# Ensure project root is in python path
sys.path.insert(0, os.path.abspath("."))

from src.synthesis.command_synthesizer import CommandSynthesizer
from src.validation.command_validator import CommandValidator
from src.validation.safety_filter import SafetyFilter

load_dotenv()

TARGET_MODEL = os.getenv("EVAL_OLLAMA_MODEL", "neuroshell-c2-gemma2:latest")


def normalize_cmd(cmd: str) -> str:
    """Normalizes command string by stripping outer whitespace and extra spaces."""
    if not isinstance(cmd, str):
        return ""
    return re.sub(r"\s+", " ", cmd).strip()


def extract_primary_tool(cmd: str) -> str:
    """Extracts primary executable tool from command."""
    tokens = cmd.strip().split()
    if not tokens:
        return ""
    first = tokens[0].lower()
    if first == "sudo" and len(tokens) > 1:
        first = tokens[1].lower()
    return os.path.basename(first)


def evaluate_sample(sample_row: pd.Series, sample_type: str, synthesizer: CommandSynthesizer, validator: CommandValidator, safety_filter: SafetyFilter) -> dict:
    """Runs a single prompt through the evaluation pipeline and reports metrics."""
    record_id = str(sample_row.get("record_id", "N/A"))
    prompt_text = str(sample_row.get("prompt", ""))
    expected_cmd = normalize_cmd(str(sample_row.get("expected_command", "")))
    expected_tool = str(sample_row.get("tool", "")).lower().strip()
    intent = str(sample_row.get("intent", "")).upper().strip()
    target = str(sample_row.get("target", "")).strip()

    # Formulate Gemma C2 instruction prompt
    full_prompt = (
        "Synthesize a valid Kali Linux C2 execution command for the following specification. Output ONLY the executable command.\n\n"
        f"Intent: {intent}\n"
        f"Target: {target}\n"
        f"Ports: {sample_row.get('ports', '')}\n"
        f"Modifiers: {sample_row.get('modifiers', '')}\n"
        f"Tool: {expected_tool}\n"
        f"Instruction: {prompt_text}"
    )

    start_time = time.time()
    
    # Inference via Ollama
    try:
        response = ollama.chat(
            model=TARGET_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": "You are a Kali Linux command generator for NeuroShell C2. Output ONLY valid, executable commands for the requested tool and target. Do not explain."
                },
                {
                    "role": "user",
                    "content": full_prompt
                }
            ]
        )
        raw_output = response["message"]["content"].strip()
    except Exception as e:
        raw_output = f"ERROR: Ollama inference failed: {str(e)}"

    latency_ms = (time.time() - start_time) * 1000.0

    # Clean & parse output using CommandSynthesizer
    parsed_cmds = synthesizer.parse_command_output(raw_output, multi_step=False)
    generated_cmd = normalize_cmd(parsed_cmds[0]) if parsed_cmds else normalize_cmd(raw_output)

    # 1. Normalized exact match
    exact_match = (generated_cmd == expected_cmd)

    # 2. Tool correctness
    generated_tool = extract_primary_tool(generated_cmd)
    tool_correct = (generated_tool == expected_tool)

    # 3. Command Validation (returns Tuple[bool, List[str]])
    validator_passed, validator_issues = validator.validate(generated_cmd, expected_tool=expected_tool)

    # 4. Safety Filter Validation (returns Tuple[bool, List[str]])
    safety_passed, safety_flags = safety_filter.validate(generated_cmd, target=target)

    return {
        "sample_type": sample_type,
        "record_id": record_id,
        "eval_model": TARGET_MODEL,
        "prompt": prompt_text,
        "expected_command": expected_cmd,
        "generated_command": generated_cmd,
        "expected_tool": expected_tool,
        "generated_tool": generated_tool,
        "exact_match": exact_match,
        "tool_correct": tool_correct,
        "validator_passed": validator_passed,
        "validator_issues": validator_issues,
        "safety_passed": safety_passed,
        "safety_flags": safety_flags,
        "latency_ms": round(latency_ms, 2)
    }


def run_verification():
    print(f"=== NEUROSHELL C2 MODEL VERIFICATION ({TARGET_MODEL}) ===")
    
    synthesizer = CommandSynthesizer()
    validator = CommandValidator()
    safety_filter = SafetyFilter()

    train_path = "data/synthesis_dataset/final/c2_sft_train.csv"
    test_path = "data/synthesis_dataset/final/c2_sft_test.csv"

    if not os.path.exists(train_path) or not os.path.exists(test_path):
        print("ERROR: Training or Test dataset file missing!")
        sys.exit(1)

    df_train = pd.read_csv(train_path)
    df_test = pd.read_csv(test_path)

    # 1. Known training sample (df_train.iloc[0])
    train_sample = df_train.iloc[0]
    res_train = evaluate_sample(train_sample, "Known Training Sample", synthesizer, validator, safety_filter)

    # 2. Held-out test sample (df_test.iloc[0])
    test_sample = df_test.iloc[0]
    res_test = evaluate_sample(test_sample, "Held-Out Test Sample", synthesizer, validator, safety_filter)

    results = [res_train, res_test]

    print("\n" + "="*80)
    for r in results:
        print(f"SAMPLE TYPE:      {r['sample_type']} ({r['record_id']})")
        print(f"EVAL MODEL:       {r['eval_model']}")
        print(f"PROMPT:           {r['prompt'][:100]}...")
        print(f"EXPECTED TOOL:    {r['expected_tool']}")
        print(f"GENERATED TOOL:   {r['generated_tool']} (Correct: {r['tool_correct']})")
        print(f"EXPECTED CMD:     {r['expected_command']}")
        print(f"GENERATED CMD:    {r['generated_command']}")
        print(f"EXACT MATCH:      {r['exact_match']}")
        print(f"VALIDATOR PASS:   {r['validator_passed']} (Issues: {r['validator_issues']})")
        print(f"SAFETY PASS:      {r['safety_passed']} (Flags: {r['safety_flags']})")
        print(f"LATENCY:          {r['latency_ms']} ms")
        print("-" * 80)

    return results


if __name__ == "__main__":
    run_verification()
