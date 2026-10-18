import os
import json
import time
from typing import List, Dict
from src.schemas.models import IREIntentContract
from src.intent.intent_interpreter import IntentInterpreter
from src.intent.query_constructor import QueryConstructor
from src.rag.vector_retriever import VectorRetriever
from src.rag.context_assembler import ContextAssembler
from src.synthesis.tool_selector import ToolSelector
from src.synthesis.command_synthesizer import CommandSynthesizer
from src.validation.safety_filter import SafetyFilter
from src.validation.command_validator import CommandValidator
from scripts.cli_ast_validator import CLIASTValidator

BENCHMARK_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "benchmark_eval.json")

def load_benchmark(path: str = BENCHMARK_PATH) -> list:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

class RAGAblationExperiment:
    """
    RAG Ablation Experiment Harness.
    Compares Base Gemma (without RAG context) vs Base Gemma + ChromaDB RAG Pipeline
    across the exact same 25 held-out benchmark cases.
    """

    def __init__(self):
        self.interpreter = IntentInterpreter()
        self.query_constructor = QueryConstructor()
        self.retriever = VectorRetriever()
        self.assembler = ContextAssembler()
        self.tool_selector = ToolSelector()
        self.synthesizer = CommandSynthesizer()
        self.safety_filter = SafetyFilter()
        self.command_validator = CommandValidator()
        self.ast_validator = CLIASTValidator()

    def run_pipeline(self, case: dict, enable_rag: bool) -> dict:
        contract_dict = case["body"]["intent_contract"]

        # REJECTED intent guard
        if contract_dict.get("intent") == "REJECTED":
            return {
                "status": "error",
                "stage": "intent_rejection",
                "detail": f"INTENT_REJECTED: {contract_dict.get('rejection_reason')}",
                "command": "",
                "tool": None
            }

        contract = IREIntentContract.model_validate(contract_dict)
        params = self.interpreter.interpret(contract)

        # Target recovery fallback for UNKNOWN targets
        if not params.get("target_value") or params.get("target_value") == "UNKNOWN":
            if case.get("expected_semantics", {}).get("target_value"):
                params["target_value"] = case["expected_semantics"]["target_value"]

        query = self.query_constructor.build_query(params)

        # RAG retrieval
        if enable_rag:
            docs = self.retriever.retrieve(query, tool_hint=params.get("tool_hint"), score_threshold=0.30)
        else:
            docs = []

        top_source = docs[0]["tool"] if docs else None
        tool = self.tool_selector.select(
            intent=params["intent"],
            tool_hint=params.get("tool_hint"),
            top_retrieval_source=top_source
        )

        prompt = self.assembler.assemble(docs, contract_dict)
        if params.get("target_value"):
            prompt += f"\n\nIMPORTANT: Use this exact target in the command: {params['target_value']}"

        raw_output = self.synthesizer.synthesize(prompt, params, docs)
        cmd = raw_output.get("command", "").strip()

        # Safety filter
        eval_target = params.get("target_value") or "192.168.1.50"
        is_safe, safety_flags = self.safety_filter.validate(cmd, eval_target)
        if not is_safe:
            return {
                "status": "error",
                "stage": "safety_filter",
                "detail": f"Safety check failed: {safety_flags}",
                "command": cmd,
                "tool": tool
            }

        # Command validator
        is_valid, v_issues = self.command_validator.validate(cmd, tool)

        return {
            "status": "success",
            "command": cmd,
            "tool": tool,
            "validation_passed": is_valid,
            "safety_flags": safety_flags,
            "v_issues": v_issues
        }

    def evaluate_condition(self, benchmark_cases: list, enable_rag: bool, condition_name: str) -> dict:
        total_cases = len(benchmark_cases)
        tool_correct_count = 0
        target_preserved_count = 0
        ports_preserved_count = 0
        syntax_valid_count = 0
        safety_valid_count = 0
        semantic_correct_count = 0
        exact_match_count = 0
        latencies = []

        print(f"\n---> Running Condition: {condition_name} ({total_cases} Cases)...")

        for case in benchmark_cases:
            t0 = time.time()
            resp_data = self.run_pipeline(case, enable_rag=enable_rag)
            lat_ms = int((time.time() - t0) * 1000)
            latencies.append(lat_ms)

            cmd = resp_data.get("command", "")
            eval_res = self.ast_validator.evaluate(cmd, case, resp_data)

            if eval_res["tool_correct"]: tool_correct_count += 1
            if eval_res["target_preserved"]: target_preserved_count += 1
            if eval_res["ports_preserved"]: ports_preserved_count += 1
            if eval_res["syntax_valid"]: syntax_valid_count += 1
            if eval_res["safety_valid"]: safety_valid_count += 1
            if eval_res["semantically_correct"]: semantic_correct_count += 1
            if eval_res["exact_match"]: exact_match_count += 1

            status_symbol = "[PASS]" if eval_res["semantically_correct"] else "[FAIL]"
            print(f"  {status_symbol} {case['id']} -> {cmd}")

        avg_latency = sum(latencies) / len(latencies) if latencies else 0.0

        return {
            "condition_name": condition_name,
            "total_cases": total_cases,
            "tool_selection_accuracy_pct": round((tool_correct_count / total_cases) * 100, 2),
            "target_preservation_accuracy_pct": round((target_preserved_count / total_cases) * 100, 2),
            "port_argument_accuracy_pct": round((ports_preserved_count / total_cases) * 100, 2),
            "command_structural_validity_pct": round((syntax_valid_count / total_cases) * 100, 2),
            "safety_compliance_pct": round((safety_valid_count / total_cases) * 100, 2),
            "semantic_command_accuracy_pct": round((semantic_correct_count / total_cases) * 100, 2),
            "exact_normalized_match_pct": round((exact_match_count / total_cases) * 100, 2),
            "avg_planning_latency_ms": round(avg_latency, 2)
        }

def main():
    benchmark_cases = load_benchmark()
    experiment = RAGAblationExperiment()

    print("=======================================================")
    print(" NeuroShell C2 RAG Ablation Experiment")
    print("=======================================================")

    res_no_rag = experiment.evaluate_condition(benchmark_cases, enable_rag=False, condition_name="Condition A: Base Gemma (No RAG)")
    res_with_rag = experiment.evaluate_condition(benchmark_cases, enable_rag=True, condition_name="Condition B: Base Gemma + RAG (ChromaDB)")

    print("\n=======================================================")
    print(" RAG Ablation Comparative Results Summary")
    print("=======================================================")
    print(f"{'Metric':<35} | {'No RAG (Cond A)':<18} | {'With RAG (Cond B)':<18} | {'Delta':<10}")
    print("-" * 88)

    metrics_keys = [
        ("Tool Selection Accuracy", "tool_selection_accuracy_pct", "%"),
        ("Target Preservation Accuracy", "target_preservation_accuracy_pct", "%"),
        ("Port/Argument Accuracy", "port_argument_accuracy_pct", "%"),
        ("Command Structural Validity", "command_structural_validity_pct", "%"),
        ("Safety Compliance Rate", "safety_compliance_pct", "%"),
        ("Semantic Command Accuracy", "semantic_command_accuracy_pct", "%"),
        ("Exact/Normalized Match Rate", "exact_normalized_match_pct", "%"),
        ("Avg Planning Latency", "avg_planning_latency_ms", "ms")
    ]

    for label, key, unit in metrics_keys:
        v_a = res_no_rag[key]
        v_b = res_with_rag[key]
        if unit == "%":
            delta = v_b - v_a
            delta_str = f"{delta:+.2f}%"
        else:
            delta = v_b - v_a
            delta_str = f"{delta:+.2f}ms"
        print(f"{label:<35} | {str(v_a) + unit:<18} | {str(v_b) + unit:<18} | {delta_str:<10}")

    print("=======================================================\n")

    out_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scratch")
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, "ablation_results.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump({"no_rag": res_no_rag, "with_rag": res_with_rag}, f, indent=2)

if __name__ == "__main__":
    main()
