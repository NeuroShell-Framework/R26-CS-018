import time
import uuid
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import os

from src.schemas.models import (
    PlanRequest, PlannerOutput, ErrorResponse, KBUpdateRequest, IREIntentContract
)
from src.intent.intent_interpreter import IntentInterpreter
from src.intent.query_constructor import QueryConstructor
from src.rag.vector_retriever import VectorRetriever
from src.rag.context_assembler import ContextAssembler
from src.synthesis.command_synthesizer import CommandSynthesizer
from src.synthesis.tool_selector import ToolSelector
from src.validation.command_validator import CommandValidator
from src.validation.safety_filter import SafetyFilter
from src.session.session_context_manager import SessionContextManager
from src.utils.metrics_collector import MetricsCollector

load_dotenv()

API_KEY   = os.getenv("API_KEY", "neuroshell-secret-key")
ADMIN_KEY = os.getenv("ADMIN_KEY", "neuroshell-admin-key")

app = FastAPI(
    title       ="NeuroShell Dynamic Planner",
    description ="C2 RAG-powered command synthesis engine",
    version     ="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize all modules
interpreter   = IntentInterpreter()
constructor   = QueryConstructor()
retriever     = VectorRetriever()
assembler     = ContextAssembler()
synthesizer   = CommandSynthesizer()
tool_selector = ToolSelector()
validator     = CommandValidator()
safety        = SafetyFilter()
session_mgr   = SessionContextManager()
metrics       = MetricsCollector()


@app.get("/health")
def health():
    try:
        session_mgr.client.ping()
        redis_status = "ok"
    except:
        redis_status = "error"

    kb_count = retriever.collection.count()

    return {
        "status"    : "ok",
        "component" : "C2-DynamicPlanner",
        "port"      : 8002,
        "redis"     : redis_status,
        "kb_chunks" : kb_count,
    }


@app.post("/plan", response_model=PlannerOutput)
def plan(request: PlanRequest, x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    start_time = time.time()
    session_id = request.session_id

    if request.intent_contract:
        contract = request.intent_contract
    else:
        contract = IREIntentContract(
            intent=request.intent,
            sub_intent=request.sub_intent,
            target=request.target,
            ports=request.ports,
            modifiers=request.modifiers,
            cve_ids=request.cve_ids,
            tool_hint=request.tool_hint,
            schedule=request.schedule,
            confidence=request.confidence or 0.0,
            rejection_reason=request.rejection_reason,
            scope_warnings=request.scope_warnings,
            target_type=request.target_type,
            target_value=request.target_value,
            primary_tool=request.primary_tool,
            tool_parameters=request.tool_parameters or {}
        )

    # ── Early exit: REJECTED intent must never reach RAG or Gemma ─────────
    if contract.intent == "REJECTED":
        latency = metrics.record(session_id, "REJECTED", "none", start_time, False, [])
        raise HTTPException(
            status_code=400,
            detail={
                "status" : "error",
                "stage"  : "intent_filter",
                "error"  : "INTENT_REJECTED",
                "detail" : (
                    contract.rejection_reason
                    or "Intent was classified as REJECTED by C1. No plan can be generated."
                ),
                "latency_ms": latency,
            },
        )

    try:
        # Step 1 - Interpret intent
        params = interpreter.interpret(contract)

        # Target Recovery: Recover target from session history if missing, empty, or UNKNOWN
        current_target = params.get("target_value")
        if not current_target or str(current_target).upper() == "UNKNOWN":
            recovered_target = session_mgr.get_last_target(session_id)
            if recovered_target:
                params["target_value"] = recovered_target

        # Step 2 - Build RAG query
        query = constructor.build_query(params)

        # Step 3 - Retrieve docs
        docs = retriever.retrieve(
            query,
            tool_hint=params.get("tool_hint"),
            top_k=3
        )

        # Step 3b - Resolve tool via ToolSelector
        #   Priority: C1 tool_hint → top RAG source → tool_map.json fallback
        top_rag_source = docs[0]["tool"] if docs else None
        tool = tool_selector.select(
            intent=contract.intent,
            tool_hint=params.get("tool_hint"),
            top_retrieval_source=top_rag_source,
        ) or "unknown"

        # Step 4 - Assemble prompt
        #   Append target-reinforcement line (moved here from CommandSynthesizer)
        prompt = assembler.assemble(docs, params)
        prompt += (
            f"\n\nIMPORTANT:\n"
            f"Use this exact target in the command: {params['target_value']}\n"
            f"Output ONLY one command.\n"
        )
        params["_query_used"] = query   # carry query through for result logging

        # Step 5 - Synthesize command sequence
        #   Pass the already-built (prompt, params, docs) — no re-processing inside.
        result      = synthesizer.synthesize(prompt, params, docs)
        command_seq = result.get("command_sequence") or [result["command"]]
        primary_cmd = command_seq[0] if command_seq else result.get("command", "")
        sources     = result["retrieval_sources"]

        # Step 6 & 7 - Multi-command Dual-Layer Validation
        target_value = params["target_value"]
        all_safety_flags = []

        for cmd in command_seq:
            safe, safety_flags = safety.validate(cmd, target_value)
            if not safe:
                latency = metrics.record(session_id, contract.intent, tool, start_time, False, safety_flags)
                raise HTTPException(status_code=400, detail=f"Safety check failed: {safety_flags}")
            all_safety_flags.extend(safety_flags)

            valid, issues = validator.validate(cmd, tool)
            if not valid:
                latency = metrics.record(session_id, contract.intent, tool, start_time, False, issues)
                raise HTTPException(
                    status_code=422,
                    detail={
                        "status"    : "error",
                        "stage"     : "command_validator",
                        "error"     : "VALIDATION_FAILED",
                        "detail"    : f"Command structural validation failed on step '{cmd}': {issues}",
                        "latency_ms": latency,
                    }
                )

        # Step 8 - Update session for all validated commands
        for cmd in command_seq:
            session_mgr.update_session(session_id, cmd, tool, target_value)

        # Step 9 - Record metrics
        latency = metrics.record(session_id, contract.intent, tool, start_time, True, all_safety_flags)

        return PlannerOutput(
            status             ="success",
            command            =primary_cmd,
            command_sequence   =command_seq,
            tool               =tool,
            session_id         =session_id,
            intent_ref         =contract.intent,
            estimated_duration ="medium",
            retrieval_sources  =sources,
            validation_passed  =True,
            safety_flags       =all_safety_flags,
            latency_ms         =latency,
        )

    except HTTPException:
        raise
    except Exception as e:
        latency = metrics.record(session_id, contract.intent, "unknown", start_time, False, [])
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/tools/available")
def available_tools():
    return {
        "tools": ["nmap", "nikto", "gobuster"],
        "kb_chunks": retriever.collection.count(),
    }


@app.get("/metrics")
def get_metrics(x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return metrics.get_summary()


# ── Administrative Endpoints ─────────────────────────────────────────────

def verify_admin_key(x_admin_key: str = Header(None), x_api_key: str = Header(None)):
    token = x_admin_key or x_api_key
    if not token or token != ADMIN_KEY:
        raise HTTPException(status_code=401, detail="Invalid Admin key")
    return token


@app.post("/kb/update")
def update_kb(
    request: KBUpdateRequest,
    x_admin_key: str = Header(None),
    x_api_key: str = Header(None)
):
    verify_admin_key(x_admin_key, x_api_key)
    try:
        chunks_added = retriever.add_document(request.content, request.metadata)
        total_chunks = retriever.collection.count()
        return {
            "status": "success",
            "chunks_added": chunks_added,
            "kb_chunks": total_chunks
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update knowledge base: {str(e)}")


@app.post("/admin/session/clear")
def clear_session(
    session_id: str,
    x_admin_key: str = Header(None),
    x_api_key: str = Header(None)
):
    verify_admin_key(x_admin_key, x_api_key)
    try:
        session_mgr.clear_session(session_id)
        return {
            "status": "success",
            "session_id": session_id,
            "message": "Session context cleared successfully"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to clear session: {str(e)}")


@app.post("/admin/metrics/reset")
def reset_metrics(
    x_admin_key: str = Header(None),
    x_api_key: str = Header(None)
):
    verify_admin_key(x_admin_key, x_api_key)
    metrics.reset()
    return {
        "status": "success",
        "message": "Metrics reset successfully"
    }


@app.get("/admin/status")
def admin_status(
    x_admin_key: str = Header(None),
    x_api_key: str = Header(None)
):
    verify_admin_key(x_admin_key, x_api_key)
    try:
        session_mgr.client.ping()
        redis_status = "ok"
    except Exception:
        redis_status = "error"

    return {
        "status": "ok",
        "component": "C2-DynamicPlanner",
        "admin_authenticated": True,
        "redis": redis_status,
        "kb_chunks": retriever.collection.count(),
        "metrics_summary": metrics.get_summary()
    }