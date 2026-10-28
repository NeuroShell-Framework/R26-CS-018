import sys
from pathlib import Path

# Ensure service root (neuroshell-ire) is in sys.path for resolution of config and src
SERVICE_ROOT = Path(__file__).resolve().parent.parent.parent
if str(SERVICE_ROOT) not in sys.path:
    sys.path.insert(0, str(SERVICE_ROOT))

import time
from contextlib import asynccontextmanager
from typing import Optional, Union

from pydantic import BaseModel
from fastapi import FastAPI, HTTPException, Request, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from config.settings import get_settings
from config.feature_flags import get_feature_flags
from config.enforcement_policy import get_enforcement_policy
from src.pipeline.ire_pipeline import IREPipeline
from src.schemas.intent_schema import (
    ParseRequest, ParseRequestV2,
    IREResponse, IREResponseV2
)
from src.pipeline.contract_builder import ContractBuilder
from src.validation.contract_validator import ContractValidator
from src.integration.planner_client import PlannerClient
from src.integration.executor_client import ExecutorClient, VulnerabilityClient
from src.utils.logging_config import get_logger
from src.utils.chain_cache import ChainCache


from src.audit import get_audit_logger


settings = get_settings()
flags = get_feature_flags()
logger = get_logger(__name__)
limiter = Limiter(key_func=get_remote_address)

pipeline: Optional[IREPipeline] = None
API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global pipeline
    logger.info("ire_startup", status="initializing")
    pipeline = IREPipeline()
    app.state.contract_builder = ContractBuilder()
    app.state.contract_validator = ContractValidator()
    app.state.audit_logger = get_audit_logger(settings=settings)
    app.state.chain_cache = ChainCache()
    if settings.planner_enabled:
        app.state.planner = PlannerClient(
            url=settings.planner_url,
            api_key=settings.planner_api_key,
            timeout_seconds=settings.planner_timeout_seconds,
        )
        logger.info(
            "planner_integration", status="enabled", url=settings.planner_url
        )
    else:
        app.state.planner = None

    if settings.component3_enabled:
        app.state.executor = ExecutorClient(
            url=settings.component3_url,
            timeout_seconds=settings.component3_timeout_seconds,
        )
        logger.info(
            "executor_integration", status="enabled", url=settings.component3_url
        )
    else:
        app.state.executor = None

    if settings.component4_enabled:
        app.state.vuln_analyzer = VulnerabilityClient(
            url=settings.component4_url,
            timeout_seconds=settings.component4_timeout_seconds,
        )
        logger.info(
            "vuln_analysis_integration",
            status="enabled",
            url=settings.component4_url,
        )
    else:
        app.state.vuln_analyzer = None

    logger.info(
        "ire_startup",
        status="ready",
        model=settings.ollama_model,
        scope_mode=settings.scope_mode,
    )
    yield
    logger.info("ire_shutdown", status="stopping")


app = FastAPI(
    title="NeuroShell IRE — Intent Recognition Engine",
    description=(
        "Domain-specific NLU gateway for the NeuroShell autonomous "
        "penetration testing framework. Converts natural language offensive "
        "security commands into validated structured JSON contracts.\n\n"
        "## Schema Versions\n"
        "- Every `POST /parse` triggers BOTH schema structures from one "
        "execution:\n"
        "- `version1` — official v1 structure (the one forwarded downstream "
        "to Component 02 for planning)\n"
        "- `version2` — extended v2 structure: v1 plus sub_intent, "
        "session context, RBAC role, cache status\n\n"
        "## Roles\n"
        "- `viewer` — blocked from all operations\n"
        "- `analyst` — passive recon + network scan only\n"
        "- `operator` — all non-destructive operations\n"
        "- `admin` — all operations including exploitation"
    ),
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

def rate_limit_handler(request: Request, exc: Exception) -> JSONResponse:
    detail = getattr(exc, "detail", str(exc))
    return JSONResponse(
        status_code=429,
        content={
            "status": "error",
            "error": "RATE_LIMIT_EXCEEDED",
            "detail": f"Rate limit exceeded: {detail}",
        }
    )


app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, rate_limit_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


async def _dispatch_to_planner(planner: PlannerClient, payload: dict) -> None:
    contract = payload.get("intent_contract") or {}
    try:
        result = await planner.push(payload)
    except Exception as e:
        logger.warning(
            "planner_push",
            status="failed",
            intent=contract.get("intent"),
            error=f"{type(e).__name__}: {e}",
        )
        return
    logger.info(
        "planner_push",
        status=result.get("status"),
        intent=contract.get("intent"),
        command=result.get("command"),
        tool=result.get("tool"),
        latency_ms=result.get("push_latency_ms"),
        schema="X-IRE-Schema-Version: 1",
        session_id=payload.get("session_id"),
        push_fields=list(contract.keys()),
    )


async def verify_api_key(api_key: str = Depends(API_KEY_HEADER)) -> str:
    if settings.ire_api_key == "dev_insecure_key":
        return "dev_mode"
    if not api_key or api_key != settings.ire_api_key:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing X-API-Key header"
        )
    return api_key


def _v1_content(
    v2_response: IREResponseV2,
    session_id: Optional[str] = None,
) -> dict:
    """Official v1 structure — the exact payload forwarded to Component 02.

    Shape: {"intent_contract": {...}, "session_id": "..."}
    """
    return {
        "intent_contract": {
            "intent": v2_response.intent.value
                if v2_response.intent else None,
            "target": v2_response.target.model_dump()
                if v2_response.target else None,
            "ports": v2_response.ports,
            "modifiers": v2_response.modifiers,
            "cve_ids": v2_response.cve_ids,
            "tool_hint": v2_response.tool_hint,
            "confidence": v2_response.confidence,
            "rejection_reason": v2_response.rejection_reason,
            "scope_warnings": v2_response.scope_warnings,
        },
        "session_id": session_id,
    }


def _response_headers(
    v2_response: IREResponseV2,
) -> dict:
    return {
        "X-IRE-Schema-Version": "1,2",
        "X-IRE-Latency-Ms": str(v2_response.latency_ms or 0),
        "X-IRE-Intent": (v2_response.intent.value
                         if v2_response.intent else "unknown"),
        "X-IRE-Cache-Hit": v2_response.cache_hit or "none",
    }


def build_parse_response(
    v2_response: IREResponseV2,
    session_id: Optional[str] = None,
) -> JSONResponse:
    """Both schema structures are triggered from a single execution.

    version1 is the official v1 structure ({intent_contract, session_id}),
    which is also the exact payload forwarded to Component 02;
    version2 is its extended form (v1 + v2 enhancement fields).
    """
    return JSONResponse(
        content={
            "version1": _v1_content(v2_response, session_id),
            "version2": v2_response.model_dump(),
        },
        headers=_response_headers(v2_response),
    )


@app.get("/", include_in_schema=False)
async def root():
    return JSONResponse(content={
        "service": "NeuroShell IRE",
        "version": "2.0.0",
        "docs": "/docs",
        "health": "/health",
        "schema_versions": [1, 2],
    })


@app.get("/health", tags=["System"])
async def health_check():
    if pipeline is None:
        return JSONResponse(
            status_code=503,
            content={"status": "unavailable",
                     "detail": "Pipeline not initialized"}
        )
    health = pipeline.health_check()
    status_code = 200 if health["status"] == "healthy" else 503
    return JSONResponse(status_code=status_code, content=health)


@app.post(
    "/parse",
    tags=["IRE"],
    summary="Parse a natural language offensive security command",
    responses={
        200: {"description": "Successfully parsed"},
        400: {"description": "Empty or invalid command"},
        401: {"description": "Invalid API key"},
        403: {"description": "RBAC access denied"},
        413: {"description": "Command too long"},
        429: {"description": "Rate limit exceeded"},
        503: {"description": "Pipeline not ready"},
    }
)
@limiter.limit("30/minute")
async def parse_command(
    request: Request,
    body: ParseRequestV2,
    background_tasks: BackgroundTasks,
    _api_key: str = Depends(verify_api_key),
):
    if pipeline is None:
        raise HTTPException(status_code=503,
                            detail="Pipeline not initialized")

    if len(body.command) > 2000:
        raise HTTPException(
            status_code=413,
            detail=f"Command length {len(body.command)} "
                   f"exceeds maximum of 2000 characters"
        )

    if not body.command.strip():
        raise HTTPException(status_code=400,
                            detail="Command cannot be empty")

    v2_response = pipeline.parse(body)

    planner = getattr(app.state, "planner", None)
    if (
        planner is not None
        and v2_response.status == "success"
        and PlannerClient.should_push(
            v2_response.intent.value if v2_response.intent else None,
            v2_response.rejection_reason,
        )
    ):
        push_payload = _v1_content(
            v2_response,
            session_id=body.session_id or "anonymous-flow",
        )
        background_tasks.add_task(
            _dispatch_to_planner,
            planner,
            dict(push_payload),
        )

    return build_parse_response(v2_response, body.session_id)


@app.post(
    "/execute",
    tags=["IRE"],
    summary="Execute the full C1 -> C2 chain and show both outputs",
    description=(
        "Runs the command through Component 01 (/parse), then synchronously "
        "forwards the resulting version1 contract as an HTTP POST to "
        "Component 02 (/plan). Returns BOTH outputs in one response so the "
        "backend chain reaction is visible from this UI."
    ),
    responses={
        200: {"description": "Full chain result: C1 output + C2 output"},
        400: {"description": "Empty command"},
        401: {"description": "Invalid API key"},
        403: {"description": "RBAC access denied"},
        413: {"description": "Command too long"},
        503: {"description": "Pipeline not ready"},
    }
)
@limiter.limit("30/minute")
async def execute_flow(
    request: Request,
    body: ParseRequestV2,
    _api_key: str = Depends(verify_api_key),
):
    if pipeline is None:
        raise HTTPException(status_code=503,
                            detail="Pipeline not initialized")

    if len(body.command) > 2000:
        raise HTTPException(
            status_code=413,
            detail=f"Command length {len(body.command)} "
                   f"exceeds maximum of 2000 characters"
        )

    if not body.command.strip():
        raise HTTPException(status_code=400,
                            detail="Command cannot be empty")

    # ── Persistent chain cache: identical input short-circuits the chain ──
    chain_cache: Optional[ChainCache] = getattr(app.state, "chain_cache", None)
    if chain_cache is not None:
        cached = chain_cache.lookup(body.command)
        if cached:
            content = cached.get("flow") or {}
            step_1 = content.get("flow", {}).get("step_1_user_input")
            if isinstance(step_1, dict):
                step_1["command"] = body.command
                step_1["session_id"] = body.session_id
                step_1["role"] = body.role
            headers = {
                "X-IRE-Schema-Version": "1,2",
                "X-IRE-Cache-Hit": "chain",
                "X-Chain-Cache-Hit": "true",
            }
            logger.info(
                "chain_cache_hit",
                key=cached.get("key"),
                session_id=body.session_id,
                hit_count=cached.get("hit_count", 0),
            )
            return JSONResponse(content=content, headers=headers)

    # ── Component 01: parse & validate ──────────────────────────────────
    v2_response = pipeline.parse(body)

    version1 = _v1_content(
        v2_response,
        session_id=body.session_id or "anonymous-flow",
    )
    version2 = v2_response.model_dump()

    c1_output = {
        "version1": version1,
        "version2": version2,
    }

    component_1 = {
        "status": v2_response.status,
        "output": c1_output,
    }

    # ── Component 02: synchronous forward of version1 ───────────────────
    planner = getattr(app.state, "planner", None)
    component_2 = None
    c2_called = bool(
        planner is not None
        and v2_response.status == "success"
        and PlannerClient.should_push(
            v2_response.intent.value if v2_response.intent else None,
            v2_response.rejection_reason,
        )
    )

    if c2_called:
        protocol_started = time.perf_counter()
        result = await planner.push(dict(version1))
        try:
            c2_elapsed_ms = result["push_latency_ms"]
        except KeyError:
            c2_elapsed_ms = int(
                (time.perf_counter() - protocol_started) * 1000
            )
        c2_output = {
            k: v for k, v in result.items()
            if k not in ("push_latency_ms",)
        }
        component_2 = {
            "status": result.get("status"),
            "latency_ms": c2_elapsed_ms,
            "output": c2_output,
        }
    else:
        component_2 = {
            "status": "skipped",
            "reason": (
                "C1 did not produce a forwardable contract "
                "(error/rejected) or planner not configured"
            ),
            "output": None,
        }

    # ── Component 03: execute the planned command via AEERE ──────────────
    executor = getattr(app.state, "executor", None)
    component_3 = None
    if (
        executor is not None
        and component_2 and component_2.get("status") == "success"
    ):
        c2_result = component_2.get("output") or {}
        c3_payload = {
            "command": c2_result.get("command"),
            "tool": c2_result.get("tool"),
            "session_id": c2_result.get("session_id"),
            "intent_ref": c2_result.get("intent_ref"),
        }
        if c3_payload.get("command"):
            c3_started = time.perf_counter()
            c3_raw = await executor.push(dict(c3_payload))
            c3_elapsed_ms = int(
                (time.perf_counter() - c3_started) * 1000
            )
            c3_raw["integration_latency_ms"] = c3_elapsed_ms
            component_3 = {
                "status": c3_raw.get("status"),
                "latency_ms": c3_elapsed_ms,
                "output": c3_raw,
            }

    # ── Component 04: analyse the AEERE result via AVAE ─────────────────
    vuln_analyzer = getattr(app.state, "vuln_analyzer", None)
    component_4 = None
    if (
        vuln_analyzer is not None
        and component_3 and component_3.get("output")
    ):
        c3_body = component_3.get("output") or {}
        is_forwardable = bool(
            c3_body.get("status") in ("success", "recovered", "failed")
            and c3_body.get("session_id")
            and c3_body.get("command_executed")
        )
        if is_forwardable:
            c2_result = component_2.get("output") or {}
            c4_payload = {
                "session_id": c3_body.get("session_id"),
                "status": c3_body.get("status"),
                "command_executed": c3_body.get("command_executed"),
                "stdout": c3_body.get("stdout", ""),
                "stderr": c3_body.get("stderr", ""),
                "exit_code": c3_body.get("exit_code", 1),
                "tool": c2_result.get("tool"),
                "intent_ref": c2_result.get("intent_ref"),
                "latency_ms": c3_body.get("latency_ms", 0),
            }
            c4_started = time.perf_counter()
            c4_raw = await vuln_analyzer.push(dict(c4_payload))
            c4_elapsed_ms = int(
                (time.perf_counter() - c4_started) * 1000
            )
            c4_raw["integration_latency_ms"] = c4_elapsed_ms
            component_4 = {
                "status": c4_raw.get("status"),
                "latency_ms": c4_elapsed_ms,
                "output": c4_raw,
            }
        else:
            component_4 = {
                "status": "skipped",
                "reason": (
                    "C3 did not produce a forwardable ExecutionResult "
                    "(transport failure / timeout) - nothing to analyse"
                ),
                "output": None,
            }

    content = {
        "status": "ok",
        "flow": {
            "step_1_user_input": {
                "command": body.command,
                "session_id": body.session_id,
                "role": body.role,
            },
            "step_2_component_1": component_1,
            "step_3_component_2": component_2,
            "step_4_component_3": component_3,
            "step_5_component_4": component_4,
        },
    }

    if chain_cache is not None and component_1.get("status") == "success":
        chain_cache.store(body.command, content)

    headers = _response_headers(v2_response)
    headers["X-Chain-Cache-Hit"] = "false"
    return JSONResponse(content=content, headers=headers)


@app.post(
    "/parse/plan",
    tags=["IRE"],
    summary="Parse command and return validated planner contract",
    responses={
        200: {"description": "PlannerContract ready for downstream planning"},
        400: {"description": "Empty command"},
        401: {"description": "Invalid API key"},
        413: {"description": "Command too long"},
    }
)
@limiter.limit("30/minute")
async def parse_for_planner(
    request: Request,
    body: ParseRequestV2,
    _api_key: str = Depends(verify_api_key),
):
    if pipeline is None:
        raise HTTPException(status_code=503,
                            detail="Pipeline not initialized")
    if len(body.command) > 2000:
        raise HTTPException(status_code=413,
                            detail="Command too long")
    if not body.command.strip():
        raise HTTPException(status_code=400,
                            detail="Command cannot be empty")

    v2_response = pipeline.parse(body)

    if v2_response.status == "error":
        return JSONResponse(
            status_code=422,
            content={
                "status": "error",
                "error": v2_response.error,
                "stage": v2_response.stage,
                "detail": v2_response.detail,
                "contract": None,
            }
        )

    from src.schemas.intent_schema import (
        IntentSchema, Target, TargetType
    )
    try:
        intent_schema = IntentSchema(
            intent=v2_response.intent,
            target=v2_response.target,
            ports=v2_response.ports or [],
            modifiers=v2_response.modifiers or [],
            cve_ids=v2_response.cve_ids or [],
            tool_hint=v2_response.tool_hint,
            schedule=v2_response.schedule,
            confidence=v2_response.confidence or 0.0,
            rejection_reason=v2_response.rejection_reason,
        )

        try:
            contract = app.state.contract_builder.build(
                schema=intent_schema,
                session_id=body.session_id,
                scope_warnings=v2_response.scope_warnings or [],
                validation_findings=v2_response.validation_findings or [],
            )

            contract, contract_warnings = \
                app.state.contract_validator.validate(contract)
        except ValueError as e:
            logger.error("contract_validation_failed", error=str(e))
            return JSONResponse(
                status_code=422,
                content={
                    "status": "error",
                    "error": "CONTRACT_VALIDATION_FAILED",
                    "stage": "contract_validator",
                    "detail": str(e),
                    "contract": None,
                }
            )

        if v2_response.sub_intent:
            contract.sub_intent = v2_response.sub_intent

        # Check for ESCALATE enforcement action findings
        import json
        escalated_finding = None
        for finding in (v2_response.validation_findings or []):
            if finding.severity == "escalate":
                escalated_finding = finding
                break

        if escalated_finding:
            h_class = (
                escalated_finding.hallucination_class.value
                if hasattr(escalated_finding.hallucination_class, "value")
                else str(escalated_finding.hallucination_class or "UNKNOWN")
            )
            audit_logger = getattr(app.state, "audit_logger", get_audit_logger())
            intent_summary = f"{intent_schema.intent.value if hasattr(intent_schema.intent, 'value') else intent_schema.intent} on {intent_schema.target.value if intent_schema.target else 'NONE'}"
            audit_id = audit_logger.record_finding(
                raw_input=body.command,
                intent_summary=intent_summary,
                hallucination_class=h_class,
                severity="escalate",
                enforcement_action="ESCALATE",
                session_id=body.session_id,
                status="pending",
                cached_contract_json=json.dumps(contract.model_dump()),
            )
            return JSONResponse(
                status_code=202,
                content={
                    "status": "pending_review",
                    "escalation_id": audit_id,
                    "message": "Contract withheld pending human review",
                    "hallucination_class": h_class,
                    "detail": escalated_finding.detail,
                    "contract": None,
                },
            )

        return contract.model_dump()

    except Exception as e:
        logger.error("contract_build_error", error=str(e))
        raise HTTPException(
            status_code=500,
            detail=f"Contract construction failed: {str(e)}"
        )


@app.get("/metrics", tags=["System"])
async def get_metrics(_api_key: str = Depends(verify_api_key)):
    if pipeline is None:
        raise HTTPException(status_code=503,
                            detail="Pipeline not initialized")
    return pipeline.metrics.get_summary()


@app.get("/session/{session_id}", tags=["Session"])
async def get_session_info(
    session_id: str,
    _api_key: str = Depends(verify_api_key),
):
    if pipeline is None:
        raise HTTPException(status_code=503,
                            detail="Pipeline not initialized")
    info = pipeline.session_context.get_session_info(session_id)
    if info is None:
        raise HTTPException(
            status_code=404,
            detail=f"Session '{session_id}' not found or expired"
        )
    return info


@app.delete("/session/{session_id}", tags=["Session"])
async def clear_session(
    session_id: str,
    _api_key: str = Depends(verify_api_key),
):
    if pipeline is None:
        raise HTTPException(status_code=503,
                            detail="Pipeline not initialized")
    cleared = pipeline.session_context.clear_session(session_id)
    if not cleared:
        raise HTTPException(
            status_code=404,
            detail=f"Session '{session_id}' not found"
        )
    return {"cleared": True, "session_id": session_id}


@app.get("/admin/rbac/{role}", tags=["Admin"])
async def get_role_permissions(
    role: str,
    _api_key: str = Depends(verify_api_key),
):
    if pipeline is None:
        raise HTTPException(status_code=503,
                            detail="Pipeline not initialized")
    return pipeline.rbac_guard.get_role_summary(role)


@app.get("/admin/features", tags=["Admin"])
async def get_feature_flags_status(
    _api_key: str = Depends(verify_api_key),
):
    if pipeline is None:
        raise HTTPException(status_code=503,
                            detail="Pipeline not initialized")
    return {
        "features": flags._flags,
        "tuning": flags._tuning,
        "schema_v2_enabled": flags.schema_v2,
    }


@app.post("/admin/features/reload", tags=["Admin"])
async def reload_features(
    _api_key: str = Depends(verify_api_key),
):
    flags.reload()
    if pipeline is not None:
        pipeline.flags = flags
    return {
        "reloaded": True,
        "features": flags._flags,
    }


class ModelSwitchRequest(BaseModel):
    model: str


def _persist_model_env(model: str) -> None:
    """Persist OLLAMA_MODEL to the .env file so the switch survives restarts."""
    env_path = Path(SERVICE_ROOT) / ".env"
    try:
        lines = env_path.read_text(encoding="utf-8").splitlines() if env_path.exists() else []
        found = False
        for i, line in enumerate(lines):
            if line.strip().upper().startswith("OLLAMA_MODEL="):
                lines[i] = f"OLLAMA_MODEL={model}"
                found = True
                break
        if not found:
            lines.append(f"OLLAMA_MODEL={model}")
        env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        logger.info("model_env_persisted", model=model)
    except Exception as e:
        logger.error("model_env_persist_error", error=str(e))


def _model_registry() -> list:
    try:
        names = pipeline.inference_engine.list_models()
    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail=f"Could not query Ollama: {str(e)}",
        )
    active = settings.ollama_model
    return [
        {"name": name, "size": 0, "active": name == active}
        for name in names
    ]


@app.get("/admin/models", tags=["Admin"])
async def list_models(
    _api_key: str = Depends(verify_api_key),
):
    if pipeline is None:
        raise HTTPException(status_code=503,
                            detail="Pipeline not initialized")
    return {
        "active": settings.ollama_model,
        "models": _model_registry(),
    }


@app.post("/admin/models/switch", tags=["Admin"])
async def switch_model(
    body: ModelSwitchRequest,
    _api_key: str = Depends(verify_api_key),
):
    if pipeline is None:
        raise HTTPException(status_code=503,
                            detail="Pipeline not initialized")
    model = body.model.strip()
    if not model:
        raise HTTPException(status_code=422,
                            detail="model must be a non-empty string")
    previous = settings.ollama_model
    try:
        pipeline.inference_engine.switch_model(model)
        _persist_model_env(model)
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))
    logger.info(
        "model_switch_requested",
        previous=previous,
        current=settings.ollama_model,
    )
    return {
        "switched_to": settings.ollama_model,
        "previous": previous,
        "active": settings.ollama_model,
        "models": _model_registry(),
        "persisted": ".env",
    }


@app.get("/admin/enforcement-policy", tags=["Admin"])
async def get_enforcement_policy_endpoint(
    _api_key: str = Depends(verify_api_key),
):
    """
    Returns the current effective enforcement policy and reasoning per HallucinationClass.
    """
    policy = get_enforcement_policy()
    return policy.get_policy_summary()


class EscalationResolveRequest(BaseModel):
    approve: bool
    note: str = ""
    resolved_by: str = "admin"


@app.get("/admin/escalations", tags=["Admin"])
async def list_escalations(
    status: str = "pending",
    _api_key: str = Depends(verify_api_key),
):
    """
    Returns items in the human-in-the-loop escalation queue.
    """
    audit_logger = getattr(app.state, "audit_logger", get_audit_logger())
    if status == "pending":
        records = audit_logger.get_pending_escalations()
    else:
        records = []
    return {
        "status": "success",
        "count": len(records),
        "escalations": records,
    }


@app.post("/admin/escalations/{audit_id}/resolve", tags=["Admin"])
async def resolve_escalation(
    audit_id: int,
    body: EscalationResolveRequest,
    _api_key: str = Depends(verify_api_key),
):
    """
    Resolves a pending escalation. If approved, releases and returns the contract.
    """
    import json
    audit_logger = getattr(app.state, "audit_logger", get_audit_logger())
    record = audit_logger.get_escalation_by_id(audit_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Escalation {audit_id} not found")

    updated = audit_logger.resolve_escalation(
        audit_id=audit_id,
        approve=body.approve,
        note=body.note,
        resolved_by=body.resolved_by or "admin",
    )

    contract_dict = None
    if body.approve and updated and updated.get("cached_contract_json"):
        try:
            contract_dict = json.loads(updated["cached_contract_json"])
        except Exception:
            contract_dict = None

    res_status = "approved" if body.approve else "rejected"
    return {
        "status": res_status,
        "escalation_id": audit_id,
        "contract": contract_dict,
        "resolved_by": updated["resolved_by"] if updated else "admin",
        "resolved_at": updated["resolved_at"] if updated else None,
        "resolution_note": updated["resolution_note"] if updated else body.note,
    }


@app.get("/admin/audit/summary", tags=["Admin"])
async def get_audit_summary_endpoint(
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    _api_key: str = Depends(verify_api_key),
):
    """
    Returns aggregate finding count summary grouped by hallucination_class and enforcement_action.
    """
    audit_logger = getattr(app.state, "audit_logger", get_audit_logger())
    summary = audit_logger.get_audit_summary(start_time=start_time, end_time=end_time)
    return {
        "status": "success",
        "summary": summary,
    }


@app.get("/admin/chain-cache", tags=["Admin"])
async def get_chain_cache_stats(
    _api_key: str = Depends(verify_api_key),
):
    """Returns stats for the persistent /execute chain cache."""
    cc: Optional[ChainCache] = getattr(app.state, "chain_cache", None)
    if cc is None:
        raise HTTPException(status_code=503, detail="Chain cache not initialized")
    return {"status": "success", **cc.stats()}


@app.delete("/admin/chain-cache", tags=["Admin"])
async def clear_chain_cache(
    _api_key: str = Depends(verify_api_key),
):
    """Clears the persistent /execute chain cache."""
    cc: Optional[ChainCache] = getattr(app.state, "chain_cache", None)
    if cc is None:
        raise HTTPException(status_code=503, detail="Chain cache not initialized")
    cc.clear()
    return {"status": "success", "cleared": True, **cc.stats()}


@app.get("/engagement/scope", tags=["Engagement"])
async def get_engagement_scope(
    _api_key: str = Depends(verify_api_key),
):
    """
    Returns the current engagement scope configuration.
    Shows the authorised target network, engagement name,
    validation mode, and CIDR prefix bounds.
    Used to verify the correct scope is loaded before
    starting a penetration testing engagement.
    """
    return {
        "engagement_name":   settings.engagement_name,
        "engagement_scope":  settings.engagement_scope,
        "engagement_mode":   settings.engagement_mode,
        "max_cidr_prefix":   settings.max_cidr_prefix,
        "min_cidr_prefix":   settings.min_cidr_prefix,
        "description": (
            f"Targets must fall within {settings.engagement_scope}. "
            f"Mode: {settings.engagement_mode}. "
            f"CIDR prefix range: /{settings.max_cidr_prefix} "
            f"to /{settings.min_cidr_prefix}."
        )
    }


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(
        "unhandled_exception",
        path=request.url.path,
        method=request.method,
        error=type(exc).__name__,
        detail=str(exc)
    )
    return JSONResponse(
        status_code=500,
        content={
            "status": "error",
            "error": "INTERNAL_SERVER_ERROR",
            "detail": "An unexpected error occurred. Check server logs."
        }
    )
