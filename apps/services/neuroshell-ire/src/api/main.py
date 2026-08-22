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
from fastapi import FastAPI, HTTPException, Request, Depends, Header
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
from src.utils.logging_config import get_logger


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
        "- `X-IRE-Schema-Version: 1` — baseline response (9 fields)\n"
        "- `X-IRE-Schema-Version: 2` — enhanced response with sub_intent, "
        "session context, RBAC role, cache status (default)\n\n"
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


async def verify_api_key(api_key: str = Depends(API_KEY_HEADER)) -> str:
    if settings.ire_api_key == "dev_insecure_key":
        return "dev_mode"
    if not api_key or api_key != settings.ire_api_key:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing X-API-Key header"
        )
    return api_key


def build_parse_response(
    v2_response: IREResponseV2,
    schema_version: int,
) -> JSONResponse:
    if schema_version == 1:
        v1_data = {
            "status": v2_response.status,
            "intent": v2_response.intent.value
                if v2_response.intent else None,
            "target": v2_response.target.model_dump()
                if v2_response.target else None,
            "ports": v2_response.ports,
            "modifiers": v2_response.modifiers,
            "cve_ids": v2_response.cve_ids,
            "tool_hint": v2_response.tool_hint,
            "schedule": v2_response.schedule,
            "confidence": v2_response.confidence,
            "rejection_reason": v2_response.rejection_reason,
            "scope_warnings": v2_response.scope_warnings,
            "latency_ms": v2_response.latency_ms,
            "error": v2_response.error,
            "stage": v2_response.stage,
            "field": v2_response.field,
            "detail": v2_response.detail,
        }
        content = v1_data
    else:
        content = v2_response.model_dump()

    headers = {
        "X-IRE-Schema-Version": str(schema_version),
        "X-IRE-Latency-Ms": str(v2_response.latency_ms or 0),
        "X-IRE-Intent": (v2_response.intent.value
                         if v2_response.intent else "unknown"),
        "X-IRE-Cache-Hit": v2_response.cache_hit or "none",
    }

    return JSONResponse(content=content, headers=headers)


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
    x_ire_schema_version: Optional[str] = Header(
        default="2",
        alias="X-IRE-Schema-Version",
        description="Response schema version: 1 (baseline) or 2 (enhanced)"
    ),
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

    try:
        schema_ver = int(x_ire_schema_version or "2")
        if schema_ver not in (1, 2):
            schema_ver = 2
    except (ValueError, TypeError):
        schema_ver = 2

    if pipeline is None:
        raise HTTPException(status_code=503, detail="Pipeline not initialized")

    v2_response = pipeline.parse(body)
    return build_parse_response(v2_response, schema_ver)


@app.post(
    "/parse/plan",
    tags=["IRE"],
    summary="Parse command and return Component 02 planner contract",
    responses={
        200: {"description": "PlannerContract ready for Component 02"},
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
