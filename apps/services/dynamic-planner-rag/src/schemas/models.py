from pydantic import BaseModel, Field
from typing import List, Optional, Literal, Dict, Any


class ToolParameters(BaseModel):
    target: Optional[str] = None
    flags: List[str] = []
    ports: List[int] = []
    wordlist: Optional[str] = None
    suggested_command: Optional[str] = None


class IREIntentContract(BaseModel):
    intent: Literal[
        "NETWORK_SCAN", "VULNERABILITY_AUDIT", "DIRECTORY_BRUTEFORCE",
        "SERVICE_ENUMERATION", "EXPLOITATION", "PASSWORD_ATTACK",
        "PASSIVE_RECON", "AMBIGUOUS", "REJECTED"
    ]

    # New enriched C1 format
    target_type: Optional[str] = None
    target_value: Optional[str] = None
    primary_tool: Optional[str] = None
    tool_parameters: ToolParameters = ToolParameters()

    # Old C2 format
    target: Optional[Dict[str, Any]] = None
    ports: List[int] = []
    modifiers: List[str] = []
    cve_ids: List[str] = []
    tool_hint: Optional[str] = None

    # Common fields
    sub_intent: Optional[str] = None
    schedule: Optional[str] = None
    confidence: float = 0.0
    rejection_reason: Optional[str] = None
    scope_warnings: List[str] = []


class PlanRequest(BaseModel):
    # Old nested format
    intent_contract: Optional[IREIntentContract] = None

    # Common request fields
    session_id: str
    contract_version: Optional[str] = None
    request_id: Optional[str] = None

    # Direct C1 fields
    intent: Optional[str] = None
    sub_intent: Optional[str] = None
    confidence: Optional[float] = None
    human_readable_intent: Optional[str] = None

    # New enriched C1 format
    target_type: Optional[str] = None
    target_value: Optional[str] = None
    target_in_scope: Optional[bool] = None
    primary_tool: Optional[str] = None
    tool_parameters: Optional[ToolParameters] = None
    safety_notes: List[str] = []

    # Direct old-style C1 format
    target: Optional[Dict[str, Any]] = None
    ports: List[int] = []
    modifiers: List[str] = []
    cve_ids: List[str] = []
    tool_hint: Optional[str] = None
    schedule: Optional[str] = None
    rejection_reason: Optional[str] = None
    scope_warnings: List[str] = []


class PlannerOutput(BaseModel):
    status: Literal["success", "error"]
    command: Optional[str] = None
    command_sequence: List[str] = []
    tool: Optional[str] = None
    session_id: str
    intent_ref: str
    estimated_duration: str = "medium"
    retrieval_sources: List[str] = []
    validation_passed: bool = False
    safety_flags: List[str] = []
    latency_ms: int = 0


class ErrorResponse(BaseModel):
    status: Literal["error"]
    error: str
    stage: str
    detail: str
    latency_ms: int


class KBUpdateRequest(BaseModel):
    content: str = Field(max_length=51200)
    metadata: dict