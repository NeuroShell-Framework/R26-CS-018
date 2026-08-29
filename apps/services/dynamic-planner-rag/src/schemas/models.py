from pydantic import BaseModel, Field, ConfigDict
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
    """Request body must match the C1 /parse version1 output exactly.

    Canonical structure:
        {"intent_contract": {...}, "session_id": "..."}

    Legacy flat fields (intent, target_value, primary_tool, ...) are still
    accepted for backward compatibility, but are hidden from the OpenAPI
    documentation so the docs reflect the real v1 contract.
    """

    model_config = ConfigDict(extra="allow")

    intent_contract: Optional[IREIntentContract] = None
    session_id: str

    @property
    def legacy(self) -> Dict[str, Any]:
        """Legacy flat fields forwarded as model extras."""
        return self.model_extra or {}

    @property
    def intent(self):
        return self.legacy.get("intent")

    @property
    def sub_intent(self):
        return self.legacy.get("sub_intent")

    @property
    def confidence(self):
        return self.legacy.get("confidence")

    @property
    def human_readable_intent(self):
        return self.legacy.get("human_readable_intent")

    @property
    def target_type(self):
        return self.legacy.get("target_type")

    @property
    def target_value(self):
        return self.legacy.get("target_value")

    @property
    def target_in_scope(self):
        return self.legacy.get("target_in_scope")

    @property
    def primary_tool(self):
        return self.legacy.get("primary_tool")

    @property
    def tool_parameters(self):
        return self.legacy.get("tool_parameters")

    @property
    def safety_notes(self):
        return self.legacy.get("safety_notes") or []

    @property
    def target(self):
        return self.legacy.get("target")

    @property
    def ports(self):
        return self.legacy.get("ports") or []

    @property
    def modifiers(self):
        return self.legacy.get("modifiers") or []

    @property
    def cve_ids(self):
        return self.legacy.get("cve_ids") or []

    @property
    def tool_hint(self):
        return self.legacy.get("tool_hint")

    @property
    def schedule(self):
        return self.legacy.get("schedule")

    @property
    def rejection_reason(self):
        return self.legacy.get("rejection_reason")

    @property
    def scope_warnings(self):
        return self.legacy.get("scope_warnings") or []


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