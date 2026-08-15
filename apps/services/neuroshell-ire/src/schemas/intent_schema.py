# NeuroShell IRE — Intent Schema
# Pydantic models for intent validation

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field, field_validator, model_validator
import re


class IntentType(str, Enum):
    NETWORK_SCAN = "NETWORK_SCAN"
    VULNERABILITY_AUDIT = "VULNERABILITY_AUDIT"
    DIRECTORY_BRUTEFORCE = "DIRECTORY_BRUTEFORCE"
    SERVICE_ENUMERATION = "SERVICE_ENUMERATION"
    EXPLOITATION = "EXPLOITATION"
    PASSWORD_ATTACK = "PASSWORD_ATTACK"
    PASSIVE_RECON = "PASSIVE_RECON"
    AMBIGUOUS = "AMBIGUOUS"
    REJECTED = "REJECTED"


class TargetType(str, Enum):
    IP = "IP"
    SUBNET = "SUBNET"
    DOMAIN = "DOMAIN"
    URL = "URL"
    HOSTNAME = "HOSTNAME"
    UNKNOWN = "UNKNOWN"


class Target(BaseModel):
    model_config = {"extra": "forbid"}

    type: TargetType
    value: str = Field(..., description="The target address, subnet, domain, or URL")


class IntentSchema(BaseModel):
    model_config = {"extra": "forbid"}

    intent: IntentType
    target: Target
    ports: List[int] = Field(default_factory=list)
    modifiers: List[str] = Field(default_factory=list)
    cve_ids: List[str] = Field(default_factory=list)
    tool_hint: Optional[str] = None
    schedule: Optional[str] = None
    confidence: float = Field(..., ge=0.0, le=1.0)
    rejection_reason: Optional[str] = None

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, v):
        for port in v:
            if not (1 <= port <= 65535):
                raise ValueError(f"Port {port} is out of valid range (1-65535)")
        return v

    @field_validator("cve_ids")
    @classmethod
    def validate_cve_format(cls, v):
        pattern = re.compile(r"^CVE-\d{4}-\d{4,7}$")
        for cve in v:
            if not pattern.match(cve):
                raise ValueError(f"Invalid CVE format: {cve}. Expected CVE-YYYY-NNNNN")
        return v

    @model_validator(mode="after")
    def validate_rejection_reason(self):
        if self.intent == IntentType.REJECTED and not self.rejection_reason:
            raise ValueError("rejection_reason must be provided when intent is REJECTED")
        if self.intent == IntentType.AMBIGUOUS and self.confidence >= 0.5:
            raise ValueError("AMBIGUOUS intent must have confidence < 0.5")
        return self


class IREResponse(BaseModel):
    """Full API response wrapper — returned by POST /parse"""
    model_config = {"extra": "forbid"}

    status: str = Field(..., description="'success' or 'error'")

    intent: Optional[IntentType] = None
    target: Optional[Target] = None
    ports: List[int] = Field(default_factory=list)
    modifiers: List[str] = Field(default_factory=list)
    cve_ids: List[str] = Field(default_factory=list)
    tool_hint: Optional[str] = None
    schedule: Optional[str] = None
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    rejection_reason: Optional[str] = None
    scope_warnings: List[str] = Field(default_factory=list)
    latency_ms: Optional[int] = None

    error: Optional[str] = None
    stage: Optional[str] = None
    field: Optional[str] = None
    detail: Optional[str] = None

    @classmethod
    def from_intent_schema(
        cls,
        schema: "IntentSchema",
        latency_ms: int,
        scope_warnings: Optional[List[str]] = None,
    ) -> "IREResponse":
        return cls(
            status="success",
            intent=schema.intent,
            target=schema.target,
            ports=schema.ports,
            modifiers=schema.modifiers,
            cve_ids=schema.cve_ids,
            tool_hint=schema.tool_hint,
            schedule=schema.schedule,
            confidence=schema.confidence,
            rejection_reason=schema.rejection_reason,
            scope_warnings=scope_warnings or [],
            latency_ms=latency_ms,
        )

    @classmethod
    def error_response(
        cls,
        error: str,
        stage: str,
        detail: str,
        latency_ms: int,
        field: Optional[str] = None,
    ) -> "IREResponse":
        return cls(
            status="error",
            error=error,
            stage=stage,
            field=field,
            detail=detail,
            latency_ms=latency_ms,
        )


class ParseRequest(BaseModel):
    """Incoming request body for POST /parse"""
    command: str = Field(..., description="Raw natural language command from the operator")
    session_id: Optional[str] = Field(default=None, description="Optional session identifier")


class IREError(Exception):
    """Base exception for all IRE pipeline errors."""
    def __init__(self, message: str, stage: str, field: str = None):
        super().__init__(message)
        self.message = message
        self.stage = stage
        self.field = field


class JSONParseError(IREError):
    def __init__(self, message: str):
        super().__init__(message, stage="json_parser")


class SchemaValidationError(IREError):
    def __init__(self, message: str, field: str = None):
        super().__init__(message, stage="schema_validator", field=field)


class RegexValidationError(IREError):
    def __init__(self, message: str, field: str = None):
        super().__init__(message, stage="regex_validator", field=field)


class ScopeError(IREError):
    def __init__(self, message: str):
        super().__init__(message, stage="scope_guard")


class InferenceError(IREError):
    def __init__(self, message: str):
        super().__init__(message, stage="inference")


class NetworkValidationError(IREError):
    """
    Raised when a target fails network architecture validation.
    Covers: out-of-scope targets, invalid topology,
    insane CIDR prefixes, and target type mismatches.
    """
    def __init__(self, message: str, field: str = "target.value",
                 validation_type: str = "scope"):
        super().__init__(message, stage="network_validator",
                         field=field)
        self.validation_type = validation_type


# --- SECTION 1: Sub-Intent Enum ---

class SubIntentType(str, Enum):
    # NETWORK_SCAN sub-intents
    NETWORK_SCAN_ICMP_DISCOVERY  = "NETWORK_SCAN.ICMP_DISCOVERY"
    NETWORK_SCAN_SYN_STEALTH     = "NETWORK_SCAN.SYN_STEALTH"
    NETWORK_SCAN_UDP_SWEEP       = "NETWORK_SCAN.UDP_SWEEP"
    NETWORK_SCAN_VERSION_DETECT  = "NETWORK_SCAN.VERSION_DETECT"
    NETWORK_SCAN_OS_DETECT       = "NETWORK_SCAN.OS_DETECT"
    NETWORK_SCAN_FULL_PORT       = "NETWORK_SCAN.FULL_PORT"

    # EXPLOITATION sub-intents
    EXPLOITATION_RCE             = "EXPLOITATION.REMOTE_CODE_EXEC"
    EXPLOITATION_PRIV_ESC        = "EXPLOITATION.PRIV_ESC"
    EXPLOITATION_LATERAL         = "EXPLOITATION.LATERAL_MOVEMENT"
    EXPLOITATION_PERSISTENCE     = "EXPLOITATION.PERSISTENCE"

    # VULNERABILITY_AUDIT sub-intents
    VULN_AUDIT_CVE_SPECIFIC      = "VULNERABILITY_AUDIT.CVE_SPECIFIC"
    VULN_AUDIT_SERVICE_SPECIFIC  = "VULNERABILITY_AUDIT.SERVICE_SPECIFIC"
    VULN_AUDIT_FULL_SCAN         = "VULNERABILITY_AUDIT.FULL_SCAN"

    # SERVICE_ENUMERATION sub-intents
    SERVICE_ENUM_BANNER_GRAB     = "SERVICE_ENUMERATION.BANNER_GRAB"
    SERVICE_ENUM_VERSION_DETECT  = "SERVICE_ENUMERATION.VERSION_DETECT"
    SERVICE_ENUM_SMB             = "SERVICE_ENUMERATION.SMB"
    SERVICE_ENUM_SNMP            = "SERVICE_ENUMERATION.SNMP"

    # PASSWORD_ATTACK sub-intents
    PASSWORD_BRUTE_FORCE         = "PASSWORD_ATTACK.BRUTE_FORCE"
    PASSWORD_SPRAY               = "PASSWORD_ATTACK.SPRAY"
    PASSWORD_CREDENTIAL_STUFFING = "PASSWORD_ATTACK.CREDENTIAL_STUFFING"

    # PASSIVE_RECON sub-intents
    PASSIVE_RECON_DNS            = "PASSIVE_RECON.DNS"
    PASSIVE_RECON_WHOIS          = "PASSIVE_RECON.WHOIS"
    PASSIVE_RECON_OSINT          = "PASSIVE_RECON.OSINT"

    # DIRECTORY_BRUTEFORCE sub-intents
    DIR_BRUTE_WEB                = "DIRECTORY_BRUTEFORCE.WEB"
    DIR_BRUTE_API                = "DIRECTORY_BRUTEFORCE.API"
    DIR_BRUTE_FILES              = "DIRECTORY_BRUTEFORCE.FILES"


# --- SECTION 2: Secondary Intent Item ---

class SecondaryIntent(BaseModel):
    """A secondary intent detected in a compound command."""
    model_config = {"extra": "forbid"}

    intent: IntentType
    confidence: float = Field(..., ge=0.0, le=1.0)
    target: Optional[Target] = None


# --- SECTION 3: XAI Token ---

class XAIToken(BaseModel):
    """Token-level attribution entry for explainability output."""
    model_config = {"extra": "forbid"}

    token: str
    score: float = Field(..., ge=0.0, le=1.0)
    entity: Optional[str] = None


# --- SECTION 4: XAI Block ---

class XAIBlock(BaseModel):
    """Explainability output block — only present when X-IRE-Explain: true."""
    model_config = {"extra": "forbid"}

    method: str = "integrated_gradients"
    top_tokens: List[XAIToken] = Field(default_factory=list)
    decision_path: Optional[str] = None


# --- SECTION 5: Extended IREResponse V2 ---

class IREResponseV2(BaseModel):
    """
    Extended API response — Schema Version 2.
    Returned when X-IRE-Schema-Version: 2 header is present.
    Includes all v1 fields plus enhancement fields.
    All new fields are Optional and default to None/[].
    """
    model_config = {"extra": "ignore"}

    # === V1 fields (identical to IREResponse) ===
    status: str
    intent: Optional[IntentType] = None
    target: Optional[Target] = None
    ports: List[int] = Field(default_factory=list)
    modifiers: List[str] = Field(default_factory=list)
    cve_ids: List[str] = Field(default_factory=list)
    tool_hint: Optional[str] = None
    schedule: Optional[str] = None
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    rejection_reason: Optional[str] = None
    scope_warnings: List[str] = Field(default_factory=list)
    latency_ms: Optional[int] = None
    error: Optional[str] = None
    stage: Optional[str] = None
    field: Optional[str] = None
    detail: Optional[str] = None

    # === V2 enhancement fields ===
    sub_intent: Optional[SubIntentType] = None
    secondary_intents: List[SecondaryIntent] = Field(default_factory=list)
    clarification_request: Optional[str] = None
    uncertainty_band: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    calibration_method: Optional[str] = None
    cache_hit: Optional[str] = None        # "exact" | "semantic" | None
    rbac_role: Optional[str] = None        # role that was used
    session_turns: Optional[int] = None    # number of turns in session
    xai: Optional[XAIBlock] = None
    schema_version: int = 2

    @classmethod
    def from_v1(cls, v1: "IREResponse", **kwargs) -> "IREResponseV2":
        """Upgrade a v1 IREResponse to v2 by copying all fields."""
        data = v1.model_dump()
        data.update(kwargs)
        data["schema_version"] = 2
        return cls(**data)

    @classmethod
    def error_response(
        cls,
        error: str,
        stage: str,
        detail: str,
        latency_ms: int,
        field: Optional[str] = None,
    ) -> "IREResponseV2":
        return cls(
            status="error",
            error=error,
            stage=stage,
            field=field,
            detail=detail,
            latency_ms=latency_ms,
            schema_version=2,
        )


# --- SECTION 6: Extended ParseRequest V2 ---

class ParseRequestV2(BaseModel):
    """
    Extended request body — Schema Version 2.
    Adds role and session_history to the base ParseRequest.
    """
    model_config = {"extra": "ignore"}

    command: str = Field(
        ...,
        description="Raw natural language command from the operator"
    )
    session_id: Optional[str] = Field(
        default=None,
        description="Session identifier for multi-turn context"
    )
    role: str = Field(
        default="analyst",
        description="Caller role for RBAC enforcement"
    )
    explain: bool = Field(
        default=False,
        description="Request XAI token attribution (adds ~200ms latency)"
    )


# --- SECTION 7: RBAC Error ---

class RBACError(IREError):
    """Raised when a caller's role is not permitted for the detected intent."""
    def __init__(self, message: str, role: str, intent: str):
        super().__init__(message, stage="rbac_guard")
        self.role = role
        self.denied_intent = intent


# --- SECTION 8: Update __all__ export list ---

__all__ = [
    # Enums
    "IntentType", "TargetType", "SubIntentType",
    # Models
    "Target", "IntentSchema", "SecondaryIntent",
    "XAIToken", "XAIBlock",
    # Requests
    "ParseRequest", "ParseRequestV2",
    # Responses
    "IREResponse", "IREResponseV2",
    # Errors
    "IREError", "JSONParseError", "SchemaValidationError",
    "RegexValidationError", "ScopeError", "InferenceError",
    "NetworkValidationError", "RBACError",
]
