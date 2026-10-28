import re
from typing import List, Optional
from pydantic import BaseModel, Field, field_validator
from src.schemas.intent_schema import IntentType, SubIntentType


class PlannerTarget(BaseModel):
    model_config = {"extra": "forbid"}

    type: str = Field(
        ...,
        description="IP | SUBNET | DOMAIN | URL | HOSTNAME | UNKNOWN",
    )
    value: str = Field(
        ...,
        description="Exact target string from operator input",
    )

    @field_validator("type")
    @classmethod
    def validate_type(cls, v: str) -> str:
        allowed = {"IP", "SUBNET", "DOMAIN", "URL", "HOSTNAME", "UNKNOWN"}
        if v not in allowed:
            raise ValueError(
                f"target.type must be one of {allowed}, got '{v}'"
            )
        return v


class PlannerContract(BaseModel):
    model_config = {"extra": "forbid"}

    intent: IntentType = Field(
        ...,
        description=(
            "Top-level intent class. One of: NETWORK_SCAN, "
            "VULNERABILITY_AUDIT, DIRECTORY_BRUTEFORCE, "
            "SERVICE_ENUMERATION, EXPLOITATION, PASSWORD_ATTACK, "
            "PASSIVE_RECON, AMBIGUOUS, REJECTED"
        ),
    )

    sub_intent: Optional[SubIntentType] = Field(
        default=None,
        description=(
            "Hierarchical sub-classification. "
            "Most important field for C02 command construction. "
            "Examples: NETWORK_SCAN.SYN_STEALTH -> nmap -sS, "
            "NETWORK_SCAN.UDP_SWEEP -> nmap -sU, "
            "SERVICE_ENUMERATION.SMB -> enum4linux"
        ),
    )

    target: PlannerTarget = Field(
        ...,
        description="Validated target specification",
    )

    ports: List[int] = Field(
        default_factory=list,
        description=(
            "Port numbers as integers. "
            "C02 formats as comma-separated string for tool flags. "
            "Empty list = use tool default ports."
        ),
    )

    modifiers: List[str] = Field(
        default_factory=list,
        description=(
            "Semantic modifiers extracted from operator input. "
            "Values: stealth, aggressive, verbose, recursive, etc. "
            "C02 maps these to tool-specific flags."
        ),
    )

    cve_ids: List[str] = Field(
        default_factory=list,
        description=(
            "CVE IDs explicitly mentioned in operator input. "
            "C02 uses these to select nuclei templates or "
            "Metasploit modules."
        ),
    )

    tool_hint: Optional[str] = Field(
        default=None,
        description=(
            "Suggested tool from IRE semantic analysis. "
            "C02 uses this as a starting point but may override "
            "based on its own tool selection logic."
        ),
    )

    schedule: Optional[str] = Field(
        default=None,
        description=(
            "Cron expression if operator specified scheduling. "
            "None = execute immediately. "
            "C02 handles scheduling logic."
        ),
    )

    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description=(
            "IRE classification confidence score. "
            "C02 should request operator clarification if < 0.6."
        ),
    )

    rejection_reason: Optional[str] = Field(
        default=None,
        description=(
            "Populated when intent is REJECTED or AMBIGUOUS. "
            "C02 must not execute commands for rejected intents."
        ),
    )

    scope_warnings: List[str] = Field(
        default_factory=list,
        description=(
            "Scope and architecture warnings from IRE validation. "
            "Includes SCOPE_WARNING (public IP) and ARCH_WARNING "
            "(CIDR too wide, target out of engagement scope). "
            "C02 must surface these to operator before execution."
        ),
    )

    session_id: Optional[str] = Field(
        default=None,
        description=(
            "Session identifier for multi-turn context tracking. "
            "C02 uses this to correlate commands within a session."
        ),
    )

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, v: List[int]) -> List[int]:
        for port in v:
            if not (1 <= port <= 65535):
                raise ValueError(
                    f"Port {port} out of valid range [1, 65535]"
                )
        return v

    @field_validator("cve_ids")
    @classmethod
    def validate_cve_format(cls, v: List[str]) -> List[str]:
        pattern = re.compile(r"^CVE-\d{4}-\d{4,7}$")
        for cve in v:
            if not pattern.match(cve):
                raise ValueError(
                    f"Invalid CVE format: '{cve}'. "
                    f"Expected CVE-YYYY-NNNNN"
                )
        return v

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        return round(v, 4)

    @property
    def is_executable(self) -> bool:
        if self.intent in (IntentType.REJECTED, IntentType.AMBIGUOUS):
            return False
        blocking = [w for w in self.scope_warnings
                    if "SCOPE_VIOLATION" in w or "ARCH_WARNING" in w]
        return len(blocking) == 0

    @property
    def is_immediate(self) -> bool:
        return self.schedule is None

    @property
    def has_scope_issues(self) -> bool:
        return len(self.scope_warnings) > 0
