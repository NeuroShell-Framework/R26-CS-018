# NeuroShell IRE — Hallucination Taxonomy
# Define hallucination categories and audit validation finding schema

from enum import Enum
from typing import Optional, Literal
from pydantic import BaseModel, Field


class HallucinationClass(str, Enum):
    FABRICATED_CVE = "FABRICATED_CVE"
    TARGET_TYPE_MISMATCH = "TARGET_TYPE_MISMATCH"
    CONTRADICTORY_ACTION_TARGET = "CONTRADICTORY_ACTION_TARGET"
    FABRICATED_PARAMETER = "FABRICATED_PARAMETER"
    UNGROUNDED_CONFIDENCE = "UNGROUNDED_CONFIDENCE"
    OUT_OF_SCOPE_TARGET = "OUT_OF_SCOPE_TARGET"


class ValidationFinding(BaseModel):
    """
    Audit record for a specific validation check executed in the pipeline.
    Captures both passed checks and failed findings with assigned hallucination class.
    """
    model_config = {"extra": "forbid"}

    validator: str = Field(..., description="Name of the validator component performing the check")
    passed: bool = Field(..., description="True if the check passed, False if violated")
    hallucination_class: Optional[HallucinationClass] = Field(
        default=None,
        description="Assigned hallucination taxonomy class if check failed"
    )
    detail: str = Field(..., description="Detailed description of the check result or violation")
    severity: Literal["block", "warn", "escalate"] = Field(
        default="block",
        description="Severity action: 'block' halts execution, 'warn' is advisory, 'escalate' routes to human review"
    )


__all__ = ["HallucinationClass", "ValidationFinding"]
