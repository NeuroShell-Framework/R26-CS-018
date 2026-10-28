from pydantic import BaseModel, Field
from typing import List, Optional, Literal


class PlannerOutput(BaseModel):
    model_config = {"extra": "ignore"}

    command: str
    tool: str
    session_id: str
    intent_ref: str
    estimated_duration: str = "medium"


class RawExecutionResult(BaseModel):
    command: str
    stdout: str
    stderr: str
    exit_code: int
    timed_out: bool = False


class ErrorContext(BaseModel):
    session_id: str
    command: str
    stdout: str = ""
    stderr: str
    exit_code: int
    tool: str
    intent_ref: str
    attempt_number: int = 1
    prior_strategies: List[str] = []
    silent_failure: bool = False


class RecoveryPlan(BaseModel):
    error_class: Literal[
        'TOOL_NOT_INSTALLED', 'PERMISSION_DENIED', 'NETWORK_UNREACHABLE',
        'WRONG_SYNTAX', 'RESOURCE_EXHAUSTION', 'AUTH_FAILURE',
        'TIMEOUT', 'VERSION_MISMATCH', 'UNKNOWN'
    ]
    root_cause: str = Field(min_length=10, max_length=500)
    strategy: Literal[
        'INSTALL_TOOL', 'ADD_SUDO', 'ADJUST_PARAMETERS',
        'TOOL_SUBSTITUTION', 'FIX_SYNTAX', 'ADJUST_TIMEOUT',
        'FIX_AUTH', 'VERSION_DOWNGRADE', 'ESCALATE'
    ]
    corrected_command: str = Field(min_length=3, max_length=1000)
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str


class SafetyCheckResult(BaseModel):
    approved: bool
    danger_words_found: List[str] = []
    scope_violation: bool = False
    confidence_too_low: bool = False
    reason: str = ''


class RecoveryLogEntry(BaseModel):
    attempt: int
    error_class: str
    strategy: str
    clf_method: str
    confidence: float
    original_command: str = ''
    corrected_command: str = ''


class CorrectionEntry(BaseModel):
    """One entry in the correction history — shows what was tried per attempt."""
    attempt: int
    original_command: str
    corrected_command: str
    error_class: str
    strategy: str
    approved: bool
    correction_source: str = ''  # 'dataset', 'llm', 'rule-based'


class ExecutionResult(BaseModel):
    session_id: str
    status: Literal['success', 'recovered', 'failed']
    command_executed: str
    stdout: str
    stderr: str
    exit_code: int
    recovery_log: List[RecoveryLogEntry] = []
    correction_history: List[CorrectionEntry] = []
    failure_report: Optional[dict] = None
    tool_substituted: bool = False
    latency_ms: int
