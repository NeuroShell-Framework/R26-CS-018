"""Request and response models for Adaptive Execution Error Recovery Service."""

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ErrorSeverity(str, Enum):
    """Error severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ErrorCategory(str, Enum):
    """Error categories."""

    TIMEOUT = "timeout"
    RESOURCE = "resource"
    VALIDATION = "validation"
    AUTHENTICATION = "authentication"
    NETWORK = "network"
    UNKNOWN = "unknown"


class ErrorContext(BaseModel):
    """Error context information."""

    error_id: str | None = None
    timestamp: str | None = None
    service_name: str | None = None
    request_id: str | None = None
    user_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ErrorDetails(BaseModel):
    """Error details."""

    error_type: str
    message: str
    stack_trace: str | None = None
    severity: ErrorSeverity = ErrorSeverity.MEDIUM
    category: ErrorCategory = ErrorCategory.UNKNOWN
    context: ErrorContext = Field(default_factory=ErrorContext)


class RecoveryStrategy(str, Enum):
    """Recovery strategy types."""

    RETRY = "retry"
    FALLBACK = "fallback"
    CIRCUIT_BREAKER = "circuit_breaker"
    QUEUE = "queue"
    MANUAL = "manual"


class RecoveryAction(BaseModel):
    """Recovery action details."""

    action: RecoveryStrategy
    description: str
    parameters: dict[str, Any] = Field(default_factory=dict)


class RecoveryPlan(BaseModel):
    """Recovery plan."""

    error_id: str
    selected_strategy: RecoveryStrategy
    actions: list[RecoveryAction]
    estimated_time_seconds: float
    success_probability: float = Field(..., ge=0.0, le=1.0)


class ProcessErrorRequest(BaseModel):
    """Process error request."""

    error: ErrorDetails
    user_context: dict[str, Any] | None = None


class ProcessErrorResponse(BaseModel):
    """Process error response."""

    error_id: str
    recovery_plan: RecoveryPlan
    recommended_action: RecoveryAction
    can_recover: bool
    message: str


class RecoveryExecutionRequest(BaseModel):
    """Recovery execution request."""

    error_id: str
    strategy: RecoveryStrategy
    parameters: dict[str, Any] = Field(default_factory=dict)


class RecoveryExecutionResponse(BaseModel):
    """Recovery execution response."""

    error_id: str
    success: bool
    message: str
    execution_time_seconds: float
    result: dict[str, Any] | None = None
