"""Request and response models for Dynamic Planner RAG Service."""

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class PlanComplexity(str, Enum):
    """Plan complexity levels."""

    SIMPLE = "simple"
    MODERATE = "moderate"
    COMPLEX = "complex"


class ActionType(str, Enum):
    """Action types for planning."""

    EXECUTE = "execute"
    QUERY = "query"
    TRANSFORM = "transform"
    AGGREGATE = "aggregate"
    VALIDATE = "validate"


class Action(BaseModel):
    """Plan action."""

    action_id: str
    action_type: ActionType
    description: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    dependencies: list[str] = Field(default_factory=list)
    estimated_duration_seconds: float = 0.0


class PlanStep(BaseModel):
    """Plan step."""

    step_id: str
    step_number: int
    action: Action
    status: str = "pending"
    result: dict[str, Any] | None = None


class PlanConstraint(BaseModel):
    """Plan constraint."""

    constraint_type: str
    value: Any
    description: str | None = None


class PlanningContext(BaseModel):
    """Planning context."""

    user_id: str | None = None
    session_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class GeneratedPlan(BaseModel):
    """Generated plan."""

    plan_id: str
    goal: str
    complexity: PlanComplexity
    steps: list[PlanStep]
    constraints: list[PlanConstraint] = Field(default_factory=list)
    estimated_duration_seconds: float
    success_probability: float = Field(..., ge=0.0, le=1.0)
    fallback_plans: list[str] = Field(default_factory=list)


class ContextSnippet(BaseModel):
    """Retrieved context snippet."""

    content: str
    source: str
    relevance_score: float


class PlanRequest(BaseModel):
    """Plan request."""

    goal: str
    context: str | None = None
    constraints: list[str] = Field(default_factory=list)
    max_steps: int | None = None


class PlanResponse(BaseModel):
    """Plan response."""

    plan: GeneratedPlan
    retrieved_context: list[ContextSnippet]
    message: str


class ExecuteStepRequest(BaseModel):
    """Execute step request."""

    plan_id: str
    step_id: str


class ExecuteStepResponse(BaseModel):
    """Execute step response."""

    plan_id: str
    step_id: str
    success: bool
    result: dict[str, Any] | None = None
    message: str
