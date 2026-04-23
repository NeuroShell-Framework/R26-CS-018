"""Request and response models for Dynamic Planner RAG Service."""

from enum import Enum
from typing import Any, Dict, List, Optional

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
    parameters: Dict[str, Any] = Field(default_factory=dict)
    dependencies: List[str] = Field(default_factory=list)
    estimated_duration_seconds: float = 0.0


class PlanStep(BaseModel):
    """Plan step."""

    step_id: str
    step_number: int
    action: Action
    status: str = "pending"
    result: Optional[Dict[str, Any]] = None


class PlanConstraint(BaseModel):
    """Plan constraint."""

    constraint_type: str
    value: Any
    description: Optional[str] = None


class PlanningContext(BaseModel):
    """Planning context."""

    user_id: Optional[str] = None
    session_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class GeneratedPlan(BaseModel):
    """Generated plan."""

    plan_id: str
    goal: str
    complexity: PlanComplexity
    steps: List[PlanStep]
    constraints: List[PlanConstraint] = Field(default_factory=list)
    estimated_duration_seconds: float
    success_probability: float = Field(..., ge=0.0, le=1.0)
    fallback_plans: List[str] = Field(default_factory=list)


class ContextSnippet(BaseModel):
    """Retrieved context snippet."""

    content: str
    source: str
    relevance_score: float


class PlanRequest(BaseModel):
    """Plan request."""

    goal: str
    context: Optional[str] = None
    constraints: List[str] = Field(default_factory=list)
    max_steps: Optional[int] = None


class PlanResponse(BaseModel):
    """Plan response."""

    plan: GeneratedPlan
    retrieved_context: List[ContextSnippet]
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
    result: Optional[Dict[str, Any]] = None
    message: str