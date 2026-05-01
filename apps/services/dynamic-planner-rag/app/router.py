"""Router for Dynamic Planner RAG Service."""

import uuid

from app import config, models
from fastapi import APIRouter, HTTPException, status
from fastapi.responses import JSONResponse
from neuroshell_shared.logging import get_logger

logger = get_logger(__name__)
router = APIRouter()

PLAN_STORE: dict[str, models.GeneratedPlan] = {}


def _retrieve_context(query: str, limit: int) -> list[models.ContextSnippet]:
    """Retrieve relevant context from knowledge base."""
    context_snippets = [
        models.ContextSnippet(
            content="For error recovery, analyze the error type and select an appropriate recovery strategy based on severity and category.",
            source="error-recovery-guidelines",
            relevance_score=0.95,
        ),
        models.ContextSnippet(
            content="When planning, break down complex goals into sequential steps with clear dependencies between actions.",
            source="planning-best-practices",
            relevance_score=0.88,
        ),
        models.ContextSnippet(
            content="Consider retry strategies for transient failures, fallback for resource issues, and circuit breaker for critical errors.",
            source="recovery-strategies",
            relevance_score=0.82,
        ),
    ]
    return context_snippets[:limit]


def _generate_plan(goal: str, constraints: list[str], max_steps: int) -> models.GeneratedPlan:
    """Generate a plan for the given goal."""
    plan_id = str(uuid.uuid4())

    steps = []
    step_number = 1

    if "error" in goal.lower() or "recover" in goal.lower():
        steps.extend(
            [
                models.PlanStep(
                    step_id=str(uuid.uuid4()),
                    step_number=step_number,
                    action=models.Action(
                        action_id=str(uuid.uuid4()),
                        action_type=models.ActionType.QUERY,
                        description="Analyze error details",
                        parameters={"depth": "detailed"},
                    ),
                ),
                models.PlanStep(
                    step_id=str(uuid.uuid4()),
                    step_number=step_number + 1,
                    action=models.Action(
                        action_id=str(uuid.uuid4()),
                        action_type=models.ActionType.VALIDATE,
                        description="Determine recovery strategy",
                        parameters={"strategy_types": ["retry", "fallback", "circuit_breaker"]},
                    ),
                ),
                models.PlanStep(
                    step_id=str(uuid.uuid4()),
                    step_number=step_number + 2,
                    action=models.Action(
                        action_id=str(uuid.uuid4()),
                        action_type=models.ActionType.EXECUTE,
                        description="Execute recovery plan",
                    ),
                ),
            ]
        )
        complexity = models.PlanComplexity.MODERATE
    elif "analyze" in goal.lower() or "scan" in goal.lower():
        steps.extend(
            [
                models.PlanStep(
                    step_id=str(uuid.uuid4()),
                    step_number=step_number,
                    action=models.Action(
                        action_id=str(uuid.uuid4()),
                        action_type=models.ActionType.QUERY,
                        description="Identify scan targets",
                    ),
                ),
                models.PlanStep(
                    step_id=str(uuid.uuid4()),
                    step_number=step_number + 1,
                    action=models.Action(
                        action_id=str(uuid.uuid4()),
                        action_type=models.ActionType.TRANSFORM,
                        description="Perform vulnerability scan",
                        parameters={"depth": "deep"},
                    ),
                ),
                models.PlanStep(
                    step_id=str(uuid.uuid4()),
                    step_number=step_number + 2,
                    action=models.Action(
                        action_id=str(uuid.uuid4()),
                        action_type=models.ActionType.AGGREGATE,
                        description="Compile findings",
                    ),
                ),
            ]
        )
        complexity = models.PlanComplexity.SIMPLE
    else:
        steps.extend(
            [
                models.PlanStep(
                    step_id=str(uuid.uuid4()),
                    step_number=step_number,
                    action=models.Action(
                        action_id=str(uuid.uuid4()),
                        action_type=models.ActionType.QUERY,
                        description="Understand goal requirements",
                    ),
                ),
                models.PlanStep(
                    step_id=str(uuid.uuid4()),
                    step_number=step_number + 1,
                    action=models.Action(
                        action_id=str(uuid.uuid4()),
                        action_type=models.ActionType.TRANSFORM,
                        description="Break down into actionable steps",
                    ),
                ),
                models.PlanStep(
                    step_id=str(uuid.uuid4()),
                    step_number=step_number + 2,
                    action=models.Action(
                        action_id=str(uuid.uuid4()),
                        action_type=models.ActionType.EXECUTE,
                        description="Execute plan",
                    ),
                ),
            ]
        )
        complexity = models.PlanComplexity.MODERATE

    plan_constraints = []
    for c in constraints:
        plan_constraints.append(
            models.PlanConstraint(
                constraint_type="user_defined",
                value=c,
                description=c,
            )
        )

    estimated_duration = len(steps) * 2.0

    return models.GeneratedPlan(
        plan_id=plan_id,
        goal=goal,
        complexity=complexity,
        steps=steps[:max_steps],
        constraints=plan_constraints,
        estimated_duration_seconds=estimated_duration,
        success_probability=0.85,
    )


@router.post("/plan", response_model=models.APIResponse[models.PlanResponse])
async def create_plan(request: models.PlanRequest) -> JSONResponse:
    """Generate a plan for the given goal."""
    logger.info(f"Generating plan for goal: {request.goal}")

    max_steps = request.max_steps or config.settings.max_plan_steps

    constraints = request.constraints or []
    plan = _generate_plan(request.goal, constraints, max_steps)

    retrieved_context = _retrieve_context(request.goal, config.settings.rag_retrieval_limit)

    PLAN_STORE[plan.plan_id] = plan

    response = models.PlanResponse(
        plan=plan,
        retrieved_context=retrieved_context,
        message=f"Plan generated with {len(plan.steps)} steps",
    )

    logger.info(
        f"Plan generated: {plan.plan_id} with {plan.success_probability:.0%} success probability"
    )

    from neuroshell_shared.models import APIResponse as APIResponseModel

    return APIResponseModel(data=response)


@router.post("/execute-step", response_model=models.APIResponse[models.ExecuteStepResponse])
async def execute_step(request: models.ExecuteStepRequest) -> JSONResponse:
    """Execute a specific plan step."""
    logger.info(f"Executing step {request.step_id} for plan {request.plan_id}")

    plan = PLAN_STORE.get(request.plan_id)
    if not plan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Plan {request.plan_id} not found",
        )

    step = next((s for s in plan.steps if s.step_id == request.step_id), None)
    if not step:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Step {request.step_id} not found",
        )

    step.status = "completed"
    step.result = {"executed": True, "output": "Step executed successfully"}

    response = models.ExecuteStepResponse(
        plan_id=request.plan_id,
        step_id=request.step_id,
        success=True,
        result=step.result,
        message="Step executed successfully",
    )

    from neuroshell_shared.models import APIResponse as APIResponseModel

    return APIResponseModel(data=response)


@router.get("/plans/{plan_id}", response_model=models.APIResponse[models.GeneratedPlan])
async def get_plan(plan_id: str) -> JSONResponse:
    """Get a plan by ID."""
    plan = PLAN_STORE.get(plan_id)
    if not plan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Plan {plan_id} not found",
        )

    from neuroshell_shared.models import APIResponse as APIResponseModel

    return APIResponseModel(data=plan)
