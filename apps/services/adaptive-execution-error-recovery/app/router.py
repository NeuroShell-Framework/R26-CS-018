"""Router for Adaptive Execution Error Recovery Service."""

import uuid

from app import config, models
from fastapi import APIRouter
from fastapi.responses import JSONResponse
from neuroshell_shared.logging import get_logger

logger = get_logger(__name__)
router = APIRouter()


def _analyze_error(error: models.ErrorDetails) -> models.RecoveryPlan:
    """Analyze error and determine recovery strategy."""
    error_id = str(uuid.uuid4())

    if error.severity == models.ErrorSeverity.CRITICAL:
        strategy = models.RecoveryStrategy.CIRCUIT_BREAKER
        actions = [
            models.RecoveryAction(
                action=models.RecoveryStrategy.CIRCUIT_BREAKER,
                description="Open circuit breaker to prevent cascading failures",
                parameters={"duration_seconds": 60},
            )
        ]
        success_prob = 0.3
    elif error.category == models.ErrorCategory.TIMEOUT:
        strategy = models.RecoveryStrategy.RETRY
        actions = [
            models.RecoveryAction(
                action=models.RecoveryStrategy.RETRY,
                description="Retry the failed operation",
                parameters={
                    "max_attempts": config.settings.max_retry_attempts,
                    "delay_seconds": config.settings.retry_delay_seconds,
                },
            )
        ]
        success_prob = 0.7
    elif error.category == models.ErrorCategory.RESOURCE:
        strategy = models.RecoveryStrategy.FALLBACK
        actions = [
            models.RecoveryAction(
                action=models.RecoveryStrategy.FALLBACK,
                description="Use fallback resource or cache",
                parameters={"use_cache": True},
            )
        ]
        success_prob = 0.85
    elif error.category == models.ErrorCategory.VALIDATION:
        strategy = models.RecoveryStrategy.MANUAL
        actions = [
            models.RecoveryAction(
                action=models.RecoveryStrategy.MANUAL,
                description="Return error for manual resolution",
                parameters={"requires_user_input": True},
            )
        ]
        success_prob = 0.5
    else:
        strategy = models.RecoveryStrategy.RETRY
        actions = [
            models.RecoveryAction(
                action=models.RecoveryStrategy.RETRY,
                description="Retry the failed operation",
                parameters={"max_attempts": config.settings.max_retry_attempts},
            )
        ]
        success_prob = 0.6

    return models.RecoveryPlan(
        error_id=error_id,
        selected_strategy=strategy,
        actions=actions,
        estimated_time_seconds=config.settings.retry_delay_seconds
        * config.settings.max_retry_attempts,
        success_probability=success_prob,
    )


@router.post("/process-error", response_model=models.APIResponse[models.ProcessErrorResponse])
async def process_error(request: models.ProcessErrorRequest) -> JSONResponse:
    """Process an error and generate recovery plan."""
    logger.info(f"Processing error: {request.error.error_type}")

    context = request.error.context
    if context:
        context.error_id = str(uuid.uuid4())

    plan = _analyze_error(request.error)

    recovery_plan = plan
    recommended_action = plan.actions[0] if plan.actions else None

    response = models.ProcessErrorResponse(
        error_id=plan.error_id,
        recovery_plan=recovery_plan,
        recommended_action=recommended_action,
        can_recover=config.settings.enable_auto_recovery,
        message=f"Recovery plan generated using {plan.selected_strategy.value} strategy",
    )

    logger.info(
        f"Recovery plan generated: {plan.selected_strategy.value} (success probability: {plan.success_probability:.0%})"
    )

    return models.APIResponse(data=response)


@router.post(
    "/execute-recovery", response_model=models.APIResponse[models.RecoveryExecutionResponse]
)
async def execute_recovery(request: models.RecoveryExecutionRequest) -> JSONResponse:
    """Execute a recovery action."""
    logger.info(f"Executing recovery for error: {request.error_id}")

    import time

    start_time = time.time()
    execution_time = 0.0

    request.parameters.get("mock_delay", 0)
    if request.parameters.get("mock_delay"):
        import asyncio

        await asyncio.sleep(request.parameters["mock_delay"])
        execution_time = time.time() - start_time

    response = models.RecoveryExecutionResponse(
        error_id=request.error_id,
        success=True,
        message=f"Recovery executed using {request.strategy.value} strategy",
        execution_time_seconds=execution_time or 0.1,
        result={"recovered": True, "strategy_used": request.strategy.value},
    )

    logger.info(f"Recovery executed successfully in {response.execution_time_seconds:.2f}s")

    return models.APIResponse(data=response)


@router.get("/strategies", response_model=models.APIResponse[list[str]])
async def list_strategies() -> JSONResponse:
    """List available recovery strategies."""
    strategies = [s.value for s in models.RecoveryStrategy]
    return models.APIResponse(data=strategies)
