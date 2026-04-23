"""Router for Intent Recognition Service."""

import time
import uuid
from typing import Dict, Any

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import JSONResponse

from neuroshell_shared.logging import get_logger

from app import config, models

logger = get_logger(__name__)
router = APIRouter()


def _recognize_intent(text: str, context: str = None) -> tuple[models.RecognizedIntent, list[models.IntentAlternative]]:
    """Recognize intent from text."""
    text_lower = text.lower()

    intent_patterns = {
        (models.IntentType.RECOVER_ERROR, models.IntentCategory.ERROR_RECOVERY): [
            "error", "fail", "exception", "recover", "fix", "retry", "crash", "broken"
        ],
        (models.IntentType.SCAN_VULNERABILITY, models.IntentCategory.VULNERABILITY_SCAN): [
            "vulnerability", "scan", "security", "threat", "risk", "exploit", "hack"
        ],
        (models.IntentType.CREATE_PLAN, models.IntentCategory.PLANNING): [
            "plan", "plan", "schedule", "organize", "arrange", "prepare"
        ],
        (models.IntentType.ANALYZE, models.IntentCategory.ANALYSIS): [
            "analyze", "analysis", "analyse", "examine", "review", "inspect", "check"
        ],
        (models.IntentType.QUERY, models.IntentCategory.QUERY): [
            "what", "how", "why", "when", "where", "who", "query", "find", "search"
        ],
    }

    best_intent = None
    best_confidence = 0.0
    matched_phrases = []

    for (intent_type, category), keywords in intent_patterns.items():
        matches = [kw for kw in keywords if kw in text_lower]
        if matches:
            confidence = min(len(matches) * 0.25, 0.95)
            if confidence > best_confidence:
                best_confidence = confidence
                matched_phrases = matches
                best_intent = models.RecognizedIntent(
                    intent_type=intent_type,
                    intent_category=category,
                    confidence=confidence,
                    parameters=[],
                    reasoning=f"Matched keywords: {', '.join(matches)}",
                    matched_phrases=matches,
                )

    if not best_intent or best_confidence < config.settings.intent_confidence_threshold:
        best_intent = models.RecognizedIntent(
            intent_type=models.IntentType.QUERY,
            intent_category=models.IntentCategory.UNKNOWN,
            confidence=0.5,
            parameters=[],
            reasoning="No clear intent matched, defaulting to query",
            matched_phrases=[],
        )

    alternatives = []
    if best_intent.intent_type != models.IntentType.QUERY:
        alternatives.append(models.IntentAlternative(
            intent_type=models.IntentType.QUERY,
            confidence=0.3,
            reason="Alternative interpretation",
        ))
    if best_intent.intent_type != models.IntentType.ANALYZE:
        alternatives.append(models.IntentAlternative(
            intent_type=models.IntentType.ANALYZE,
            confidence=0.25,
            reason="Could be analysis request",
        ))

    if config.settings.enable_fuzzy_matching and best_confidence < 0.6:
        if "error" in text_lower or "fail" in text_lower:
            best_intent.confidence = max(best_intent.confidence, 0.65)
            best_intent.reasoning = "Fuzzy matched to error recovery"

    alternatives.sort(key=lambda x: x.confidence, reverse=True)

    return best_intent, alternatives[:3]


@router.post("/recognize", response_model=models.APIResponse[models.RecognizeResponse])
async def recognize(request: models.RecognizeRequest) -> JSONResponse:
    """Recognize intent from input text."""
    logger.info(f"Recognizing intent for: {request.text[:50]}...")

    start_time = time.time()

    intent, alternatives = _recognize_intent(request.text, request.context or "")

    processing_time = (time.time() - start_time) * 1000

    metadata = models.IntentMetadata(
        processing_time_ms=processing_time,
        model_version=config.settings.app_version,
        language="en",
    )

    response = models.RecognizeResponse(
        intent=intent,
        alternatives=alternatives if request.return_alternatives else [],
        metadata=metadata,
        message=f"Intent recognized with {intent.confidence:.0%} confidence",
    )

    logger.info(f"Intent recognized: {intent.intent_type.value} ({intent.confidence:.0%}) in {processing_time:.1f}ms")

    from neuroshell_shared.models import APIResponse as APIResponseModel

    return APIResponseModel(data=response)


@router.post("/batch-recognize", response_model=models.APIResponse[models.BatchRecognizeResponse])
async def batch_recognize(request: models.BatchRecognizeRequest) -> JSONResponse:
    """Batch recognize intents from multiple texts."""
    logger.info(f"Batch recognizing {len(request.texts)} texts")

    results = []
    for text in request.texts:
        intent, _ = _recognize_intent(text, request.context or "")
        results.append(intent)

    response = models.BatchRecognizeResponse(
        results=results,
        processed_count=len(results),
        message=f"Processed {len(results)} texts",
    )

    from neuroshell_shared.models import APIResponse as APIResponseModel

    return APIResponseModel(data=response)


@router.get("/intents", response_model=models.APIResponse[list[str]])
async def list_intents() -> JSONResponse:
    """List supported intents."""
    intents = [i.value for i in models.IntentType]
    from neuroshell_shared.models import APIResponse as APIResponseModel

    return APIResponseModel(data=intents)