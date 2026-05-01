"""Router for Intent Recognition Service."""

import time
import uuid
from typing import Optional
from collections import defaultdict

from fastapi import APIRouter, HTTPException, status, Request
from fastapi.responses import JSONResponse

from neuroshell_shared.logging import get_logger

from app import config, models
from app.ml import get_classifier

logger = get_logger(__name__)
router = APIRouter()

_statistics = {
    "total_predictions": 0,
    "predictions_by_intent": defaultdict(int),
    "processing_times": [],
}


def _keyword_based_intent(text: str) -> tuple[models.IntentType, models.IntentCategory, float]:
    """Fallback keyword-based intent recognition."""
    text_lower = text.lower()

    intent_patterns = {
        (models.IntentType.RECOVER_ERROR, models.IntentCategory.ERROR_RECOVERY): [
            "error", "fail", "exception", "recover", "fix", "retry", "crash", "broken", "timeout"
        ],
        (models.IntentType.SCAN_VULNERABILITY, models.IntentCategory.VULNERABILITY_SCAN): [
            "vulnerability", "scan", "security", "threat", "risk", "exploit", "hack"
        ],
        (models.IntentType.CREATE_PLAN, models.IntentCategory.PLANNING): [
            "plan", "schedule", "organize", "arrange", "prepare", "roadmap", "workflow"
        ],
        (models.IntentType.ANALYZE, models.IntentCategory.ANALYSIS): [
            "analyze", "analysis", "analyse", "examine", "review", "inspect", "check", "evaluate"
        ],
        (models.IntentType.QUERY, models.IntentCategory.QUERY): [
            "what", "how", "why", "when", "where", "who", "query", "find", "search", "show"
        ],
        (models.IntentType.EXECUTE, models.IntentCategory.COMMAND): [
            "execute", "run", "start", "trigger", "launch", "begin", "initiate", "go"
        ],
    }

    best_intent = None
    best_confidence = 0.0
    matched_phrases = []

    for (intent_type, category), keywords in intent_patterns.items():
        matches = [kw for kw in keywords if kw in text_lower]
        if matches:
            confidence = min(len(matches) * 0.2, 0.85)
            if confidence > best_confidence:
                best_confidence = confidence
                matched_phrases = matches
                best_intent = (intent_type, category)

    if not best_intent:
        return models.IntentType.QUERY, models.IntentCategory.UNKNOWN, 0.5

    return best_intent[0], best_intent[1], best_confidence


def _recognize_intent(
    text: str,
    use_ml: bool = True,
    return_alternatives: bool = False
) -> tuple[models.RecognizedIntent, list[models.IntentAlternative]]:
    """Recognize intent from text using ML or keyword-based approach."""

    if use_ml:
        try:
            classifier = get_classifier()
            if not classifier.is_trained:
                logger.info("Training classifier on first use...")
                classifier.train()

            main_intent, alternatives = classifier.predict_with_alternatives(text, top_n=3)

            intent = models.RecognizedIntent(
                intent_type=models.IntentType(main_intent["intent_type"]),
                intent_category=models.IntentCategory(main_intent["intent_category"]),
                confidence=main_intent["confidence"],
                parameters=[],
                reasoning=f"ML classification with {main_intent['confidence']:.0%} confidence",
                matched_phrases=[],
            )

            alt_intents = []
            if return_alternatives:
                for alt in alternatives:
                    alt_intents.append(models.IntentAlternative(
                        intent_type=models.IntentType(alt["intent_type"]),
                        intent_category=models.IntentCategory(alt["intent_category"]),
                        confidence=alt["confidence"],
                        reason=alt["reason"],
                    ))

            return intent, alt_intents

        except Exception as e:
            logger.warning(f"ML classification failed, falling back to keyword-based: {e}")
            use_ml = False

    if not use_ml:
        intent_type, intent_category, confidence = _keyword_based_intent(text)

        intent = models.RecognizedIntent(
            intent_type=intent_type,
            intent_category=intent_category,
            confidence=confidence,
            parameters=[],
            reasoning="Keyword-based classification",
            matched_phrases=[],
        )

        alt_intents = []

    return intent, alt_intents


@router.post("/recognize", response_model=models.APIResponse[models.RecognizeResponse])
async def recognize(request: models.RecognizeRequest) -> JSONResponse:
    """Recognize intent from input text."""
    logger.info(f"Recognizing intent for: {request.text[:50]}... (ML: {request.use_ml})")

    start_time = time.time()

    intent, alternatives = _recognize_intent(
        request.text,
        use_ml=request.use_ml,
        return_alternatives=request.return_alternatives
    )

    processing_time = (time.time() - start_time) * 1000

    metadata = models.IntentMetadata(
        processing_time_ms=processing_time,
        model_version=config.settings.app_version,
        language="en",
        model_type="tfidf_logistic_regression" if request.use_ml else "keyword_matching",
    )

    _statistics["total_predictions"] += 1
    _statistics["predictions_by_intent"][intent.intent_type.value] += 1
    _statistics["processing_times"].append(processing_time)
    if len(_statistics["processing_times"]) > 1000:
        _statistics["processing_times"] = _statistics["processing_times"][-1000:]

    response = models.RecognizeResponse(
        intent=intent,
        alternatives=alternatives,
        metadata=metadata,
        message=f"Intent recognized with {intent.confidence:.0%} confidence",
    )

    logger.info(f"Intent recognized: {intent.intent_type.value} ({intent.confidence:.0%}) in {processing_time:.1f}ms")

    from neuroshell_shared.models import APIResponse as APIResponseModel

    return APIResponseModel(data=response)


@router.post("/batch-recognize", response_model=models.APIResponse[models.BatchRecognizeResponse])
async def batch_recognize(request: models.BatchRecognizeRequest) -> JSONResponse:
    """Batch recognize intents from multiple texts."""
    logger.info(f"Batch recognizing {len(request.texts)} texts (ML: {request.use_ml})")

    results = []
    for text in request.texts:
        intent, _ = _recognize_intent(text, use_ml=request.use_ml, return_alternatives=False)
        results.append(intent)

    response = models.BatchRecognizeResponse(
        results=results,
        processed_count=len(results),
        message=f"Processed {len(results)} texts",
    )

    from neuroshell_shared.models import APIResponse as APIResponseModel

    return APIResponseModel(data=response)


@router.post("/train", response_model=models.APIResponse[models.TrainingResponse])
async def train_model(request: models.TrainingDataRequest) -> JSONResponse:
    """Train the intent classifier with custom data."""
    logger.info(f"Training model with {len(request.data)} samples")

    training_data = [(item.text, item.intent) for item in request.data]

    classifier = get_classifier()
    results = classifier.train(training_data=training_data, test_size=request.test_size)

    training_result = models.TrainingResult(
        training_samples=results["training_samples"],
        test_samples=results["test_samples"],
        accuracy=results["accuracy"],
        f1_macro=results["report"]["macro avg"]["f1-score"],
        f1_weighted=results["report"]["weighted avg"]["f1-score"],
        report=results["report"],
    )

    response = models.TrainingResponse(
        success=True,
        result=training_result,
        message=f"Model trained successfully with {results['accuracy']:.1%} accuracy",
    )

    logger.info(f"Model trained: accuracy={results['accuracy']:.1%}, f1={results['report']['macro avg']['f1-score']:.1%}")

    from neuroshell_shared.models import APIResponse as APIResponseModel

    return APIResponseModel(data=response)


@router.get("/model/info", response_model=models.APIResponse[models.ModelInfo])
async def model_info() -> JSONResponse:
    """Get model information."""
    classifier = get_classifier()

    info = models.ModelInfo(
        is_trained=classifier.is_trained,
        model_type="tfidf_logistic_regression",
        supported_intents=classifier.get_supported_intents(),
    )

    from neuroshell_shared.models import APIResponse as APIResponseModel

    return APIResponseModel(data=info)


@router.get("/intents", response_model=models.APIResponse[list[str]])
async def list_intents() -> JSONResponse:
    """List supported intents."""
    classifier = get_classifier()
    intents = [i["type"] for i in classifier.get_supported_intents()]

    from neuroshell_shared.models import APIResponse as APIResponseModel

    return APIResponseModel(data=intents)


@router.get("/statistics", response_model=models.APIResponse[models.StatisticsResponse])
async def get_statistics() -> JSONResponse:
    """Get prediction statistics."""
    avg_confidence = 0.0
    if _statistics["processing_times"]:
        avg_time = sum(_statistics["processing_times"]) / len(_statistics["processing_times"])
    else:
        avg_time = 0.0

    stats = models.StatisticsResponse(
        total_predictions=_statistics["total_predictions"],
        predictions_by_intent=dict(_statistics["predictions_by_intent"]),
        average_confidence=avg_confidence,
        average_processing_time_ms=avg_time,
    )

    from neuroshell_shared.models import APIResponse as APIResponseModel

    return APIResponseModel(data=stats)


@router.post("/reset-statistics")
async def reset_statistics() -> JSONResponse:
    """Reset prediction statistics."""
    global _statistics
    _statistics = {
        "total_predictions": 0,
        "predictions_by_intent": defaultdict(int),
        "processing_times": [],
    }

    from neuroshell_shared.models import APIResponse as APIResponseModel

    return APIResponseModel(data={"message": "Statistics reset successfully"})