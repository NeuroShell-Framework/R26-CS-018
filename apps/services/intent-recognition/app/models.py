"""Request and response models for Intent Recognition Service."""

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class IntentCategory(str, Enum):
    """Intent categories."""

    ERROR_RECOVERY = "error_recovery"
    VULNERABILITY_SCAN = "vulnerability_scan"
    PLANNING = "planning"
    ANALYSIS = "analysis"
    QUERY = "query"
    COMMAND = "command"
    UNKNOWN = "unknown"


class IntentType(str, Enum):
    """Intent types."""

    RECOVER_ERROR = "recover_error"
    SCAN_VULNERABILITY = "scan_vulnerability"
    CREATE_PLAN = "create_plan"
    ANALYZE = "analyze"
    QUERY = "query"
    EXECUTE = "execute"


class IntentParameter(BaseModel):
    """Intent parameter."""

    name: str
    value: Any
    confidence: float = Field(..., ge=0.0, le=1.0)


class RecognizedIntent(BaseModel):
    """Recognized intent."""

    intent_type: IntentType
    intent_category: IntentCategory
    confidence: float = Field(..., ge=0.0, le=1.0)
    parameters: List[IntentParameter] = Field(default_factory=list)
    reasoning: Optional[str] = None
    matched_phrases: List[str] = Field(default_factory=list)


class IntentAlternative(BaseModel):
    """Alternative intent."""

    intent_type: IntentType
    intent_category: IntentCategory
    confidence: float = Field(..., ge=0.0, le=1.0)
    reason: str


class IntentMetadata(BaseModel):
    """Intent metadata."""

    processing_time_ms: float
    model_version: str
    language: str = "en"
    model_type: str = "tfidf_logistic_regression"


class TrainingDataItem(BaseModel):
    """Training data item."""

    text: str
    intent: str


class TrainingDataRequest(BaseModel):
    """Training data request."""

    data: List[TrainingDataItem]
    test_size: float = Field(default=0.2, ge=0.1, le=0.4)


class TrainingResult(BaseModel):
    """Training result."""

    training_samples: int
    test_samples: int
    accuracy: float
    f1_macro: float
    f1_weighted: float
    report: Dict[str, Any]


class TrainingResponse(BaseModel):
    """Training response."""

    success: bool
    result: TrainingResult
    message: str


class ModelInfo(BaseModel):
    """Model information."""

    is_trained: bool
    model_type: str
    supported_intents: List[Dict[str, str]]
    training_samples: Optional[int] = None


class RecognizeRequest(BaseModel):
    """Recognize request."""

    text: str = Field(..., min_length=1, description="Input text to analyze")
    context: Optional[str] = Field(default=None, description="Optional context")
    return_alternatives: bool = Field(default=False, description="Return alternative intents")
    use_ml: bool = Field(default=True, description="Use ML-based classification")


class RecognizeResponse(BaseModel):
    """Recognize response."""

    intent: RecognizedIntent
    alternatives: List[IntentAlternative] = Field(default_factory=list)
    metadata: IntentMetadata
    message: str


class BatchRecognizeRequest(BaseModel):
    """Batch recognize request."""

    texts: List[str] = Field(..., min_length=1, max_length=50)
    context: Optional[str] = None
    use_ml: bool = Field(default=True, description="Use ML-based classification")


class BatchRecognizeResponse(BaseModel):
    """Batch recognize response."""

    results: List[RecognizedIntent]
    processed_count: int
    message: str


class HealthCheckResponse(BaseModel):
    """Health check response."""

    status: str
    service: str
    version: str
    model_status: str
    uptime: float
    total_predictions: int


class StatisticsResponse(BaseModel):
    """Statistics response."""

    total_predictions: int
    predictions_by_intent: Dict[str, int]
    average_confidence: float
    average_processing_time_ms: float