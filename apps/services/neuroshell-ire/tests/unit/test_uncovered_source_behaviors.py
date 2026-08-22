# NeuroShell IRE — Unit Tests for Additional Source Coverage

import pytest
from unittest.mock import MagicMock

from config.settings import Settings
from src.inference.ollama_inference_engine import OllamaInferenceEngine
from src.schemas.intent_schema import IntentSchema, Target, TargetType, IntentType, InferenceError
from src.validation.network_validator import NetworkArchitectureValidator
from src.validation.scope_guard import ScopeGuard
from src.utils.metrics_collector import MetricsCollector


def test_ollama_call_ollama_exception_raises_inference_error():
    """_call_ollama catches connection error and raises InferenceError."""
    engine = OllamaInferenceEngine()
    engine.client = MagicMock()
    engine.client.chat.side_effect = Exception("Ollama daemon unavailable")
    with pytest.raises(InferenceError):
        engine._call_ollama("scan 10.0.0.1", temperature=0.1)


def test_network_validator_ipv6_subnet():
    """NetworkArchitectureValidator validates IPv6 targets and subnets cleanly."""
    validator = NetworkArchitectureValidator()
    validator.settings.engagement_mode = "strict"
    validator.settings.engagement_scope = "2001:db8::/32"

    schema = IntentSchema(
        intent=IntentType.NETWORK_SCAN,
        target=Target(type=TargetType.SUBNET, value="2001:db8:1::/64"),
        confidence=0.9,
    )
    validated, warnings = validator.validate(schema)
    assert validated is not None
    assert len(warnings) == 0


def test_scope_guard_production_mode():
    """ScopeGuard enforces scope check when scope_mode='production'."""
    guard = ScopeGuard()
    guard.settings = Settings(scope_mode="production")

    schema = IntentSchema(
        intent=IntentType.NETWORK_SCAN,
        target=Target(type=TargetType.IP, value="10.0.0.1"),
        confidence=0.9,
    )
    validated, warnings = guard.check(schema, raw_input="scan 10.0.0.1")
    assert validated is not None
    assert len(guard.last_findings) > 0


def test_metrics_collector_percentiles_calculation():
    """MetricsCollector computes latency p95 and p99 percentiles correctly."""
    metrics = MetricsCollector()
    for latency in range(1, 101):
        metrics.record_success(intent="NETWORK_SCAN", latency_ms=latency, confidence=0.9)

    summary = metrics.get_summary()
    assert summary["total_requests"] == 100
    assert summary["latency_p50_ms"] >= 50
    assert summary["latency_p95_ms"] >= 95
    assert summary["latency_p99_ms"] >= 99
