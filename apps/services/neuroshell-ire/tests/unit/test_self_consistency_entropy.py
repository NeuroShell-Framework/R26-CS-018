# NeuroShell IRE — Unit Tests for Self-Consistency & Semantic Entropy Uncertainty

from unittest.mock import MagicMock
import pytest

from src.inference.ollama_inference_engine import OllamaInferenceEngine
from src.utils.metrics_collector import MetricsCollector
from src.schemas.intent_schema import IREResponseV2, IntentType, Target, TargetType


def test_clear_cut_input_tier1_gating():
    """Clear-cut input with high confidence returns Tier 1 result without triggering Tier 2."""
    engine = OllamaInferenceEngine()
    engine.client = MagicMock()

    high_conf_response = (
        '{"intent":"NETWORK_SCAN","target":{"type":"IP","value":"192.168.1.1"},'
        '"ports":[80],"modifiers":["stealth"],"cve_ids":[],"confidence":0.95}'
    )
    engine.client.chat.return_value = {"message": {"content": high_conf_response}}

    output = engine.generate("scan 192.168.1.1")

    assert output == high_conf_response
    assert engine.client.chat.call_count == 1  # Called EXACTLY ONCE — proves Tier 2 gating works!
    assert engine.last_metadata["tier_triggered"] == 1
    assert engine.last_metadata["uncertainty_band"] == "low"
    assert engine.last_metadata["raw_entropy"] == 0.0
    assert engine.last_metadata["resolution_method"] == "single_sample"


def test_low_tier1_triggers_tier2_identical_candidates():
    """Low Tier 1 confidence triggers Tier 2; identical candidates result in H=0.0 and low uncertainty."""
    engine = OllamaInferenceEngine()
    engine.client = MagicMock()
    engine.settings.self_consistency_trigger_threshold = 0.7
    engine.settings.self_consistency_samples = 5

    low_conf_response = (
        '{"intent":"NETWORK_SCAN","target":{"type":"IP","value":"192.168.1.1"},'
        '"ports":[],"modifiers":[],"cve_ids":[],"confidence":0.4}'
    )
    engine.client.chat.return_value = {"message": {"content": low_conf_response}}

    output = engine.generate("ambiguous input scan 192.168.1.1")

    assert output == low_conf_response
    assert engine.client.chat.call_count == 5  # Tier 1 (1 call) + Tier 2 (4 additional resamples) = 5 total
    assert engine.last_metadata["tier_triggered"] == 2
    assert engine.last_metadata["uncertainty_band"] == "low"
    assert engine.last_metadata["raw_entropy"] == 0.0
    assert engine.last_metadata["resolution_method"] == "majority_vote"


def test_low_tier1_triggers_tier2_distinct_candidates_high_entropy():
    """Low Tier 1 confidence with 5 semantically distinct candidates results in high entropy & high uncertainty."""
    engine = OllamaInferenceEngine()
    engine.client = MagicMock()
    engine.settings.self_consistency_trigger_threshold = 0.7
    engine.settings.self_consistency_samples = 5

    candidate_responses = [
        '{"intent":"NETWORK_SCAN","target":{"type":"IP","value":"10.0.0.1"},"confidence":0.4}',
        '{"intent":"VULNERABILITY_AUDIT","target":{"type":"IP","value":"10.0.0.2"},"confidence":0.4}',
        '{"intent":"EXPLOITATION","target":{"type":"IP","value":"10.0.0.3"},"confidence":0.4}',
        '{"intent":"DIRECTORY_BRUTEFORCE","target":{"type":"URL","value":"http://target/admin"},"confidence":0.4}',
        '{"intent":"PASSIVE_RECON","target":{"type":"DOMAIN","value":"example.com"},"confidence":0.4}',
    ]
    engine.client.chat.side_effect = [
        {"message": {"content": r}} for r in candidate_responses
    ]

    output = engine.generate("extremely ambiguous query")

    assert engine.client.chat.call_count == 5
    assert engine.last_metadata["tier_triggered"] == 2
    assert engine.last_metadata["raw_entropy"] > 0.8
    assert engine.last_metadata["uncertainty_band"] == "high"
    assert engine.last_metadata["resolution_method"] == "majority_vote"


def test_cluster_signature_ignores_minor_parameter_differences():
    """Clustering logic groups candidates with minor parameter differences (ports/modifiers) into the same cluster."""
    engine = OllamaInferenceEngine()

    cand1 = '{"intent":"NETWORK_SCAN","target":{"type":"IP","value":"192.168.1.1"},"ports":[80],"modifiers":["stealth"]}'
    cand2 = '{"intent":"NETWORK_SCAN","target":{"type":"IP","value":"192.168.1.1"},"ports":[443],"modifiers":["verbose"]}'
    cand3 = '{"intent":"VULNERABILITY_AUDIT","target":{"type":"IP","value":"192.168.1.1"},"ports":[80]}'

    sig1 = engine._extract_cluster_signature(cand1)
    sig2 = engine._extract_cluster_signature(cand2)
    sig3 = engine._extract_cluster_signature(cand3)

    assert sig1 == sig2  # Same intent + target -> same cluster!
    assert sig1 != sig3  # Different intent -> different cluster!


def test_metrics_collector_records_entropy():
    """MetricsCollector records raw entropy values and tier counts correctly."""
    collector = MetricsCollector()
    collector.record_entropy(raw_entropy=0.45, uncertainty_band="medium", tier_triggered=2)
    collector.record_entropy(raw_entropy=0.10, uncertainty_band="low", tier_triggered=1)

    summary = collector.get_summary()
    assert summary["average_semantic_entropy"] == 0.275
    assert summary["max_semantic_entropy"] == 0.45
    assert summary["tier_counts"][1] == 1
    assert summary["tier_counts"][2] == 1
