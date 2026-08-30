# NeuroShell IRE — Semantic Cache Adversarial & Reliability Test Suite
# Tests near-duplicate query isolation, threshold determinism, grounding staleness invalidation, and hit-type distinction.

import math
import pytest
from unittest.mock import patch, MagicMock

from src.middleware.semantic_cache import SemanticCache, CacheEntry
from src.schemas.intent_schema import IREResponse, IntentType, Target, TargetType


@pytest.fixture
def cache(monkeypatch):
    c = SemanticCache()
    monkeypatch.setattr(c.flags, "_flags", {"semantic_cache": True})
    return c


@pytest.fixture
def response_vuln_audit():
    return IREResponse(
        status="success",
        intent=IntentType.VULNERABILITY_AUDIT,
        target=Target(type=TargetType.IP, value="10.0.0.1"),
        confidence=0.95,
        latency_ms=10,
    )


@pytest.fixture
def response_exploitation():
    return IREResponse(
        status="success",
        intent=IntentType.EXPLOITATION,
        target=Target(type=TargetType.IP, value="10.0.0.1"),
        confidence=0.95,
        latency_ms=12,
    )


def test_near_duplicate_different_intent_not_cached(cache, response_vuln_audit):
    """
    Near-duplicate queries with different ground truth intents must NOT be served cached responses.
    e.g. 'scan 10.0.0.1 for smb vulnerabilities' vs 'scan 10.0.0.1 for eternalblue'
    """
    cmd_audit = "scan 10.0.0.1 for smb vulnerabilities"
    cmd_exploit = "scan 10.0.0.1 for eternalblue"

    # Store general audit query
    cache.store(cmd_audit, response_vuln_audit)

    # Perform lookup for distinct exploit query
    cached_resp, hit_type = cache.lookup(cmd_exploit)
    assert cached_resp is None
    assert hit_type == "none"


def test_similarity_threshold_boundary_deterministic(cache, response_vuln_audit):
    """
    Similarity threshold boundary evaluation must be strictly deterministic.
    Scores below threshold return miss; scores at or above threshold return hit.
    """
    # Threshold is configured at 0.98
    target_threshold = getattr(cache, "_threshold", 0.98)

    # Mock embeddings to yield controlled cosine similarity
    # vec1 = [1.0, 0.0], vec2 = [cos(theta), sin(theta)] => cos(theta) = dot product
    theta_below = math.acos(target_threshold - 0.005)
    theta_above = math.acos(target_threshold + 0.005)

    vec_query = [1.0, 0.0]
    vec_entry = [1.0, 0.0]

    # Store entry
    with patch.object(cache, "_embed", return_value=vec_entry):
        cache.store("scan 10.0.0.1", response_vuln_audit)

    # Lookup with vector below threshold
    vec_below = [math.cos(theta_below), math.sin(theta_below)]
    with patch.object(cache, "_embed", return_value=vec_below):
        resp, hit_type = cache.lookup("different query text")
        assert resp is None
        assert hit_type == "none"

    # Lookup with vector above threshold
    vec_above = [math.cos(theta_above), math.sin(theta_above)]
    with patch.object(cache, "_embed", return_value=vec_above):
        resp, hit_type = cache.lookup("different query text")
        assert resp is not None
        assert resp.intent == IntentType.VULNERABILITY_AUDIT
        assert hit_type == "semantic"


def test_grounding_update_invalidates_cache_entry(cache, response_vuln_audit, monkeypatch):
    """
    Updating grounding data between queries invalidates stale cache entries.
    Cache entries generated under old grounding hashes must fail lookup.
    """
    # 1. Initial grounding hash v1
    monkeypatch.setattr(cache, "_get_grounding_hash", lambda: "grounding_v1_hash")
    cache.store("scan 10.0.0.1", response_vuln_audit)

    # Verify lookup succeeds under v1
    resp1, hit1 = cache.lookup("scan 10.0.0.1")
    assert resp1 is not None

    # 2. Update grounding source to v2
    monkeypatch.setattr(cache, "_get_grounding_hash", lambda: "grounding_v2_hash_updated")

    # Lookup for identical query must now return miss (invalidated)
    resp2, hit2 = cache.lookup("scan 10.0.0.1")
    assert resp2 is None
    assert hit2 == "none"


def test_cache_hit_distinguishes_exact_and_semantic(cache, response_vuln_audit):
    """
    lookup() must distinguish 'exact' (identical text key_hash match) from 'semantic' (vector match).
    """
    cmd = "scan 192.168.1.1"
    cache.store(cmd, response_vuln_audit)

    # Exact string match
    resp_exact, hit_exact = cache.lookup(cmd)
    assert resp_exact is not None
    assert hit_exact == "exact"

    # Near-identical text with identical embedding => semantic hit
    with patch.object(cache, "_embed", return_value=cache._entries[0].embedding):
        resp_sem, hit_sem = cache.lookup("scan 192.168.1.1 for ports")
        assert resp_sem is not None
        assert hit_sem == "semantic"
