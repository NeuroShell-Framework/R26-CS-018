import pytest
from unittest.mock import patch, MagicMock
import time
from src.middleware.semantic_cache import SemanticCache, CacheEntry
from src.schemas.intent_schema import IREResponse, IntentType, Target, TargetType


@pytest.fixture
def cache():
    with patch("src.middleware.semantic_cache.get_feature_flags") as mock:
        mock.return_value.semantic_cache = True
        mock.return_value.get_tuning = lambda k, d: {
            "semantic_cache_threshold": 0.97,
            "semantic_cache_max_size": 512,
        }.get(k, d)
        c = SemanticCache()
        c._model = MagicMock()
        return c


@pytest.fixture
def cache_disabled():
    with patch("src.middleware.semantic_cache.get_feature_flags") as mock:
        mock.return_value.semantic_cache = False
        mock.return_value.get_tuning = lambda k, d: d
        return SemanticCache()


@pytest.fixture
def success_response():
    return IREResponse(
        status="success",
        intent=IntentType.NETWORK_SCAN,
        target=Target(type=TargetType.IP, value="192.168.1.1"),
        ports=[22, 80],
        modifiers=["stealth"],
        cve_ids=[],
        tool_hint="nmap",
        confidence=0.92,
        latency_ms=1500,
    )


@pytest.fixture
def error_response():
    return IREResponse(
        status="error",
        error="PARSE_FAILED",
        stage="json_parser",
        detail="Invalid JSON",
        latency_ms=50,
    )


class TestCacheEntry:

    def test_cache_entry_initial_state(self):
        """CacheEntry initializes with hit_count 0 and timestamps."""
        entry = CacheEntry(key_hash="abc", embedding=[0.1], response=MagicMock())
        assert entry.hit_count == 0
        assert entry.created_at > 0
        assert entry.last_hit_at > 0


class TestSemanticCacheInit:

    def test_cache_initializes_with_empty_entries(self, cache):
        """SemanticCache starts with an empty _entries list."""
        assert cache._entries == []

    def test_cache_sets_threshold_from_flags(self, cache):
        """SemanticCache reads threshold from feature flags tuning."""
        assert cache._threshold == 0.97

    def test_cache_sets_max_size_from_flags(self, cache):
        """SemanticCache reads max_size from feature flags tuning."""
        assert cache._max_size == 512

    def test_cache_model_is_none_initially(self):
        """SemanticCache._model is None before first embed call."""
        with patch("src.middleware.semantic_cache.get_feature_flags") as mock:
            mock.return_value.semantic_cache = True
            mock.return_value.get_tuning = lambda k, d: d
            c = SemanticCache()
            assert c._model is None


class TestMakeKeyHash:

    def test_make_key_hash_is_deterministic(self, cache):
        """_make_key_hash returns same hash for same input."""
        h1 = cache._make_key_hash("scan 10.0.0.1")
        h2 = cache._make_key_hash("scan 10.0.0.1")
        assert h1 == h2

    def test_make_key_hash_is_case_insensitive(self, cache):
        """_make_key_hash normalizes case (lower)."""
        h1 = cache._make_key_hash("Scan 10.0.0.1")
        h2 = cache._make_key_hash("scan 10.0.0.1")
        assert h1 == h2

    def test_make_key_hash_strips_whitespace(self, cache):
        """_make_key_hash strips leading/trailing whitespace."""
        h1 = cache._make_key_hash("  scan 10.0.0.1  ")
        h2 = cache._make_key_hash("scan 10.0.0.1")
        assert h1 == h2

    def test_make_key_hash_different_for_different_inputs(self, cache):
        """_make_key_hash produces different hashes for different inputs."""
        h1 = cache._make_key_hash("scan 10.0.0.1")
        h2 = cache._make_key_hash("scan 10.0.0.2")
        assert h1 != h2


class TestCosineSimilarity:

    def test_cosine_similarity_identical_vectors(self, cache):
        """_cosine_similarity returns 1.0 for identical vectors."""
        vec = [1.0, 2.0, 3.0]
        assert cache._cosine_similarity(vec, vec) == pytest.approx(1.0)

    def test_cosine_similarity_orthogonal_vectors(self, cache):
        """_cosine_similarity returns 0.0 for orthogonal vectors."""
        a = [1.0, 0.0, 0.0]
        b = [0.0, 1.0, 0.0]
        assert cache._cosine_similarity(a, b) == pytest.approx(0.0)

    def test_cosine_similarity_zero_magnitude(self, cache):
        """_cosine_similarity returns 0.0 when either vector has zero magnitude."""
        assert cache._cosine_similarity([0.0, 0.0], [1.0, 2.0]) == 0.0


class TestLookup:

    def test_lookup_returns_none_when_empty(self, cache):
        """lookup returns (None, 'none') when cache has no entries."""
        result, status = cache.lookup("scan 10.0.0.1")
        assert result is None
        assert status == "none"

    def test_lookup_returns_none_when_disabled(self, cache_disabled):
        """lookup returns (None, 'none') when semantic_cache is disabled."""
        result, status = cache_disabled.lookup("scan 10.0.0.1")
        assert result is None
        assert status == "none"

    def test_lookup_hit_returns_response_and_semantic(self, cache, success_response):
        """lookup returns (response, 'semantic') when similarity exceeds threshold."""
        cache._entries.append(CacheEntry(
            key_hash=cache._make_key_hash("scan 10.0.0.1"),
            embedding=[0.1] * 384,
            response=success_response,
        ))
        with patch.object(cache, "_embed", return_value=[0.1] * 384):
            result, status = cache.lookup("scan 10.0.0.1")
        assert result is not None
        assert status in ("semantic", "exact")

    def test_lookup_miss_returns_none_when_below_threshold(self, cache, success_response):
        """lookup returns (None, 'none') when similarity is below threshold."""
        emb_entry = [1.0] + [0.0] * 383
        emb_query = [0.0, 1.0] + [0.0] * 382  # Orthogonal non-zero vector, cosine sim = 0.0
        cache._entries.append(CacheEntry(
            key_hash=cache._make_key_hash("scan 10.0.0.1"),
            embedding=emb_entry,
            response=success_response,
        ))
        with patch.object(cache, "_embed", return_value=emb_query):
            result, status = cache.lookup("exploit host with CVE-2017-0144")
        assert result is None
        assert status == "none"

    def test_lookup_increments_hit_count(self, cache, success_response):
        """lookup increments hit_count on the matched entry."""
        entry = CacheEntry(
            key_hash=cache._make_key_hash("scan 10.0.0.1"),
            embedding=[0.1] * 384,
            response=success_response,
        )
        cache._entries.append(entry)
        with patch.object(cache, "_embed", return_value=[0.1] * 384):
            cache.lookup("scan 10.0.0.1")
        assert entry.hit_count == 1

    def test_lookup_updates_last_hit_at(self, cache, success_response):
        """lookup updates last_hit_at timestamp on the matched entry."""
        entry = CacheEntry(
            key_hash=cache._make_key_hash("scan 10.0.0.1"),
            embedding=[0.1] * 384,
            response=success_response,
            last_hit_at=0.0,
        )
        cache._entries.append(entry)
        with patch.object(cache, "_embed", return_value=[0.1] * 384):
            cache.lookup("scan 10.0.0.1")
        assert entry.last_hit_at > 0.0

    def test_lookup_selects_best_match(self, cache):
        """lookup returns the entry with highest cosine similarity."""
        resp_a = MagicMock(name="resp_a")
        resp_b = MagicMock(name="resp_b")
        entry_a = CacheEntry(
            key_hash="hash_a",
            embedding=[0.5, 0.5] + [0.0] * 382,
            response=resp_a,
        )
        entry_b = CacheEntry(
            key_hash="hash_b",
            embedding=[0.99, 0.1] + [0.0] * 382,
            response=resp_b,
        )
        cache._entries = [entry_a, entry_b]
        query_emb = [1.0] + [0.0] * 383  # Higher cosine sim to entry_b (0.995 vs 0.707)
        with patch.object(cache, "_embed", return_value=query_emb):
            result, status = cache.lookup("similar query")
        assert status == "semantic"
        assert result is resp_b

    def test_lookup_returns_none_on_exception(self, cache):
        """lookup returns (None, 'none') when embedding raises an exception."""
        cache._entries.append(CacheEntry(
            key_hash="hash_x",
            embedding=[0.1] * 384,
            response=MagicMock(),
        ))
        with patch.object(cache, "_embed", side_effect=RuntimeError("model error")):
            result, status = cache.lookup("scan 10.0.0.1")
        assert result is None
        assert status == "none"


class TestStore:

    def test_store_adds_entry_on_success(self, cache, success_response):
        """store adds a CacheEntry when given a successful response."""
        with patch.object(cache, "_embed", return_value=[0.2] * 384):
            cache.store("scan 10.0.0.1", success_response)
        assert len(cache._entries) == 1
        assert cache._entries[0].response is success_response

    def test_store_ignores_error_response(self, cache, error_response):
        """store does nothing when response status is error."""
        with patch.object(cache, "_embed", return_value=[0.2] * 384):
            cache.store("bad command", error_response)
        assert len(cache._entries) == 0

    def test_store_ignores_none_response(self, cache):
        """store does nothing when response is None."""
        with patch.object(cache, "_embed", return_value=[0.2] * 384):
            cache.store("scan host", None)
        assert len(cache._entries) == 0

    def test_store_noop_when_disabled(self, cache_disabled, success_response):
        """store is a no-op when semantic_cache is disabled."""
        cache_disabled._model = MagicMock()
        cache_disabled.store("scan 10.0.0.1", success_response)
        assert len(cache_disabled._entries) == 0

    def test_store_skips_duplicate_hash(self, cache, success_response):
        """store skips storing an entry if the key_hash already exists."""
        with patch.object(cache, "_embed", return_value=[0.2] * 384):
            cache.store("scan 10.0.0.1", success_response)
            cache.store("scan 10.0.0.1", success_response)
        assert len(cache._entries) == 1

    def test_store_evicts_lru_when_at_capacity(self, cache, success_response):
        """store evicts LRU entry when cache is at max_size."""
        cache._max_size = 2
        with patch.object(cache, "_embed", return_value=[0.2] * 384):
            cache.store("cmd a", success_response)
            time.sleep(0.01)
            cache.store("cmd b", success_response)
            time.sleep(0.01)
            cache.store("cmd c", success_response)
        assert len(cache._entries) == 2

    def test_store_sets_embedding(self, cache, success_response):
        """store generates and stores the embedding for the text."""
        with patch.object(cache, "_embed", return_value=[0.3] * 384):
            cache.store("scan 10.0.0.1", success_response)
        assert cache._entries[0].embedding == [0.3] * 384

    def test_store_sets_key_hash(self, cache, success_response):
        """store sets the correct key_hash for the entry."""
        with patch.object(cache, "_embed", return_value=[0.3] * 384):
            cache.store("scan 10.0.0.1", success_response)
        expected_hash = cache._make_key_hash("scan 10.0.0.1")
        assert cache._entries[0].key_hash == expected_hash

    def test_store_on_exception_logs_and_continues(self, cache, success_response):
        """store handles embedding exceptions gracefully without crashing."""
        with patch.object(cache, "_embed", side_effect=RuntimeError("embed fail")):
            cache.store("scan 10.0.0.1", success_response)


class TestEvictLRU:

    def test_evict_lru_removes_least_recently_hit(self, cache, success_response):
        """_evict_lru removes the entry with the oldest last_hit_at."""
        e1 = CacheEntry(key_hash="e1", embedding=[0.1]*384, response=success_response, last_hit_at=100.0)
        e2 = CacheEntry(key_hash="e2", embedding=[0.1]*384, response=success_response, last_hit_at=200.0)
        cache._entries = [e1, e2]
        cache._evict_lru()
        assert len(cache._entries) == 1
        assert cache._entries[0].key_hash == "e2"

    def test_evict_lru_on_empty_list_does_not_crash(self, cache):
        """_evict_lru on empty entries list is a safe no-op."""
        cache._entries = []
        cache._evict_lru()
        assert cache._entries == []


class TestGetStats:

    def test_get_stats_returns_entries_count(self, cache, success_response):
        """get_stats reports the correct number of cache entries."""
        with patch.object(cache, "_embed", return_value=[0.1] * 384):
            cache.store("cmd1", success_response)
            cache.store("cmd2", success_response)
        stats = cache.get_stats()
        assert stats["entries"] == 2

    def test_get_stats_returns_max_size(self, cache):
        """get_stats includes max_size configuration value."""
        stats = cache.get_stats()
        assert stats["max_size"] == cache._max_size

    def test_get_stats_returns_threshold(self, cache):
        """get_stats includes threshold configuration value."""
        stats = cache.get_stats()
        assert stats["threshold"] == cache._threshold

    def test_get_stats_returns_feature_enabled(self, cache):
        """get_stats includes feature_enabled boolean."""
        stats = cache.get_stats()
        assert isinstance(stats["feature_enabled"], bool)

    def test_get_stats_returns_model_loaded_status(self, cache):
        """get_stats includes model_loaded boolean."""
        stats = cache.get_stats()
        assert isinstance(stats["model_loaded"], bool)

    def test_get_stats_returns_total_hits(self, cache, success_response):
        """get_stats reports total_hits across all entries."""
        entry = CacheEntry(
            key_hash="h1",
            embedding=[0.1] * 384,
            response=success_response,
            hit_count=5,
        )
        cache._entries.append(entry)
        stats = cache.get_stats()
        assert stats["total_hits"] == 5
