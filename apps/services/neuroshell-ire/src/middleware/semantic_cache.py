import time
import hashlib
from typing import Optional, List, Tuple, Any
from dataclasses import dataclass, field
from config.feature_flags import get_feature_flags
from src.schemas.intent_schema import IREResponse
from src.utils.logging_config import get_logger


@dataclass
class CacheEntry:
    """One entry in the semantic cache."""
    key_hash: str
    embedding: List[float]
    response: IREResponse
    grounding_hash: str = ""
    hit_count: int = 0
    created_at: float = field(default_factory=time.time)
    last_hit_at: float = field(default_factory=time.time)


class SemanticCache:
    def __init__(self):
        self.logger = get_logger(__name__)
        self.flags = get_feature_flags()
        self._entries: List[CacheEntry] = []
        self._model = None
        self._model_name = "all-MiniLM-L6-v2"
        self._threshold = self.flags.get_tuning("semantic_cache_threshold", 0.98)
        self._max_size = self.flags.get_tuning("semantic_cache_max_size", 512)
        self.logger.info(
            "semantic_cache_initialized",
            extra={"threshold": self._threshold, "max_size": self._max_size}
        )

    def _get_grounding_hash(self) -> str:
        """Compute SHA-256 digest of grounding dataset sources (cve_grounding.json & alias_map.json)."""
        import os
        hasher = hashlib.sha256()
        grounding_files = [
            "data/cve_grounding.json",
            "data/alias_map.json",
            "config/alias_map.json",
        ]
        found = False
        for fpath in grounding_files:
            if os.path.exists(fpath):
                try:
                    with open(fpath, "rb") as f:
                        hasher.update(f.read())
                    found = True
                except Exception:
                    pass
        if not found:
            hasher.update(b"default_grounding_v1")
        return hasher.hexdigest()

    def _load_model(self) -> None:
        if self._model is None:
            try:
                from sentence_transformers import SentenceTransformer
                self.logger.info(
                    "semantic_cache_model_loading",
                    extra={"model": self._model_name}
                )
                self._model = SentenceTransformer(self._model_name)
                self.logger.info(
                    "semantic_cache_model_ready",
                    extra={"model": self._model_name}
                )
            except ImportError:
                self.logger.error(
                    "semantic_cache_import_error",
                    extra={"detail": "sentence-transformers not installed. "
                           "Run: pip install sentence-transformers"}
                )
                raise

    def _embed(self, text: str) -> List[float]:
        self._load_model()
        embedding = self._model.encode(text, convert_to_numpy=True)
        return embedding.tolist()

    def _cosine_similarity(self, vec_a: List[float], vec_b: List[float]) -> float:
        import math
        dot = sum(a * b for a, b in zip(vec_a, vec_b))
        mag_a = math.sqrt(sum(a * a for a in vec_a))
        mag_b = math.sqrt(sum(b * b for b in vec_b))
        if mag_a == 0.0 or mag_b == 0.0:
            return 0.0
        return dot / (mag_a * mag_b)

    def _make_key_hash(self, text: str) -> str:
        return hashlib.sha256(text.strip().lower().encode()).hexdigest()

    def _evict_lru(self) -> None:
        if self._entries:
            lru_idx = min(
                range(len(self._entries)),
                key=lambda i: self._entries[i].last_hit_at
            )
            evicted = self._entries.pop(lru_idx)
            self.logger.debug(
                "semantic_cache_eviction",
                extra={"evicted_hash": evicted.key_hash[:8]}
            )

    def lookup(self, text: str) -> Tuple[Optional[IREResponse], str]:
        if not self.flags.semantic_cache:
            return None, "none"

        if not self._entries:
            return None, "none"

        try:
            query_hash = self._make_key_hash(text)
            current_grounding = self._get_grounding_hash()

            # 1. Exact Key Hash Match Lookup
            for entry in list(self._entries):
                if entry.key_hash == query_hash:
                    if entry.grounding_hash and entry.grounding_hash != current_grounding:
                        # Grounding data updated since entry creation -> invalidate stale entry
                        self._entries.remove(entry)
                        self.logger.info("semantic_cache_stale_invalidated", extra={"key_hash": query_hash[:8]})
                        return None, "none"
                    entry.hit_count += 1
                    entry.last_hit_at = time.time()
                    return entry.response, "exact"

            # 2. Vector Cosine Similarity Lookup
            query_embedding = self._embed(text)
            best_score = 0.0
            best_entry = None

            for entry in list(self._entries):
                if entry.grounding_hash and entry.grounding_hash != current_grounding:
                    continue
                score = self._cosine_similarity(query_embedding, entry.embedding)
                if score > best_score:
                    best_score = score
                    best_entry = entry

            if best_entry and best_score >= self._threshold:
                best_entry.hit_count += 1
                best_entry.last_hit_at = time.time()
                self.logger.info(
                    "semantic_cache_hit",
                    extra={
                        "similarity": round(best_score, 4),
                        "hit_count": best_entry.hit_count
                    }
                )
                return best_entry.response, "semantic"

            self.logger.debug(
                "semantic_cache_miss",
                extra={"best_similarity": round(best_score, 4) if best_score > 0 else 0.0}
            )
            return None, "none"

        except Exception as e:
            self.logger.error(
                "semantic_cache_lookup_error",
                extra={"error": str(e)}
            )
            return None, "none"

    def store(self, text: str, response: IREResponse) -> None:
        if not self.flags.semantic_cache:
            return
        if not response or response.status != "success":
            return

        try:
            key_hash = self._make_key_hash(text)

            if any(e.key_hash == key_hash for e in self._entries):
                return

            embedding = self._embed(text)

            if len(self._entries) >= self._max_size:
                self._evict_lru()

            entry = CacheEntry(
                key_hash=key_hash,
                embedding=embedding,
                response=response,
                grounding_hash=self._get_grounding_hash(),
            )
            self._entries.append(entry)

            self.logger.debug(
                "semantic_cache_stored",
                extra={"key_hash": key_hash[:8], "cache_size": len(self._entries)}
            )

        except Exception as e:
            self.logger.error(
                "semantic_cache_store_error",
                extra={"error": str(e)}
            )

    def get_stats(self) -> dict:
        return {
            "entries": len(self._entries),
            "max_size": self._max_size,
            "threshold": self._threshold,
            "feature_enabled": self.flags.semantic_cache,
            "model_loaded": self._model is not None,
            "total_hits": sum(e.hit_count for e in self._entries),
        }
