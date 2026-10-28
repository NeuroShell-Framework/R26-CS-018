# NeuroShell IRE — Metrics Collector
# Collect and report pipeline performance metrics including raw semantic entropy

import time
from collections import defaultdict
from typing import Dict, Any, List
from src.utils.logging_config import get_logger


class MetricsCollector:
    def __init__(self):
        self.logger = get_logger(__name__)
        self._success_count: int = 0
        self._error_counts: Dict[str, int] = defaultdict(int)
        self._latencies: list = []
        self._intent_counts: Dict[str, int] = defaultdict(int)
        self._start_time: float = time.time()
        self._entropy_records: List[float] = []
        self._tier_counts: Dict[int, int] = defaultdict(int)
        self._cache_hits: Dict[str, int] = defaultdict(int)

    def record_success(self, intent: str, latency_ms: int, confidence: float) -> None:
        self._success_count += 1
        self._intent_counts[intent] += 1
        self._latencies.append(latency_ms)
        if len(self._latencies) > 1000:
            self._latencies.pop(0)
        self.logger.debug(
            "metric_recorded",
            type="success",
            intent=intent,
            latency_ms=latency_ms,
            confidence=confidence,
        )

    def record_cache_result(self, hit_type: str) -> None:
        """Record cache lookup result ('exact', 'semantic', 'miss')."""
        norm_type = "miss" if hit_type in ("none", "miss") else hit_type
        self._cache_hits[norm_type] += 1
        self.logger.debug("metric_recorded", type="cache_hit", hit_type=norm_type)

    def record_entropy(
        self, raw_entropy: float, uncertainty_band: str, tier_triggered: int
    ) -> None:
        """Record raw semantic entropy value and uncertainty tier."""
        self._entropy_records.append(raw_entropy)
        if len(self._entropy_records) > 1000:
            self._entropy_records.pop(0)
        self._tier_counts[tier_triggered] += 1
        self.logger.info(
            "semantic_entropy_measured",
            raw_entropy=raw_entropy,
            uncertainty_band=uncertainty_band,
            tier_triggered=tier_triggered,
        )

    def record_error(self, stage: str) -> None:
        self._error_counts[stage] += 1
        self.logger.debug("metric_recorded", type="error", stage=stage)

    def get_summary(self) -> Dict[str, Any]:
        total = self._success_count + sum(self._error_counts.values())
        p50 = p95 = p99 = 0
        if self._latencies:
            sorted_lat = sorted(self._latencies)
            n = len(sorted_lat)
            p50 = sorted_lat[int(n * 0.50)]
            p95 = sorted_lat[int(n * 0.95)]
            p99 = sorted_lat[min(int(n * 0.99), n - 1)]

        avg_entropy = (
            sum(self._entropy_records) / len(self._entropy_records)
            if self._entropy_records
            else 0.0
        )
        max_entropy = max(self._entropy_records) if self._entropy_records else 0.0

        return {
            "total_requests": total,
            "success_count": self._success_count,
            "error_counts": dict(self._error_counts),
            "intent_distribution": dict(self._intent_counts),
            "cache_hits": dict(self._cache_hits),
            "latency_p50_ms": p50,
            "latency_p95_ms": p95,
            "latency_p99_ms": p99,
            "average_semantic_entropy": round(avg_entropy, 4),
            "max_semantic_entropy": round(max_entropy, 4),
            "tier_counts": dict(self._tier_counts),
            "uptime_seconds": int(time.time() - self._start_time),
        }
