# NeuroShell IRE — IRE Pipeline
# Orchestrate the full intent recognition pipeline

import time
from typing import Optional, Union
from src.preprocessing import InputNormalizer, AliasResolver
from src.inference import OllamaInferenceEngine
from src.validation import JSONParser, SchemaValidator, RegexValidator, ScopeGuard, NetworkArchitectureValidator
from src.schemas.intent_schema import (
    IREResponse, IREResponseV2, ParseRequest,
    ParseRequestV2, IntentType,
    IREError, JSONParseError, SchemaValidationError,
    RegexValidationError, ScopeError, InferenceError,
    NetworkValidationError, RBACError
)
from src.middleware import (
    RBACGuard, SessionContextStore,
    AdversarialDetector, SemanticCache,
    SubIntentClassifier
)
from src.utils.logging_config import get_logger
from src.utils.metrics_collector import MetricsCollector
from config.feature_flags import get_feature_flags


class IREPipeline:
    def __init__(self):
        self.logger = get_logger(__name__)
        self.normalizer = InputNormalizer()
        self.resolver = AliasResolver()
        self.inference_engine = OllamaInferenceEngine()
        self.json_parser = JSONParser()
        self.schema_validator = SchemaValidator()
        self.regex_validator = RegexValidator()
        self.scope_guard = ScopeGuard()
        self.network_validator = NetworkArchitectureValidator()
        self.metrics = MetricsCollector()

        self.flags = get_feature_flags()
        self.rbac_guard = RBACGuard()
        self.session_context = SessionContextStore()
        self.adversarial = AdversarialDetector()
        self.semantic_cache = SemanticCache()
        self.sub_intent_clf = SubIntentClassifier()

        self.logger.info(
            "pipeline_initialized",
            status="ready",
            middleware_enabled=[
                "rbac" if self.flags.rbac else None,
                "session_context" if self.flags.session_context else None,
                "adversarial" if self.flags.adversarial_detection else None,
                "semantic_cache" if self.flags.semantic_cache else None,
                "sub_intent" if self.flags.sub_intent else None,
            ]
        )

    def parse(
        self,
        request: Union[ParseRequest, ParseRequestV2]
    ) -> IREResponseV2:
        if isinstance(request, ParseRequest) and not isinstance(request, ParseRequestV2):
            request = ParseRequestV2(
                command=request.command,
                session_id=request.session_id,
                role="analyst",
                explain=False,
            )

        pipeline_start = time.time()

        def elapsed() -> int:
            return int((time.time() - pipeline_start) * 1000)

        command_with_context = request.command

        # M1 — Adversarial detection
        try:
            self.adversarial.scan(request.command, session_id=request.session_id or "")
        except ScopeError as e:
            self.metrics.record_error("adversarial_detector")
            return IREResponseV2.error_response(
                error="ADVERSARIAL_INPUT_BLOCKED",
                stage="adversarial_detector",
                detail=e.message,
                latency_ms=elapsed()
            )
        except Exception as e:
            self.logger.error("adversarial_middleware_error", error=str(e))

        # M2 — RBAC pre-inference check
        try:
            self.rbac_guard.pre_inference_check(request.role)
        except RBACError as e:
            self.metrics.record_error("rbac_guard")
            return IREResponseV2.error_response(
                error="INTENT_ACCESS_DENIED",
                stage="rbac_guard",
                detail=e.message,
                latency_ms=elapsed()
            )
        except Exception as e:
            self.logger.error("rbac_middleware_error", error=str(e))

        # M3 — Session context injection
        try:
            command_with_context = self.session_context.inject_context(
                request.command, request.session_id
            )
        except Exception as e:
            self.logger.error("session_context_inject_error", error=str(e))
            command_with_context = request.command

        # M4 — Semantic cache lookup
        try:
            cached_response, cache_type = self.semantic_cache.lookup(command_with_context)
            if cached_response and cache_type == "semantic":
                v2_cached = IREResponseV2.from_v1(
                    cached_response,
                    cache_hit=cache_type,
                    rbac_role=request.role,
                    latency_ms=elapsed()
                )
                try:
                    v2_cached = self.sub_intent_clf.enrich(v2_cached)
                except Exception:
                    pass
                try:
                    self.session_context.update(
                        request.session_id, request.command, cached_response
                    )
                except Exception:
                    pass
                self.logger.info(
                    "pipeline_cache_hit",
                    cache_type=cache_type,
                    session_id=request.session_id,
                    latency_ms=elapsed()
                )
                return v2_cached
        except Exception as e:
            self.logger.error("semantic_cache_lookup_error", error=str(e))

        # Stage 1 — Input normalization
        try:
            normalized = self.normalizer.normalize(command_with_context)
        except ValueError as e:
            return IREResponseV2.error_response(
                error="INPUT_VALIDATION_FAILED",
                stage="input_normalizer",
                detail=str(e),
                latency_ms=elapsed()
            )

        # Stage 2 — Alias enrichment
        enriched = self.resolver.enrich(normalized)

        # Stage 3 — Inference
        try:
            raw_llm_output = self.inference_engine.generate(enriched)
        except InferenceError as e:
            self.metrics.record_error("inference")
            return IREResponseV2.error_response(
                error="INFERENCE_FAILED",
                stage=e.stage,
                detail=e.message,
                latency_ms=elapsed()
            )

        # Stage 4 — JSON parsing
        try:
            parsed_dict = self.json_parser.parse(raw_llm_output)
        except JSONParseError as e:
            self.metrics.record_error("json_parser")
            return IREResponseV2.error_response(
                error="JSON_PARSE_FAILED",
                stage=e.stage,
                detail=e.message,
                latency_ms=elapsed()
            )

        # Stage 5 — Schema validation
        try:
            intent_schema = self.schema_validator.validate(parsed_dict)
        except SchemaValidationError as e:
            self.metrics.record_error("schema_validator")
            return IREResponseV2.error_response(
                error="SCHEMA_VALIDATION_FAILED",
                stage=e.stage,
                detail=e.message,
                field=e.field,
                latency_ms=elapsed()
            )

        # Stage 6 — Regex validation
        try:
            intent_schema = self.regex_validator.validate(intent_schema)
        except RegexValidationError as e:
            self.metrics.record_error("regex_validator")
            return IREResponseV2.error_response(
                error="REGEX_VALIDATION_FAILED",
                stage=e.stage,
                detail=e.message,
                field=e.field,
                latency_ms=elapsed()
            )

        # Stage 6B — Network Architecture Validation
        arch_warnings = []
        try:
            intent_schema, arch_warnings = \
                self.network_validator.validate(intent_schema)
        except NetworkValidationError as e:
            self.metrics.record_error("network_validator")
            return IREResponseV2.error_response(
                error="NETWORK_ARCHITECTURE_VIOLATION",
                stage=e.stage,
                detail=e.message,
                field=e.field,
                latency_ms=elapsed()
            )
        except Exception as e:
            self.logger.error("network_validator_error", error=str(e))
            arch_warnings = []

        # Stage 7 — Scope check
        try:
            intent_schema, scope_warnings = self.scope_guard.check(
                intent_schema, request.command
            )
        except ScopeError as e:
            self.metrics.record_error("scope_guard")
            return IREResponseV2.error_response(
                error="SCOPE_VIOLATION",
                stage=e.stage,
                detail=e.message,
                latency_ms=elapsed()
            )

        # M5 — RBAC post-inference check
        try:
            self.rbac_guard.post_inference_check(request.role, intent_schema.intent)
        except RBACError as e:
            self.metrics.record_error("rbac_guard")
            return IREResponseV2.error_response(
                error="INTENT_ACCESS_DENIED",
                stage="rbac_guard",
                detail=e.message,
                latency_ms=elapsed()
            )
        except Exception as e:
            self.logger.error("rbac_post_middleware_error", error=str(e))

        latency = elapsed()
        v1_response = IREResponse.from_intent_schema(
            schema=intent_schema,
            latency_ms=latency,
            scope_warnings=scope_warnings + arch_warnings
        )

        # M7 — Store in semantic cache
        try:
            self.semantic_cache.store(command_with_context, v1_response)
        except Exception as e:
            self.logger.error("semantic_cache_store_error", error=str(e))

        # M8 — Build v2 response
        v2_response = IREResponseV2.from_v1(
            v1_response,
            rbac_role=request.role,
            schema_version=2
        )

        # M9 — Sub-intent enrichment
        try:
            v2_response = self.sub_intent_clf.enrich(v2_response, intent_schema)
        except Exception as e:
            self.logger.error("sub_intent_enrich_error", error=str(e))

        # M10 — Session context update
        try:
            self.session_context.update(
                request.session_id, request.command, v1_response
            )
        except Exception as e:
            self.logger.error("session_context_update_error", error=str(e))

        # M11 — Session info enrichment
        try:
            if request.session_id:
                info = self.session_context.get_session_info(request.session_id)
                if info:
                    v2_response.session_turns = info["turn_count"]
        except Exception as e:
            self.logger.error("session_info_error", error=str(e))

        # Record metrics
        self.metrics.record_success(
            intent=intent_schema.intent.value,
            latency_ms=latency,
            confidence=intent_schema.confidence
        )

        self.logger.info(
            "pipeline_complete",
            session_id=request.session_id,
            role=request.role,
            intent=intent_schema.intent.value,
            sub_intent=v2_response.sub_intent.value if v2_response.sub_intent else None,
            confidence=intent_schema.confidence,
            latency_ms=latency,
            scope_warnings=len(scope_warnings),
            cache_hit=v2_response.cache_hit,
            status="success"
        )

        return v2_response

    def health_check(self) -> dict:
        ollama_ok = self.inference_engine.health_check()
        session_stats = self.session_context.get_stats()
        cache_stats = self.semantic_cache.get_stats()
        return {
            "status": "healthy" if ollama_ok else "degraded",
            "ollama": "connected" if ollama_ok else "unreachable",
            "model": self.inference_engine.settings.ollama_model,
            "pipeline_stages": 7,
            "middleware": {
                "rbac": self.flags.rbac,
                "session_context": self.flags.session_context,
                "adversarial_detection": self.flags.adversarial_detection,
                "semantic_cache": self.flags.semantic_cache,
                "sub_intent": self.flags.sub_intent,
            },
            "session_store": session_stats,
            "semantic_cache": cache_stats,
            "inference_cache_size": len(self.inference_engine._cache),
        }
