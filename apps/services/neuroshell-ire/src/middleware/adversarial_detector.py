import re
import math
from typing import List, Tuple, Optional
from dataclasses import dataclass, field
from config.feature_flags import get_feature_flags
from src.schemas.intent_schema import ScopeError
from src.utils.logging_config import get_logger


@dataclass
class ThreatSignal:
    """A single detected threat signal with its weight."""
    signal_type: str
    description: str
    weight: float
    matched_text: str = ""


@dataclass
class ThreatAssessment:
    """Full threat assessment result for one input."""
    threat_score: float
    signals: List[ThreatSignal] = field(default_factory=list)
    blocked: bool = False
    block_reason: Optional[str] = None

    def add_signal(self, signal: ThreatSignal) -> None:
        self.signals.append(signal)
        self.threat_score = min(1.0, self.threat_score + signal.weight)


class AdversarialDetector:
    def __init__(self):
        self.logger = get_logger(__name__)
        self.flags = get_feature_flags()
        self._threshold = self.flags.get_tuning(
            "adversarial_classifier_threshold", 0.7
        )

        # Layer A: Lexical injection patterns
        self._INJECTION_PATTERNS: List[Tuple[re.Pattern, str, float]] = [
            (re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", re.I),
             "classic ignore-instructions injection", 0.9),
            (re.compile(r"forget\s+(everything|all|your\s+instructions?)", re.I),
             "forget-instructions injection", 0.9),
            (re.compile(r"you\s+are\s+now\s+(?!scanning|checking|running)", re.I),
             "persona-override injection", 0.8),
            (re.compile(r"act\s+as\s+(a\s+)?(?!nmap|scanner|tool)(different|new|another|evil|unrestricted)", re.I),
             "role-override injection", 0.8),
            (re.compile(r"jailbreak", re.I),
             "explicit jailbreak keyword", 1.0),
            (re.compile(r"dan\s+mode", re.I),
             "DAN mode jailbreak", 1.0),
            (re.compile(r"prompt\s*injection", re.I),
             "explicit prompt injection reference", 0.9),
            (re.compile(r"(system|assistant|user)\s*:\s*you\s+(must|shall|will)", re.I),
             "role-prefix injection attempt", 0.85),
            (re.compile(r"<\|im_(start|end)\|>", re.I),
             "Gemma control token injection", 1.0),
            (re.compile(r"<\|think\|>", re.I),
             "Gemma think token injection", 0.95),
            (re.compile(r"\[\s*INST\s*\]|\[\/\s*INST\s*\]", re.I),
             "Llama instruction token injection", 0.9),
            (re.compile(r"###\s*(instruction|system|human|assistant)", re.I),
             "Alpaca/ChatML template injection", 0.85),
            (re.compile(r"disregard\s+(all\s+)?(prior|previous|your)", re.I),
             "disregard-instructions variant", 0.85),
            (re.compile(r"new\s+instructions?\s*:", re.I),
             "new-instructions injection", 0.8),
            (re.compile(r"override\s+(previous\s+)?(instructions?|rules?|guidelines?)", re.I),
             "override-instructions injection", 0.85),
        ]

        # Layer B: Structural anomaly patterns
        self._STRUCTURAL_PATTERNS: List[Tuple[re.Pattern, str, float]] = [
            (re.compile(r"(\\x[0-9a-f]{2}){4,}", re.I),
             "hex encoding sequence", 0.6),
            (re.compile(r"(%[0-9a-f]{2}){4,}", re.I),
             "URL encoding sequence", 0.5),
            (re.compile(r"base64\s*:\s*[A-Za-z0-9+/]{20,}", re.I),
             "base64 payload", 0.7),
            (re.compile(r"<script[\s>]", re.I),
             "script tag injection", 0.8),
            (re.compile(r"\$\{[^}]{0,50}\}", re.I),
             "template expression injection", 0.6),
            (re.compile(r"eval\s*\(|exec\s*\(|__import__\s*\(", re.I),
             "code execution attempt", 0.9),
            (re.compile(r"(rm\s+-rf|del\s+/[sq]|format\s+c:)", re.I),
             "destructive command in input", 0.8),
        ]

        self.logger.info(
            "adversarial_detector_initialized",
            extra={
                "injection_patterns": len(self._INJECTION_PATTERNS),
                "structural_patterns": len(self._STRUCTURAL_PATTERNS),
                "threshold": self._threshold
            }
        )

    def _layer_a_lexical(self, text: str, assessment: ThreatAssessment) -> None:
        for pattern, description, weight in self._INJECTION_PATTERNS:
            if assessment.threat_score >= self._threshold:
                break
            match = pattern.search(text)
            if match:
                assessment.add_signal(ThreatSignal(
                    signal_type="injection_phrase",
                    description=description,
                    weight=weight,
                    matched_text=match.group(0)[:50]
                ))

    def _layer_b_structural(self, text: str, assessment: ThreatAssessment) -> None:
        for pattern, description, weight in self._STRUCTURAL_PATTERNS:
            if assessment.threat_score >= self._threshold:
                break
            match = pattern.search(text)
            if match:
                assessment.add_signal(ThreatSignal(
                    signal_type="structural_anomaly",
                    description=description,
                    weight=weight,
                    matched_text=match.group(0)[:50]
                ))

        # Special character density check
        if len(text) > 20:
            special_chars = sum(
                1 for c in text
                if not c.isalnum() and c not in " .,;:-_/\\'\"()"
            )
            density = special_chars / len(text)
            if density > 0.30:
                assessment.add_signal(ThreatSignal(
                    signal_type="high_special_char_density",
                    description=f"Special char density {density:.1%} exceeds 30%",
                    weight=0.4,
                    matched_text=f"density={density:.2f}"
                ))

        # Suspiciously long single token
        words = text.split()
        for word in words:
            if len(word) > 100:
                assessment.add_signal(ThreatSignal(
                    signal_type="abnormal_token_length",
                    description=f"Single token length {len(word)} exceeds 100",
                    weight=0.3,
                    matched_text=word[:30] + "..."
                ))
                break

        # Repeated phrase detection
        if len(text) > 50:
            words_lower = text.lower().split()
            for size in [3, 4, 5]:
                ngrams = [
                    " ".join(words_lower[i:i+size])
                    for i in range(len(words_lower) - size + 1)
                ]
                for ngram in set(ngrams):
                    if len(ngram) >= 10 and ngrams.count(ngram) > 3:
                        assessment.add_signal(ThreatSignal(
                            signal_type="repeated_phrase",
                            description=f"Phrase repeated {ngrams.count(ngram)}x",
                            weight=0.35,
                            matched_text=ngram[:40]
                        ))
                        break

    def _layer_c_score(self, assessment: ThreatAssessment) -> None:
        # Auto-block on critical signals (weight >= 0.95)
        critical = [s for s in assessment.signals if s.weight >= 0.95]
        if critical:
            assessment.blocked = True
            assessment.block_reason = f"Critical threat signal: {critical[0].description}"
            return

        # Score threshold block
        if assessment.threat_score >= self._threshold:
            assessment.blocked = True
            assessment.block_reason = (
                f"Threat score {assessment.threat_score:.2f} "
                f"exceeds threshold {self._threshold:.2f}. "
                f"Signals: {[s.signal_type for s in assessment.signals]}"
            )

    def assess(self, text: str) -> ThreatAssessment:
        assessment = ThreatAssessment(threat_score=0.0)
        self._layer_a_lexical(text, assessment)
        self._layer_b_structural(text, assessment)
        self._layer_c_score(assessment)
        return assessment

    def scan(self, text: str, session_id: str = "") -> None:
        if not self.flags.adversarial_detection:
            return

        assessment = self.assess(text)

        if assessment.blocked:
            self.logger.warning(
                "adversarial_input_blocked",
                extra={
                    "session_id": session_id,
                    "threat_score": assessment.threat_score,
                    "block_reason": assessment.block_reason,
                    "signal_count": len(assessment.signals)
                }
            )
            raise ScopeError(f"Adversarial input detected: {assessment.block_reason}")

        if assessment.signals:
            self.logger.info(
                "adversarial_signals_detected_not_blocked",
                extra={
                    "session_id": session_id,
                    "threat_score": assessment.threat_score,
                    "signals": [s.signal_type for s in assessment.signals]
                }
            )
        else:
            self.logger.debug(
                "adversarial_scan_clean",
                extra={"session_id": session_id}
            )
