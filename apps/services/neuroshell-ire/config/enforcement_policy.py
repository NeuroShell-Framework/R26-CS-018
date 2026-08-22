# NeuroShell IRE — Unified Enforcement Policy Engine
# Central policy configuration mapping HallucinationClass entries to enforcement actions (BLOCK, WARN, ESCALATE).

from enum import Enum
from typing import Dict, Literal, Optional
from config.settings import get_settings, Settings


class EnforcementMode(str, Enum):
    BLOCK = "block"
    WARN = "warn"
    ESCALATE = "escalate"


POLICY_REASONING: Dict[str, str] = {
    "FABRICATED_PARAMETER": (
        "Out-of-bounds parameters (e.g. invalid ports) or shell metacharacter injection "
        "present immediate execution risks and must be hard-blocked."
    ),
    "CONTRADICTORY_ACTION_TARGET": (
        "Incompatible action-target pairings or missing intent violate safety invariants "
        "and must be hard-blocked."
    ),
    "TARGET_TYPE_MISMATCH": (
        "Structural mismatch between target type and string value prevents downstream "
        "planner execution and must be hard-blocked."
    ),
    "FABRICATED_CVE": (
        "Malformed CVE ID syntax indicates complete LLM hallucination and must be hard-blocked."
    ),
    "UNGROUNDED_CONFIDENCE": (
        "Syntactically valid but unindexed CVEs may represent novel external vulnerabilities; "
        "permitted with advisory warning."
    ),
    "OUT_OF_SCOPE_TARGET": (
        "Out-of-scope targets are WARNED in research mode to allow safe experimentation, "
        "but BLOCKED in strict production mode."
    ),
}


class EnforcementPolicy:
    """
    Central source of truth for hallucination classification enforcement.
    Derives enforcement mode (BLOCK, WARN, ESCALATE) dynamically based on environment configuration.
    """

    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()

    def get_mode(self, hallucination_class: Optional[object]) -> EnforcementMode:
        from src.validation.hallucination_taxonomy import HallucinationClass
        if hallucination_class is None:
            return EnforcementMode.BLOCK

        h_val = hallucination_class.value if isinstance(hallucination_class, HallucinationClass) else str(hallucination_class)

        if h_val == HallucinationClass.OUT_OF_SCOPE_TARGET.value:
            # Configurable per environment: strict -> BLOCK, research -> WARN
            scope_mode = getattr(self.settings, "scope_mode", "research").lower()
            engagement_mode = getattr(self.settings, "engagement_mode", "warn").lower()
            if scope_mode == "strict" or engagement_mode == "strict":
                return EnforcementMode.BLOCK
            return EnforcementMode.WARN

        if h_val == HallucinationClass.UNGROUNDED_CONFIDENCE.value:
            return EnforcementMode.WARN

        if h_val in (
            HallucinationClass.FABRICATED_PARAMETER.value,
            HallucinationClass.CONTRADICTORY_ACTION_TARGET.value,
            HallucinationClass.TARGET_TYPE_MISMATCH.value,
            HallucinationClass.FABRICATED_CVE.value,
        ):
            return EnforcementMode.BLOCK

        return EnforcementMode.BLOCK

    def get_severity(self, hallucination_class: Optional[object]) -> Literal["block", "warn", "escalate"]:
        mode = self.get_mode(hallucination_class)
        if mode == EnforcementMode.WARN:
            return "warn"
        if mode == EnforcementMode.ESCALATE:
            return "escalate"
        return "block"

    def get_policy_summary(self) -> dict:
        from src.validation.hallucination_taxonomy import HallucinationClass
        policy_map = {}
        for h_class in HallucinationClass:
            policy_map[h_class.value] = self.get_mode(h_class).value

        return {
            "scope_mode": getattr(self.settings, "scope_mode", "research"),
            "engagement_mode": getattr(self.settings, "engagement_mode", "warn"),
            "policy": policy_map,
            "reasoning": dict(POLICY_REASONING),
        }


_policy_instance: Optional[EnforcementPolicy] = None


def get_enforcement_policy(settings: Optional[Settings] = None) -> EnforcementPolicy:
    if settings is not None:
        return EnforcementPolicy(settings=settings)
    global _policy_instance
    if _policy_instance is None:
        _policy_instance = EnforcementPolicy()
    return _policy_instance
