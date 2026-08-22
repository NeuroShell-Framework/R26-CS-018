# NeuroShell IRE — Unit Tests for Unified Enforcement Policy Engine

import pytest
from fastapi.testclient import TestClient

from config.enforcement_policy import EnforcementPolicy, EnforcementMode, get_enforcement_policy
from config.settings import Settings
from src.api.main import app
from src.schemas.intent_schema import IntentSchema, Target, TargetType, IntentType, ScopeError, RegexValidationError
from src.validation.hallucination_taxonomy import HallucinationClass
from src.validation.scope_guard import ScopeGuard
from src.validation.regex_validator import RegexValidator


def test_scope_guard_warns_in_research_mode(monkeypatch):
    """ScopeGuard produces warning finding in research mode for public target."""
    settings = Settings(scope_mode="research")
    guard = ScopeGuard()
    guard.settings = settings

    schema = IntentSchema(
        intent=IntentType.NETWORK_SCAN,
        target=Target(type=TargetType.IP, value="8.8.8.8"),
        confidence=0.9,
    )
    validated, warnings = guard.check(schema, raw_input="scan 8.8.8.8")
    assert validated is not None
    assert len(warnings) == 1
    assert "public address" in warnings[0]

    findings = guard.last_findings
    scope_finding = next((f for f in findings if f.hallucination_class == HallucinationClass.OUT_OF_SCOPE_TARGET), None)
    assert scope_finding is not None
    assert scope_finding.severity == "warn"


def test_scope_guard_blocks_in_strict_mode(monkeypatch):
    """ScopeGuard blocks and raises ScopeError in strict mode for public target."""
    settings = Settings(scope_mode="strict")
    guard = ScopeGuard()
    guard.settings = settings

    policy = get_enforcement_policy(settings)
    assert policy.get_severity(HallucinationClass.OUT_OF_SCOPE_TARGET) == "block"

    schema = IntentSchema(
        intent=IntentType.NETWORK_SCAN,
        target=Target(type=TargetType.IP, value="8.8.8.8"),
        confidence=0.9,
    )

    with pytest.raises(ScopeError) as exc_info:
        guard.check(schema, raw_input="scan 8.8.8.8")

    findings = getattr(exc_info.value, "findings", [])
    scope_finding = next((f for f in findings if f.hallucination_class == HallucinationClass.OUT_OF_SCOPE_TARGET), None)
    assert scope_finding is not None
    assert scope_finding.severity == "block"


def test_admin_enforcement_policy_endpoint():
    """GET /admin/enforcement-policy endpoint returns current effective policy mapping and reasoning."""
    client = TestClient(app)
    response = client.get("/admin/enforcement-policy", headers={"X-API-Key": "test_api_key"})
    assert response.status_code == 200

    data = response.json()
    assert "scope_mode" in data
    assert "policy" in data
    assert "reasoning" in data

    policy_map = data["policy"]
    assert policy_map["FABRICATED_PARAMETER"] == "block"
    assert policy_map["CONTRADICTORY_ACTION_TARGET"] == "block"
    assert policy_map["FABRICATED_CVE"] == "block"
    assert policy_map["UNGROUNDED_CONFIDENCE"] == "warn"


def test_monkeypatch_policy_turns_warn_into_block(monkeypatch):
    """Monkeypatching UNGROUNDED_CONFIDENCE policy to BLOCK causes unindexed CVE validation to raise RegexValidationError."""
    validator = RegexValidator()

    # Original policy: UNGROUNDED_CONFIDENCE -> "warn"
    schema = IntentSchema(
        intent=IntentType.VULNERABILITY_AUDIT,
        target=Target(type=TargetType.IP, value="192.168.1.1"),
        cve_ids=["CVE-2024-99999"],
        confidence=0.9,
    )
    # With original policy, does not raise exception
    validator.validate(schema)
    assert any(f.severity == "warn" for f in validator.last_findings)

    # Monkeypatch get_severity to return "block" for UNGROUNDED_CONFIDENCE
    policy = get_enforcement_policy()
    orig_get_severity = policy.get_severity

    def custom_get_severity(h_class):
        if h_class == HallucinationClass.UNGROUNDED_CONFIDENCE:
            return "block"
        return orig_get_severity(h_class)

    monkeypatch.setattr(policy, "get_severity", custom_get_severity)

    # Now validator must block and raise RegexValidationError!
    with pytest.raises(RegexValidationError) as exc_info:
        validator.validate(schema)

    findings = getattr(exc_info.value, "findings", [])
    block_finding = next((f for f in findings if f.hallucination_class == HallucinationClass.UNGROUNDED_CONFIDENCE), None)
    assert block_finding is not None
    assert block_finding.severity == "block"
