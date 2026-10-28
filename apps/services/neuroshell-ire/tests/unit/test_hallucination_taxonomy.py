# NeuroShell IRE — Unit Tests for Hallucination Taxonomy & Validator Audit Findings

import pytest
from src.schemas.intent_schema import (
    IntentSchema, Target, TargetType, IntentType,
    RegexValidationError, SchemaValidationError, NetworkValidationError
)
from src.schemas.planner_contract import PlannerContract, PlannerTarget
from src.validation.hallucination_taxonomy import HallucinationClass, ValidationFinding
from src.validation import (
    SchemaValidator, RegexValidator, NetworkArchitectureValidator,
    ScopeGuard, ContractValidator
)
from src.pipeline.contract_builder import ContractBuilder


def test_hallucination_class_enum_values():
    """Verify all required taxonomy classes are present in HallucinationClass."""
    expected_classes = {
        "FABRICATED_CVE",
        "TARGET_TYPE_MISMATCH",
        "CONTRADICTORY_ACTION_TARGET",
        "FABRICATED_PARAMETER",
        "UNGROUNDED_CONFIDENCE",
        "OUT_OF_SCOPE_TARGET",
    }
    actual_classes = {c.value for c in HallucinationClass}
    assert expected_classes.issubset(actual_classes)


def test_fabricated_cve_classification():
    """Verify invalid CVE format triggers FABRICATED_CVE hallucination finding."""
    validator = RegexValidator()
    schema = IntentSchema(
        intent=IntentType.VULNERABILITY_AUDIT,
        target=Target(type=TargetType.IP, value="192.168.1.10"),
        cve_ids=["CVE-2021-44228"],
        confidence=0.9,
    )
    object.__setattr__(schema, "cve_ids", ["INVALID-CVE-2024-9999"])
    with pytest.raises(RegexValidationError) as exc_info:
        validator.validate(schema)

    findings = getattr(exc_info.value, "findings", [])
    failed_finding = next((f for f in findings if not f.passed), None)
    assert failed_finding is not None
    assert failed_finding.hallucination_class == HallucinationClass.FABRICATED_CVE
    assert failed_finding.severity == "block"


def test_target_type_mismatch_classification():
    """Verify target type IP with non-IP string triggers TARGET_TYPE_MISMATCH finding."""
    validator = RegexValidator()
    schema = IntentSchema(
        intent=IntentType.NETWORK_SCAN,
        target=Target(type=TargetType.IP, value="not-a-valid-ip"),
        confidence=0.85,
    )
    with pytest.raises(RegexValidationError) as exc_info:
        validator.validate(schema)

    findings = getattr(exc_info.value, "findings", [])
    failed_finding = next((f for f in findings if not f.passed), None)
    assert failed_finding is not None
    assert failed_finding.hallucination_class == HallucinationClass.TARGET_TYPE_MISMATCH
    assert failed_finding.severity == "block"


def test_target_type_mismatch_network_validator():
    """Verify CIDR slash in IP target triggers TARGET_TYPE_MISMATCH in network_validator."""
    validator = NetworkArchitectureValidator()
    validator.settings.engagement_mode = "strict"
    schema = IntentSchema(
        intent=IntentType.NETWORK_SCAN,
        target=Target(type=TargetType.IP, value="192.168.1.0/24"),
        confidence=0.9,
    )
    with pytest.raises(NetworkValidationError) as exc_info:
        validator.validate(schema)

    findings = getattr(exc_info.value, "findings", [])
    failed_finding = next((f for f in findings if not f.passed), None)
    assert failed_finding is not None
    assert failed_finding.hallucination_class == HallucinationClass.TARGET_TYPE_MISMATCH


def test_contradictory_action_target_classification():
    """Verify missing contract intent triggers CONTRADICTORY_ACTION_TARGET finding."""
    validator = ContractValidator()
    contract = PlannerContract(
        intent=IntentType.NETWORK_SCAN,
        target=PlannerTarget(type="IP", value="192.168.1.1"),
        confidence=0.9,
    )
    object.__setattr__(contract, "intent", None)
    with pytest.raises(ValueError) as exc_info:
        validator.validate(contract)

    findings = getattr(exc_info.value, "findings", [])
    failed_finding = next((f for f in findings if not f.passed), None)
    assert failed_finding is not None
    assert failed_finding.hallucination_class == HallucinationClass.CONTRADICTORY_ACTION_TARGET


def test_fabricated_parameter_port_out_of_range():
    """Verify out-of-bounds port number triggers FABRICATED_PARAMETER finding."""
    validator = RegexValidator()
    schema = IntentSchema(
        intent=IntentType.NETWORK_SCAN,
        target=Target(type=TargetType.IP, value="192.168.1.1"),
        ports=[80],
        confidence=0.9,
    )
    object.__setattr__(schema, "ports", [99999])
    with pytest.raises(RegexValidationError) as exc_info:
        validator.validate(schema)

    findings = getattr(exc_info.value, "findings", [])
    failed_finding = next((f for f in findings if not f.passed), None)
    assert failed_finding is not None
    assert failed_finding.hallucination_class == HallucinationClass.FABRICATED_PARAMETER


def test_fabricated_parameter_shell_metacharacters():
    """Verify shell metacharacter injection in target triggers FABRICATED_PARAMETER finding."""
    validator = RegexValidator()
    schema = IntentSchema(
        intent=IntentType.NETWORK_SCAN,
        target=Target(type=TargetType.IP, value="192.168.1.1"),
        modifiers=["stealth; rm -rf /"],
        confidence=0.9,
    )
    with pytest.raises(RegexValidationError) as exc_info:
        validator.validate(schema)

    findings = getattr(exc_info.value, "findings", [])
    failed_finding = next((f for f in findings if not f.passed), None)
    assert failed_finding is not None
    assert failed_finding.hallucination_class == HallucinationClass.FABRICATED_PARAMETER


def test_ungrounded_confidence_out_of_range():
    """Verify contract confidence out of [0, 1] range triggers UNGROUNDED_CONFIDENCE finding."""
    validator = ContractValidator()
    contract = PlannerContract(
        intent=IntentType.NETWORK_SCAN,
        target=PlannerTarget(type="IP", value="192.168.1.1"),
        confidence=0.9,
    )
    object.__setattr__(contract, "confidence", 1.5)
    with pytest.raises(ValueError) as exc_info:
        validator.validate(contract)

    findings = getattr(exc_info.value, "findings", [])
    failed_finding = next((f for f in findings if not f.passed), None)
    assert failed_finding is not None
    assert failed_finding.hallucination_class == HallucinationClass.UNGROUNDED_CONFIDENCE


def test_ungrounded_confidence_ambiguous_intent():
    """Verify AMBIGUOUS intent with high confidence triggers UNGROUNDED_CONFIDENCE finding."""
    validator = SchemaValidator()
    raw_dict = {
        "intent": "AMBIGUOUS",
        "target": {"type": "IP", "value": "192.168.1.1"},
        "confidence": 0.8,
    }
    with pytest.raises(SchemaValidationError) as exc_info:
        validator.validate(raw_dict)

    findings = getattr(exc_info.value, "findings", [])
    failed_finding = next((f for f in findings if not f.passed), None)
    assert failed_finding is not None
    assert failed_finding.hallucination_class == HallucinationClass.UNGROUNDED_CONFIDENCE


def test_out_of_scope_target_classification():
    """Verify target IP outside engagement scope triggers OUT_OF_SCOPE_TARGET finding."""
    validator = NetworkArchitectureValidator()
    validator.settings.engagement_mode = "strict"
    validator.settings.engagement_scope = "10.0.0.0/8"
    schema = IntentSchema(
        intent=IntentType.NETWORK_SCAN,
        target=Target(type=TargetType.IP, value="192.168.1.1"),
        confidence=0.9,
    )
    with pytest.raises(NetworkValidationError) as exc_info:
        validator.validate(schema)

    findings = getattr(exc_info.value, "findings", [])
    failed_finding = next((f for f in findings if not f.passed), None)
    assert failed_finding is not None
    assert failed_finding.hallucination_class == HallucinationClass.OUT_OF_SCOPE_TARGET


def test_fully_valid_intent_produces_all_passed_findings():
    """Verify a valid intent produces a validation_findings list where all findings passed."""
    schema = IntentSchema(
        intent=IntentType.NETWORK_SCAN,
        target=Target(type=TargetType.IP, value="192.168.1.5"),
        ports=[80, 443],
        modifiers=["stealth"],
        cve_ids=["CVE-2021-44228"],
        confidence=0.95,
    )

    all_findings = []

    sv = SchemaValidator()
    sv.validate(schema)
    all_findings.extend(sv.last_findings)

    rv = RegexValidator()
    rv.validate(schema)
    all_findings.extend(rv.last_findings)

    net_val = NetworkArchitectureValidator()
    net_val.settings.engagement_scope = "192.168.0.0/16"
    net_val.settings.engagement_mode = "warn"
    net_val.validate(schema)
    all_findings.extend(net_val.last_findings)

    scope_guard = ScopeGuard()
    scope_guard.check(schema, "scan 192.168.1.5")
    all_findings.extend(scope_guard.last_findings)

    assert len(all_findings) > 0
    assert all(f.passed for f in all_findings)
    assert all(f.hallucination_class is None for f in all_findings)


def test_contract_builder_raises_on_blocking_finding():
    """Verify ContractBuilder raises ValueError when any finding is severity='block' and passed=False."""
    builder = ContractBuilder()
    schema = IntentSchema(
        intent=IntentType.NETWORK_SCAN,
        target=Target(type=TargetType.IP, value="192.168.1.5"),
        confidence=0.9,
    )
    blocking_findings = [
        ValidationFinding(
            validator="regex_validator",
            passed=False,
            hallucination_class=HallucinationClass.FABRICATED_PARAMETER,
            detail="Port out of range",
            severity="block",
        )
    ]
    with pytest.raises(ValueError) as exc_info:
        builder.build(schema, validation_findings=blocking_findings)

    assert "blocking validation findings" in str(exc_info.value)


def test_contract_builder_allows_warn_findings():
    """Verify ContractBuilder does NOT raise when only severity='warn' findings are present."""
    builder = ContractBuilder()
    schema = IntentSchema(
        intent=IntentType.NETWORK_SCAN,
        target=Target(type=TargetType.IP, value="192.168.1.5"),
        confidence=0.9,
    )
    warn_findings = [
        ValidationFinding(
            validator="scope_guard",
            passed=False,
            hallucination_class=HallucinationClass.OUT_OF_SCOPE_TARGET,
            detail="Target appears to be public IP",
            severity="warn",
        ),
        ValidationFinding(
            validator="schema_validator",
            passed=True,
            hallucination_class=None,
            detail="Schema passed",
            severity="block",
        ),
    ]
    contract = builder.build(schema, validation_findings=warn_findings)
    assert contract is not None
    assert contract.target.value == "192.168.1.5"
