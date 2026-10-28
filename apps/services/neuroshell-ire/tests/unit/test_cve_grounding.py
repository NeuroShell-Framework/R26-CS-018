# NeuroShell IRE — Unit Tests for Offline CVE Grounding Verification

import pytest
from src.schemas.intent_schema import (
    IntentSchema, Target, TargetType, IntentType, RegexValidationError
)
from src.validation.hallucination_taxonomy import HallucinationClass, ValidationFinding
from src.validation.regex_validator import RegexValidator
from src.pipeline.contract_builder import ContractBuilder


def test_known_cve_passes_grounding_check():
    """Known CVE from grounding dataset (CVE-2021-44228) passes validation cleanly."""
    validator = RegexValidator()
    schema = IntentSchema(
        intent=IntentType.VULNERABILITY_AUDIT,
        target=Target(type=TargetType.IP, value="192.168.1.10"),
        cve_ids=["CVE-2021-44228"],
        confidence=0.9,
    )
    validated = validator.validate(schema)
    assert validated is not None

    findings = validator.last_findings
    cve_finding = next((f for f in findings if f.validator == "regex_validator" and f.passed and "CVE" in f.detail), None)
    assert cve_finding is not None
    assert "validated against local grounding dataset" in cve_finding.detail
    assert cve_finding.hallucination_class is None


def test_syntactically_valid_unindexed_cve_returns_warning():
    """Syntactically valid CVE not in grounding dataset returns severity='warn' and does NOT raise."""
    validator = RegexValidator()
    schema = IntentSchema(
        intent=IntentType.VULNERABILITY_AUDIT,
        target=Target(type=TargetType.IP, value="192.168.1.10"),
        cve_ids=["CVE-2024-99999"],
        confidence=0.9,
    )
    # Does NOT raise exception!
    validated = validator.validate(schema)
    assert validated is not None

    findings = validator.last_findings
    warn_finding = next((f for f in findings if not f.passed and f.severity == "warn"), None)
    assert warn_finding is not None
    assert warn_finding.hallucination_class in (HallucinationClass.UNGROUNDED_CONFIDENCE, HallucinationClass.FABRICATED_CVE)
    assert "is not present in local offline grounding dataset" in warn_finding.detail


def test_cve_shaped_fabricated_string_returns_warning():
    """CVE-shaped string not in grounding set returns severity='warn'."""
    validator = RegexValidator()
    schema = IntentSchema(
        intent=IntentType.VULNERABILITY_AUDIT,
        target=Target(type=TargetType.IP, value="192.168.1.10"),
        cve_ids=["CVE-2099-1234567"],
        confidence=0.9,
    )
    validated = validator.validate(schema)
    assert validated is not None

    findings = validator.last_findings
    warn_finding = next((f for f in findings if not f.passed and f.severity == "warn"), None)
    assert warn_finding is not None
    assert warn_finding.severity == "warn"


def test_gibberish_invalid_cve_syntax_blocks():
    """Gibberish string not matching CVE syntax returns severity='block' and raises RegexValidationError."""
    validator = RegexValidator()
    schema = IntentSchema(
        intent=IntentType.VULNERABILITY_AUDIT,
        target=Target(type=TargetType.IP, value="192.168.1.10"),
        cve_ids=["CVE-2021-44228"],
        confidence=0.9,
    )
    object.__setattr__(schema, "cve_ids", ["INVALID-CVE-GIBBERISH"])

    with pytest.raises(RegexValidationError) as exc_info:
        validator.validate(schema)

    findings = getattr(exc_info.value, "findings", [])
    block_finding = next((f for f in findings if not f.passed and f.severity == "block"), None)
    assert block_finding is not None
    assert block_finding.hallucination_class == HallucinationClass.FABRICATED_CVE
    assert "Invalid CVE format" in block_finding.detail


def test_contract_builder_allows_unindexed_cve_warning():
    """ContractBuilder allows contract generation when unindexed CVE warning finding is present."""
    builder = ContractBuilder()
    schema = IntentSchema(
        intent=IntentType.VULNERABILITY_AUDIT,
        target=Target(type=TargetType.IP, value="192.168.1.10"),
        cve_ids=["CVE-2024-99999"],
        confidence=0.9,
    )
    warn_findings = [
        ValidationFinding(
            validator="regex_validator",
            passed=False,
            hallucination_class=HallucinationClass.FABRICATED_CVE,
            detail="CVE-2024-99999 is syntactically valid but not present in local grounding dataset",
            severity="warn",
        )
    ]
    contract = builder.build(schema, validation_findings=warn_findings)
    assert contract is not None
    assert contract.target.value == "192.168.1.10"
