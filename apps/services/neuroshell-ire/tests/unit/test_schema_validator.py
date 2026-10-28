import pytest
from src.validation.schema_validator import SchemaValidator
from src.schemas.intent_schema import (
    IntentSchema, SchemaValidationError, IntentType, Target, TargetType
)


@pytest.fixture
def validator():
    return SchemaValidator()


@pytest.fixture
def valid_network_scan_dict():
    return {
        "intent": "NETWORK_SCAN",
        "target": {"type": "SUBNET", "value": "192.168.1.0/24"},
        "ports": [22, 80, 443],
        "modifiers": ["stealth"],
        "cve_ids": [],
        "confidence": 0.95
    }


class TestSchemaValidator:

    # === VALID INTENTS (9 tests) ===

    def test_validate_network_scan_intent(self, validator):
        """NETWORK_SCAN intent validates successfully."""
        data = {"intent": "NETWORK_SCAN", "target": {"type": "IP", "value": "192.168.1.1"}, "confidence": 0.9}
        result = validator.validate(data)
        assert result.intent == IntentType.NETWORK_SCAN

    def test_validate_vulnerability_audit_intent(self, validator):
        """VULNERABILITY_AUDIT intent validates successfully."""
        data = {"intent": "VULNERABILITY_AUDIT", "target": {"type": "IP", "value": "10.0.0.5"}, "confidence": 0.9}
        result = validator.validate(data)
        assert result.intent == IntentType.VULNERABILITY_AUDIT

    def test_validate_directory_bruteforce_intent(self, validator):
        """DIRECTORY_BRUTEFORCE intent validates successfully."""
        data = {"intent": "DIRECTORY_BRUTEFORCE", "target": {"type": "URL", "value": "http://example.com"}, "confidence": 0.9}
        result = validator.validate(data)
        assert result.intent == IntentType.DIRECTORY_BRUTEFORCE

    def test_validate_service_enumeration_intent(self, validator):
        """SERVICE_ENUMERATION intent validates successfully."""
        data = {"intent": "SERVICE_ENUMERATION", "target": {"type": "IP", "value": "192.168.1.1"}, "confidence": 0.9}
        result = validator.validate(data)
        assert result.intent == IntentType.SERVICE_ENUMERATION

    def test_validate_exploitation_intent(self, validator):
        """EXPLOITATION intent validates successfully."""
        data = {"intent": "EXPLOITATION", "target": {"type": "IP", "value": "10.0.0.1"}, "confidence": 0.9}
        result = validator.validate(data)
        assert result.intent == IntentType.EXPLOITATION

    def test_validate_password_attack_intent(self, validator):
        """PASSWORD_ATTACK intent validates successfully."""
        data = {"intent": "PASSWORD_ATTACK", "target": {"type": "DOMAIN", "value": "example.com"}, "confidence": 0.9}
        result = validator.validate(data)
        assert result.intent == IntentType.PASSWORD_ATTACK

    def test_validate_passive_recon_intent(self, validator):
        """PASSIVE_RECON intent validates successfully."""
        data = {"intent": "PASSIVE_RECON", "target": {"type": "DOMAIN", "value": "example.com"}, "confidence": 0.9}
        result = validator.validate(data)
        assert result.intent == IntentType.PASSIVE_RECON

    def test_validate_ambiguous_intent(self, validator):
        """AMBIGUOUS intent validates only when confidence < 0.5."""
        data = {"intent": "AMBIGUOUS", "target": {"type": "UNKNOWN", "value": ""}, "confidence": 0.3}
        result = validator.validate(data)
        assert result.intent == IntentType.AMBIGUOUS
        assert result.confidence < 0.5

    def test_validate_rejected_intent(self, validator):
        """REJECTED intent requires rejection_reason."""
        data = {"intent": "REJECTED", "target": {"type": "UNKNOWN", "value": ""}, "confidence": 0.0, "rejection_reason": "out of scope"}
        result = validator.validate(data)
        assert result.intent == IntentType.REJECTED
        assert result.rejection_reason == "out of scope"

    # === FIELD VALIDATION (6 tests) ===

    def test_validate_missing_confidence_raises(self, validator):
        """Missing confidence field raises SchemaValidationError."""
        data = {"intent": "NETWORK_SCAN", "target": {"type": "IP", "value": "10.0.0.1"}}
        with pytest.raises(SchemaValidationError):
            validator.validate(data)

    def test_validate_missing_intent_raises(self, validator):
        """Missing intent field raises SchemaValidationError."""
        data = {"target": {"type": "IP", "value": "10.0.0.1"}, "confidence": 0.9}
        with pytest.raises(SchemaValidationError):
            validator.validate(data)

    def test_validate_missing_target_raises(self, validator):
        """Missing target field raises SchemaValidationError."""
        data = {"intent": "NETWORK_SCAN", "confidence": 0.9}
        with pytest.raises(SchemaValidationError):
            validator.validate(data)

    def test_validate_extra_field_raises(self, validator):
        """Extra unknown field raises SchemaValidationError (extra=forbid)."""
        data = {"intent": "NETWORK_SCAN", "target": {"type": "IP", "value": "10.0.0.1"}, "confidence": 0.9, "unknown_field": "bad"}
        with pytest.raises(SchemaValidationError):
            validator.validate(data)

    def test_validate_invalid_intent_enum_raises(self, validator):
        """Invalid intent string raises SchemaValidationError."""
        data = {"intent": "INVALID_INTENT", "target": {"type": "IP", "value": "10.0.0.1"}, "confidence": 0.9}
        with pytest.raises(SchemaValidationError):
            validator.validate(data)

    def test_validate_invalid_target_type_raises(self, validator):
        """Invalid target type raises SchemaValidationError."""
        data = {"intent": "NETWORK_SCAN", "target": {"type": "INVALID_TYPE", "value": "10.0.0.1"}, "confidence": 0.9}
        with pytest.raises(SchemaValidationError):
            validator.validate(data)

    # === RETURN TYPE (2 tests) ===

    def test_validate_returns_intent_schema_instance(self, validator, valid_network_scan_dict):
        """Validator returns an IntentSchema instance."""
        result = validator.validate(valid_network_scan_dict)
        assert isinstance(result, IntentSchema)

    def test_validate_intent_field_is_intent_type_enum(self, validator, valid_network_scan_dict):
        """Intent field is an IntentType enum, not a string."""
        result = validator.validate(valid_network_scan_dict)
        assert isinstance(result.intent, IntentType)

    # === CVE AND PORT VALIDATION (3 tests) ===

    def test_validate_valid_cve_ids_accepted(self, validator):
        """Valid CVE IDs are accepted."""
        data = {"intent": "VULNERABILITY_AUDIT", "target": {"type": "IP", "value": "10.0.0.1"}, "confidence": 0.9, "cve_ids": ["CVE-2021-44228", "CVE-2017-0144"]}
        result = validator.validate(data)
        assert "CVE-2021-44228" in result.cve_ids

    def test_validate_invalid_cve_format_raises(self, validator):
        """Invalid CVE format raises SchemaValidationError."""
        data = {"intent": "VULNERABILITY_AUDIT", "target": {"type": "IP", "value": "10.0.0.1"}, "confidence": 0.9, "cve_ids": ["CVE-BAD-FORMAT"]}
        with pytest.raises(SchemaValidationError):
            validator.validate(data)

    def test_validate_port_out_of_range_raises(self, validator):
        """Port out of valid range (1-65535) raises SchemaValidationError."""
        data = {"intent": "NETWORK_SCAN", "target": {"type": "IP", "value": "10.0.0.1"}, "confidence": 0.9, "ports": [0, 99999]}
        with pytest.raises(SchemaValidationError):
            validator.validate(data)
