import pytest
from src.validation.network_validator import NetworkArchitectureValidator
from src.schemas.intent_schema import (
    IntentSchema, Target, TargetType, IntentType,
    NetworkValidationError,
)
from config.settings import get_settings


@pytest.fixture(autouse=True)
def _reset_engagement_mode():
    get_settings().engagement_mode = "warn"


@pytest.fixture
def validator():
    return NetworkArchitectureValidator()


@pytest.fixture
def make_schema():
    def _make(
        intent="NETWORK_SCAN", target_type="IP",
        target_value="192.168.1.1",
        ports=None, modifiers=None,
        confidence=0.95,
    ):
        return IntentSchema(
            intent=IntentType(intent),
            target=Target(type=TargetType(target_type), value=target_value),
            ports=ports or [],
            modifiers=modifiers or [],
            cve_ids=[],
            confidence=confidence,
        )
    return _make


class TestInScope:
    def test_ip_within_scope_no_warnings(self, validator, make_schema):
        schema = make_schema(target_value="192.168.1.1")
        _, warnings = validator.validate(schema)
        scope_warns = [w for w in warnings if "SCOPE_VIOLATION" in w]
        assert len(scope_warns) == 0

    def test_subnet_overlapping_scope_no_warnings(self, validator, make_schema):
        schema = make_schema(target_type="SUBNET", target_value="192.168.1.0/24")
        _, warnings = validator.validate(schema)
        scope_warns = [w for w in warnings if "SCOPE_VIOLATION" in w]
        assert len(scope_warns) == 0

    def test_domain_target_skips_scope_check(self, validator, make_schema):
        schema = make_schema(target_type="DOMAIN", target_value="example.com")
        _, warnings = validator.validate(schema)
        scope_warns = [w for w in warnings if "SCOPE_VIOLATION" in w]
        assert len(scope_warns) == 0

    def test_unknown_target_empty_value_passes(self, validator, make_schema):
        schema = make_schema(target_type="UNKNOWN", target_value="")
        _, warnings = validator.validate(schema)
        scope_warns = [w for w in warnings if "SCOPE_VIOLATION" in w]
        assert len(scope_warns) == 0


class TestOutOfScope:
    def test_ip_outside_scope_warn_mode_adds_warning(self, validator, make_schema):
        schema = make_schema(target_value="10.0.0.1")
        _, warnings = validator.validate(schema)
        scope_warns = [w for w in warnings if "SCOPE_VIOLATION" in w]
        assert len(scope_warns) >= 1

    def test_subnet_no_overlap_warn_mode_adds_warning(self, validator, make_schema):
        schema = make_schema(target_type="SUBNET", target_value="172.16.0.0/24")
        _, warnings = validator.validate(schema)
        scope_warns = [w for w in warnings if "SCOPE_VIOLATION" in w]
        assert len(scope_warns) >= 1

    def test_ip_outside_scope_strict_mode_raises(self, make_schema):
        schema = make_schema(target_value="10.0.0.1")
        v = NetworkArchitectureValidator()
        v.settings.engagement_mode = "strict"
        with pytest.raises(NetworkValidationError):
            v.validate(schema)

    def test_subnet_outside_scope_strict_mode_raises(self, make_schema):
        schema = make_schema(target_type="SUBNET", target_value="172.16.0.0/24")
        v = NetworkArchitectureValidator()
        v.settings.engagement_mode = "strict"
        with pytest.raises(NetworkValidationError):
            v.validate(schema)


class TestCidrSanity:
    def test_cidr_32_in_subnet_field_warns(self, validator, make_schema):
        schema = make_schema(target_type="SUBNET", target_value="192.168.1.1/32")
        _, warnings = validator.validate(schema)
        cidr_warns = [w for w in warnings if "ARCH_WARNING" in w]
        assert len(cidr_warns) >= 1

    def test_cidr_too_wide_warns(self, validator, make_schema):
        schema = make_schema(target_type="SUBNET", target_value="192.168.0.0/8")
        _, warnings = validator.validate(schema)
        cidr_warns = [w for w in warnings if "ARCH_WARNING" in w]
        assert len(cidr_warns) >= 1

    def test_valid_cidr_30_passes(self, validator, make_schema):
        schema = make_schema(target_type="SUBNET", target_value="192.168.1.0/30")
        _, warnings = validator.validate(schema)
        cidr_warns = [w for w in warnings if "ARCH_WARNING" in w]
        assert len(cidr_warns) == 0

    def test_non_subnet_type_skips_cidr_check(self, validator, make_schema):
        schema = make_schema(target_value="192.168.1.1")
        _, warnings = validator.validate(schema)
        cidr_warns = [w for w in warnings if "ARCH_WARNING" in w]
        assert len(cidr_warns) == 0


class TestTypeConsistency:
    def test_ip_type_with_cidr_value_warns(self, validator, make_schema):
        schema = make_schema(target_type="IP", target_value="192.168.1.0/24")
        _, warnings = validator.validate(schema)
        arch_warns = [w for w in warnings if "ARCH_WARNING" in w]
        assert len(arch_warns) >= 1

    def test_subnet_type_without_prefix_warns(self, validator, make_schema):
        schema = make_schema(target_type="SUBNET", target_value="192.168.1.0")
        _, warnings = validator.validate(schema)
        arch_warns = [w for w in warnings if "ARCH_WARNING" in w]
        assert len(arch_warns) >= 1

    def test_unknown_type_with_value_warns(self, validator, make_schema):
        schema = make_schema(target_type="UNKNOWN", target_value="192.168.1.1")
        _, warnings = validator.validate(schema)
        arch_warns = [w for w in warnings if "ARCH_WARNING" in w]
        assert len(arch_warns) >= 1

    def test_consistent_types_pass(self, validator, make_schema):
        schema = make_schema(target_type="IP", target_value="192.168.1.1")
        _, warnings = validator.validate(schema)
        arch_warns = [w for w in warnings if "ARCH_WARNING" in w]
        assert len(arch_warns) == 0


class TestModes:
    def test_disabled_mode_skips_all_checks(self, make_schema):
        schema = make_schema(target_value="10.0.0.1")
        v = NetworkArchitectureValidator()
        v.settings.engagement_mode = "disabled"
        schema_out, warnings = v.validate(schema)
        assert len(warnings) == 0
        assert schema_out is schema

    def test_warn_mode_returns_warnings_not_raises(self, validator, make_schema):
        schema = make_schema(target_value="10.0.0.1")
        schema_out, warnings = validator.validate(schema)
        assert isinstance(warnings, list)
        assert len(warnings) >= 1
        assert schema_out is schema

    def test_strict_mode_raises_on_violation(self, make_schema):
        schema = make_schema(target_value="10.0.0.1")
        v = NetworkArchitectureValidator()
        v.settings.engagement_mode = "strict"
        with pytest.raises(NetworkValidationError):
            v.validate(schema)


class TestReturnType:
    def test_validate_returns_tuple_schema_and_list(self, validator, make_schema):
        schema = make_schema()
        result = validator.validate(schema)
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], IntentSchema)
        assert isinstance(result[1], list)
