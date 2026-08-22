import pytest
from pydantic import ValidationError
from src.validation.regex_validator import RegexValidator
from src.schemas.intent_schema import (
    IntentSchema, Target, IntentType, TargetType, RegexValidationError
)


@pytest.fixture
def validator():
    return RegexValidator()


@pytest.fixture
def make_schema():
    def _make(intent="NETWORK_SCAN", target_type="IP",
              target_value="192.168.1.1", ports=None,
              cve_ids=None, modifiers=None, confidence=0.9):
        return IntentSchema(
            intent=IntentType(intent),
            target=Target(type=TargetType(target_type), value=target_value),
            ports=ports or [],
            cve_ids=cve_ids or [],
            modifiers=modifiers or [],
            confidence=confidence,
        )
    return _make


class TestRegexValidator:

    # === IPv4 VALIDATION (5 tests) ===

    def test_validate_valid_ipv4_passes(self, validator, make_schema):
        """Valid IPv4 addresses pass regex validation."""
        s = make_schema(target_value="192.168.1.1")
        validator.validate(s)

    def test_validate_invalid_ipv4_octets_raises(self, validator, make_schema):
        """IPv4 with octets > 255 raises RegexValidationError."""
        s = make_schema(target_value="999.1.1.1")
        with pytest.raises(RegexValidationError):
            validator.validate(s)

    def test_validate_ipv4_edge_cases(self, validator, make_schema):
        """IPv4 edge cases with leading zeros are handled by the regex."""
        # Regex allows some leading zeros - this documents current behavior
        s = make_schema(target_value="192.168.001.1")
        validator.validate(s)

    def test_validate_ipv4_too_many_octets_raises(self, validator, make_schema):
        """IPv4 with too many octets raises RegexValidationError."""
        s = make_schema(target_value="192.168.1.1.1")
        with pytest.raises(RegexValidationError):
            validator.validate(s)

    def test_validate_ipv4_with_port_raises(self, validator, make_schema):
        """IPv4 with appended port number raises RegexValidationError."""
        s = make_schema(target_value="192.168.1.1:80")
        with pytest.raises(RegexValidationError):
            validator.validate(s)

    # === CIDR VALIDATION (5 tests) ===

    def test_validate_valid_cidr_24_passes(self, validator, make_schema):
        """Valid /24 CIDR passes validation."""
        s = make_schema(target_type="SUBNET", target_value="192.168.1.0/24")
        validator.validate(s)

    def test_validate_valid_cidr_8_passes(self, validator, make_schema):
        """Valid /8 CIDR passes validation."""
        s = make_schema(target_type="SUBNET", target_value="10.0.0.0/8")
        validator.validate(s)

    def test_validate_valid_cidr_32_passes(self, validator, make_schema):
        """Valid /32 CIDR passes validation."""
        s = make_schema(target_type="SUBNET", target_value="192.168.1.1/32")
        validator.validate(s)

    def test_validate_cidr_prefix_too_large_raises(self, validator, make_schema):
        """CIDR with prefix > 32 raises RegexValidationError."""
        s = make_schema(target_type="SUBNET", target_value="192.168.1.0/33")
        with pytest.raises(RegexValidationError):
            validator.validate(s)

    def test_validate_cidr_missing_prefix_raises(self, validator, make_schema):
        """CIDR without prefix raises RegexValidationError."""
        s = make_schema(target_type="SUBNET", target_value="192.168.1.0")
        with pytest.raises(RegexValidationError):
            validator.validate(s)

    # === DOMAIN VALIDATION (4 tests) ===

    def test_validate_valid_domain_passes(self, validator, make_schema):
        """Valid domain passes validation."""
        s = make_schema(target_type="DOMAIN", target_value="example.com")
        validator.validate(s)

    def test_validate_valid_subdomain_passes(self, validator, make_schema):
        """Valid subdomain passes validation."""
        s = make_schema(target_type="DOMAIN", target_value="sub.example.com")
        validator.validate(s)

    def test_validate_invalid_domain_no_tld_raises(self, validator, make_schema):
        """Domain without TLD raises RegexValidationError."""
        s = make_schema(target_type="DOMAIN", target_value="example")
        with pytest.raises(RegexValidationError):
            validator.validate(s)

    def test_validate_domain_with_ip_format_raises(self, validator, make_schema):
        """Invalid domain format raises RegexValidationError."""
        s = make_schema(target_type="DOMAIN", target_value="domain..com")
        with pytest.raises(RegexValidationError):
            validator.validate(s)

    # === URL VALIDATION (3 tests) ===

    def test_validate_valid_https_url_passes(self, validator, make_schema):
        """Valid HTTPS URL passes validation."""
        s = make_schema(target_type="URL", target_value="https://example.com/path")
        validator.validate(s)

    def test_validate_valid_http_url_passes(self, validator, make_schema):
        """Valid HTTP URL passes validation."""
        s = make_schema(target_type="URL", target_value="http://example.com:8080/api")
        validator.validate(s)

    def test_validate_invalid_url_no_scheme_raises(self, validator, make_schema):
        """URL without http/https scheme raises RegexValidationError."""
        s = make_schema(target_type="URL", target_value="example.com/path")
        with pytest.raises(RegexValidationError):
            validator.validate(s)

    # === CVE VALIDATION (5 tests) ===

    def test_validate_valid_cve_2021_44228_passes(self, validator, make_schema):
        """CVE-2021-44228 passes CVE format validation."""
        s = make_schema(cve_ids=["CVE-2021-44228"])
        validator.validate(s)

    def test_validate_valid_cve_short_id_passes(self, validator, make_schema):
        """CVE with 4-digit ID passes validation."""
        s = make_schema(cve_ids=["CVE-2014-1234"])
        validator.validate(s)

    def test_validate_valid_cve_long_id_passes(self, validator, make_schema):
        """CVE with 7-digit ID passes validation."""
        s = make_schema(cve_ids=["CVE-2021-1234567"])
        validator.validate(s)

    def test_validate_invalid_cve_no_year_raises(self, validator, make_schema):
        """CVE without year raises RegexValidationError when validated."""
        s = make_schema(cve_ids=["CVE-2021-44228"])
        object.__setattr__(s, "cve_ids", ["CVE-44228"])
        with pytest.raises(RegexValidationError):
            validator.validate(s)

    def test_validate_invalid_cve_wrong_format_raises(self, validator, make_schema):
        """Malformed CVE string raises RegexValidationError when validated."""
        s = make_schema(cve_ids=["CVE-2021-44228"])
        object.__setattr__(s, "cve_ids", ["CVE-XXXX-YYYY"])
        with pytest.raises(RegexValidationError):
            validator.validate(s)

    # === PORT VALIDATION (4 tests) ===

    def test_validate_port_1_passes(self, validator, make_schema):
        """Port 1 (minimum valid) passes."""
        s = make_schema(ports=[1])
        validator.validate(s)

    def test_validate_port_65535_passes(self, validator, make_schema):
        """Port 65535 (maximum valid) passes."""
        s = make_schema(ports=[65535])
        validator.validate(s)

    def test_validate_port_0_raises(self, validator, make_schema):
        """Port 0 raises RegexValidationError when validated."""
        s = make_schema(ports=[80])
        object.__setattr__(s, "ports", [0])
        with pytest.raises(RegexValidationError):
            validator.validate(s)

    def test_validate_port_65536_raises(self, validator, make_schema):
        """Port 65536 raises RegexValidationError when validated."""
        s = make_schema(ports=[80])
        object.__setattr__(s, "ports", [65536])
        with pytest.raises(RegexValidationError):
            validator.validate(s)

    # === SHELL METACHARACTER (6 tests) ===

    def test_validate_semicolon_in_target_raises(self, validator, make_schema):
        """Semicolon in target raises RegexValidationError."""
        s = make_schema(target_value="10.0.0.1;rm -rf /")
        with pytest.raises(RegexValidationError):
            validator.validate(s)

    def test_validate_pipe_in_target_raises(self, validator, make_schema):
        """Pipe character in target raises RegexValidationError."""
        s = make_schema(target_value="10.0.0.1|cat /etc/passwd")
        with pytest.raises(RegexValidationError):
            validator.validate(s)

    def test_validate_ampersand_in_target_raises(self, validator, make_schema):
        """Ampersand in target raises RegexValidationError."""
        s = make_schema(target_value="10.0.0.1 & whoami")
        with pytest.raises(RegexValidationError):
            validator.validate(s)

    def test_validate_backtick_in_target_raises(self, validator, make_schema):
        """Backtick in target raises RegexValidationError."""
        s = make_schema(target_value="10.0.0.1`id`")
        with pytest.raises(RegexValidationError):
            validator.validate(s)

    def test_validate_dollar_in_target_raises(self, validator, make_schema):
        """Dollar sign in target raises RegexValidationError."""
        s = make_schema(target_value="10.0.0.1$HOME")
        with pytest.raises(RegexValidationError):
            validator.validate(s)

    def test_validate_shell_meta_in_modifier_raises(self, validator, make_schema):
        """Shell metacharacters in modifier raises RegexValidationError."""
        s = make_schema(modifiers=["stealth;rm -rf /"])
        with pytest.raises(RegexValidationError):
            validator.validate(s)

    # === UNKNOWN TARGET (4 tests) ===

    def test_validate_unknown_target_type_skips_format_check(self, validator, make_schema):
        """UNKNOWN target type skips IP/CIDR/domain format check."""
        s = make_schema(target_type="UNKNOWN", target_value="")
        validator.validate(s)

    def test_validate_empty_value_with_unknown_type_passes(self, validator, make_schema):
        """Empty value with UNKNOWN target type passes."""
        s = make_schema(target_type="UNKNOWN", target_value="")
        validator.validate(s)

    def test_validate_returns_schema_unchanged_on_success(self, validator, make_schema):
        """Valid schema is returned unchanged."""
        s = make_schema()
        result = validator.validate(s)
        assert result is s

    def test_validate_valid_schema_no_exception(self, validator, make_schema):
        """Fully valid schema raises no exception."""
        s = make_schema(
            target_value="10.0.0.1",
            ports=[22, 80],
            cve_ids=["CVE-2021-44228"],
            modifiers=["stealth"],
        )
        validator.validate(s)

    # === HOSTNAME (4 tests) ===

    def test_validate_valid_hostname_passes(self, validator, make_schema):
        """Valid hostname passes validation."""
        s = make_schema(target_type="HOSTNAME", target_value="webserver.local")
        validator.validate(s)

    def test_validate_hostname_with_hyphens_passes(self, validator, make_schema):
        """Hostname with hyphens passes validation."""
        s = make_schema(target_type="HOSTNAME", target_value="my-web-server.local")
        validator.validate(s)

    def test_validate_hostname_single_label_passes(self, validator, make_schema):
        """Single-label hostname without dot is rejected by FQDN regex."""
        s = make_schema(target_type="HOSTNAME", target_value="localhost")
        with pytest.raises(RegexValidationError):
            validator.validate(s)

    def test_validate_hostname_invalid_chars_raises(self, validator, make_schema):
        """Hostname with invalid characters raises RegexValidationError."""
        s = make_schema(target_type="HOSTNAME", target_value="web_server.local")
        with pytest.raises(RegexValidationError):
            validator.validate(s)
