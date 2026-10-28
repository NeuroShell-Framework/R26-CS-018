import json
import pytest
from pydantic import ValidationError
from src.schemas.planner_contract import PlannerContract, PlannerTarget
from src.schemas.intent_schema import IntentType, SubIntentType


@pytest.fixture
def network_scan_contract():
    return PlannerContract(
        intent=IntentType.NETWORK_SCAN,
        sub_intent=SubIntentType.NETWORK_SCAN_SYN_STEALTH,
        target=PlannerTarget(type="SUBNET", value="192.168.1.0/24"),
        ports=[22, 80, 443],
        modifiers=["stealth"],
        cve_ids=[],
        tool_hint="nmap",
        confidence=0.97,
        schedule=None,
        rejection_reason=None,
        scope_warnings=[],
        session_id="test-001",
    )


@pytest.fixture
def vuln_audit_contract():
    return PlannerContract(
        intent=IntentType.VULNERABILITY_AUDIT,
        sub_intent=SubIntentType.VULN_AUDIT_CVE_SPECIFIC,
        target=PlannerTarget(type="IP", value="192.168.1.5"),
        ports=[445],
        modifiers=[],
        cve_ids=["CVE-2017-0144"],
        tool_hint="metasploit",
        confidence=0.98,
        schedule=None,
        rejection_reason=None,
        scope_warnings=[],
        session_id="test-002",
    )


@pytest.fixture
def rejected_contract():
    return PlannerContract(
        intent=IntentType.REJECTED,
        sub_intent=None,
        target=PlannerTarget(type="UNKNOWN", value=""),
        ports=[],
        modifiers=[],
        cve_ids=[],
        tool_hint=None,
        confidence=0.0,
        schedule=None,
        rejection_reason="Prompt injection attempt detected",
        scope_warnings=[],
        session_id="test-003",
    )


class TestSchemaStructure:

    def test_contract_has_no_extra_fields(self):
        with pytest.raises(ValidationError):
            PlannerContract(
                intent=IntentType.NETWORK_SCAN,
                target=PlannerTarget(type="IP", value="10.0.0.1"),
                ports=[],
                modifiers=[],
                cve_ids=[],
                confidence=0.9,
                extra_field="bad",
            )

    def test_contract_serialises_to_12_fields(self, network_scan_contract):
        data = network_scan_contract.model_dump()
        assert len(data) == 12

    def test_target_has_exactly_two_fields(self):
        target = PlannerTarget(type="IP", value="10.0.0.1")
        assert set(target.model_dump().keys()) == {"type", "value"}

    def test_target_type_validation(self):
        with pytest.raises(ValidationError):
            PlannerTarget(type="INVALID", value="x")

    def test_contract_json_matches_expected_structure(self, network_scan_contract):
        data = json.loads(network_scan_contract.model_dump_json())
        assert set(data.keys()) == {
            "intent", "sub_intent", "target", "ports", "modifiers",
            "cve_ids", "tool_hint", "confidence", "schedule",
            "rejection_reason", "scope_warnings", "session_id",
        }


class TestPortValidation:

    def test_valid_ports_accepted(self):
        contract = PlannerContract(
            intent=IntentType.NETWORK_SCAN,
            target=PlannerTarget(type="IP", value="10.0.0.1"),
            ports=[22, 80, 443, 8080],
            modifiers=[],
            cve_ids=[],
            confidence=0.9,
        )
        assert contract.ports == [22, 80, 443, 8080]

    def test_port_zero_raises(self):
        with pytest.raises(ValidationError):
            PlannerContract(
                intent=IntentType.NETWORK_SCAN,
                target=PlannerTarget(type="IP", value="10.0.0.1"),
                ports=[0],
                modifiers=[],
                cve_ids=[],
                confidence=0.9,
            )

    def test_port_65536_raises(self):
        with pytest.raises(ValidationError):
            PlannerContract(
                intent=IntentType.NETWORK_SCAN,
                target=PlannerTarget(type="IP", value="10.0.0.1"),
                ports=[65536],
                modifiers=[],
                cve_ids=[],
                confidence=0.9,
            )

    def test_empty_ports_accepted(self):
        contract = PlannerContract(
            intent=IntentType.NETWORK_SCAN,
            target=PlannerTarget(type="IP", value="10.0.0.1"),
            ports=[],
            modifiers=[],
            cve_ids=[],
            confidence=0.9,
        )
        assert contract.ports == []
        assert contract.is_executable is True


class TestCveValidation:

    def test_valid_cve_format_accepted(self):
        contract = PlannerContract(
            intent=IntentType.VULNERABILITY_AUDIT,
            target=PlannerTarget(type="IP", value="10.0.0.1"),
            ports=[],
            modifiers=[],
            cve_ids=["CVE-2021-44228"],
            confidence=0.9,
        )
        assert "CVE-2021-44228" in contract.cve_ids

    def test_invalid_cve_no_year_raises(self):
        with pytest.raises(ValidationError):
            PlannerContract(
                intent=IntentType.VULNERABILITY_AUDIT,
                target=PlannerTarget(type="IP", value="10.0.0.1"),
                ports=[],
                modifiers=[],
                cve_ids=["CVE-BAD"],
                confidence=0.9,
            )

    def test_multiple_cve_ids_accepted(self):
        contract = PlannerContract(
            intent=IntentType.VULNERABILITY_AUDIT,
            target=PlannerTarget(type="IP", value="10.0.0.1"),
            ports=[],
            modifiers=[],
            cve_ids=["CVE-2017-0144", "CVE-2021-44228"],
            confidence=0.9,
        )
        assert len(contract.cve_ids) == 2


class TestIntentAndSubIntent:

    def test_all_intent_types_accepted(self):
        for intent in IntentType:
            contract = PlannerContract(
                intent=intent,
                target=PlannerTarget(type="IP", value="10.0.0.1"),
                ports=[],
                modifiers=[],
                cve_ids=[],
                confidence=0.5,
            )
            assert contract.intent == intent

    def test_sub_intent_none_accepted(self):
        contract = PlannerContract(
            intent=IntentType.NETWORK_SCAN,
            target=PlannerTarget(type="IP", value="10.0.0.1"),
            ports=[],
            modifiers=[],
            cve_ids=[],
            confidence=0.9,
            sub_intent=None,
        )
        assert contract.sub_intent is None

    def test_sub_intent_populated(self):
        contract = PlannerContract(
            intent=IntentType.NETWORK_SCAN,
            sub_intent=SubIntentType.NETWORK_SCAN_SYN_STEALTH,
            target=PlannerTarget(type="IP", value="10.0.0.1"),
            ports=[],
            modifiers=[],
            cve_ids=[],
            confidence=0.9,
        )
        assert contract.sub_intent.value == "NETWORK_SCAN.SYN_STEALTH"

    def test_rejected_intent_has_rejection_reason(self, rejected_contract):
        assert rejected_contract.rejection_reason is not None


class TestProperties:

    def test_is_executable_true_for_clean_scan(self, network_scan_contract):
        assert network_scan_contract.is_executable is True

    def test_is_executable_false_for_rejected(self, rejected_contract):
        assert rejected_contract.is_executable is False

    def test_is_immediate_true_when_no_schedule(self, network_scan_contract):
        assert network_scan_contract.is_immediate is True

    def test_has_scope_issues_true_when_warnings(self):
        contract = PlannerContract(
            intent=IntentType.NETWORK_SCAN,
            target=PlannerTarget(type="IP", value="10.0.0.1"),
            ports=[],
            modifiers=[],
            cve_ids=[],
            confidence=0.9,
            scope_warnings=["ARCH_WARNING: /16 wider than /30"],
        )
        assert contract.has_scope_issues is True


class TestScopeWarnings:

    def test_scope_warnings_empty_list_default(self):
        contract = PlannerContract(
            intent=IntentType.NETWORK_SCAN,
            target=PlannerTarget(type="IP", value="10.0.0.1"),
            ports=[],
            modifiers=[],
            cve_ids=[],
            confidence=0.9,
            scope_warnings=[],
        )
        assert contract.scope_warnings == []

    def test_arch_warning_in_scope_warnings(self):
        contract = PlannerContract(
            intent=IntentType.NETWORK_SCAN,
            target=PlannerTarget(type="IP", value="10.0.0.1"),
            ports=[],
            modifiers=[],
            cve_ids=[],
            confidence=0.9,
            scope_warnings=["ARCH_WARNING: /16 wider than /30"],
        )
        assert contract.has_scope_issues is True
        assert contract.is_executable is False

    def test_scope_warning_public_ip(self):
        contract = PlannerContract(
            intent=IntentType.NETWORK_SCAN,
            target=PlannerTarget(type="IP", value="8.8.8.8"),
            ports=[],
            modifiers=[],
            cve_ids=[],
            confidence=0.9,
            scope_warnings=["SCOPE_WARNING: 8.8.8.8 is public"],
        )
        assert contract.has_scope_issues is True


class TestConfidence:

    def test_confidence_rounded_to_4_decimal_places(self):
        contract = PlannerContract(
            intent=IntentType.NETWORK_SCAN,
            target=PlannerTarget(type="IP", value="10.0.0.1"),
            ports=[],
            modifiers=[],
            cve_ids=[],
            confidence=0.97123456,
        )
        assert contract.confidence == 0.9712

    def test_confidence_out_of_range_raises(self):
        with pytest.raises(ValidationError):
            PlannerContract(
                intent=IntentType.NETWORK_SCAN,
                target=PlannerTarget(type="IP", value="10.0.0.1"),
                ports=[],
                modifiers=[],
                cve_ids=[],
                confidence=1.1,
            )
