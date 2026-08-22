import pytest
from unittest.mock import patch
from src.middleware.sub_intent_classifier import SubIntentClassifier
from src.schemas.intent_schema import (
    IntentSchema, IntentType, SubIntentType,
    Target, TargetType, IREResponseV2
)


@pytest.fixture
def classifier():
    return SubIntentClassifier()


@pytest.fixture
def classifier_disabled():
    with patch("src.middleware.sub_intent_classifier.get_feature_flags") as mock:
        mock.return_value.sub_intent = False
        mock.return_value.get_tuning = lambda k, d: d
        return SubIntentClassifier()


@pytest.fixture
def make_schema():
    def _make(intent=IntentType.NETWORK_SCAN, ports=None, modifiers=None, cve_ids=None, confidence=0.9, rejection_reason=None):
        return IntentSchema(
            intent=intent,
            target=Target(type=TargetType.IP, value="10.0.0.1"),
            ports=ports or [],
            modifiers=modifiers or [],
            cve_ids=cve_ids or [],
            confidence=confidence,
            rejection_reason=rejection_reason,
        )
    return _make


@pytest.fixture
def make_v2_response():
    def _make(status="success", intent=IntentType.NETWORK_SCAN,
              ports=None, modifiers=None, cve_ids=None, confidence=0.9):
        return IREResponseV2(
            status=status,
            intent=intent,
            target=Target(type=TargetType.IP, value="10.0.0.1"),
            ports=ports or [],
            modifiers=modifiers or [],
            cve_ids=cve_ids or [],
            confidence=confidence,
        )
    return _make


class TestNetworkScanSubIntents:

    def test_syn_stealth_via_modifier(self, classifier, make_schema):
        """'stealth' modifier maps to SYN_STEALTH sub-intent."""
        s = make_schema(modifiers=["stealth"])
        result = classifier.classify(s)
        assert result == SubIntentType.NETWORK_SCAN_SYN_STEALTH

    def test_syn_stealth_via_port_445(self, classifier, make_schema):
        """Port 445 maps to SYN_STEALTH sub-intent."""
        s = make_schema(ports=[445])
        result = classifier.classify(s)
        assert result == SubIntentType.NETWORK_SCAN_SYN_STEALTH

    def test_icmp_discovery_via_ping_modifier(self, classifier, make_schema):
        """'ping' modifier maps to ICMP_DISCOVERY sub-intent."""
        s = make_schema(modifiers=["ping"])
        result = classifier.classify(s)
        assert result == SubIntentType.NETWORK_SCAN_ICMP_DISCOVERY

    def test_icmp_discovery_no_ports_no_modifiers(self, classifier, make_schema):
        """No ports and no modifiers maps to ICMP_DISCOVERY (default scan)."""
        s = make_schema(ports=[], modifiers=[])
        result = classifier.classify(s)
        assert result == SubIntentType.NETWORK_SCAN_ICMP_DISCOVERY

    def test_udp_sweep_via_modifier(self, classifier, make_schema):
        """'udp' modifier maps to UDP_SWEEP sub-intent."""
        s = make_schema(modifiers=["udp"])
        result = classifier.classify(s)
        assert result == SubIntentType.NETWORK_SCAN_UDP_SWEEP

    def test_version_detect_via_modifier(self, classifier, make_schema):
        """'version' modifier maps to VERSION_DETECT sub-intent."""
        s = make_schema(modifiers=["version"])
        result = classifier.classify(s)
        assert result == SubIntentType.NETWORK_SCAN_VERSION_DETECT

    def test_version_detect_via_common_ports(self, classifier, make_schema):
        """Common service ports (e.g., 80) map to VERSION_DETECT."""
        s = make_schema(ports=[80])
        result = classifier.classify(s)
        assert result == SubIntentType.NETWORK_SCAN_VERSION_DETECT

    def test_os_detect_via_modifier(self, classifier, make_schema):
        """'os' modifier maps to OS_DETECT sub-intent."""
        s = make_schema(modifiers=["os"])
        result = classifier.classify(s)
        assert result == SubIntentType.NETWORK_SCAN_OS_DETECT

    def test_full_port_via_many_ports(self, classifier, make_schema):
        """More than 10 ports maps to FULL_PORT sub-intent."""
        s = make_schema(ports=list(range(1, 15)))
        result = classifier.classify(s)
        assert result == SubIntentType.NETWORK_SCAN_FULL_PORT

    def test_full_port_via_modifier(self, classifier, make_schema):
        """'full' modifier maps to FULL_PORT sub-intent."""
        s = make_schema(modifiers=["full"])
        result = classifier.classify(s)
        assert result == SubIntentType.NETWORK_SCAN_FULL_PORT


class TestExploitationSubIntents:

    def test_rce_via_cve(self, classifier, make_schema):
        """CVE-2021-44228 maps to RCE sub-intent."""
        s = make_schema(intent=IntentType.EXPLOITATION, cve_ids=["CVE-2021-44228"])
        result = classifier.classify(s)
        assert result == SubIntentType.EXPLOITATION_RCE

    def test_rce_via_modifier(self, classifier, make_schema):
        """'remote code' modifier maps to RCE sub-intent."""
        s = make_schema(intent=IntentType.EXPLOITATION, modifiers=["remote code"])
        result = classifier.classify(s)
        assert result == SubIntentType.EXPLOITATION_RCE

    def test_priv_esc_via_modifier(self, classifier, make_schema):
        """'privesc' modifier maps to PRIV_ESC sub-intent."""
        s = make_schema(intent=IntentType.EXPLOITATION, modifiers=["privesc"])
        result = classifier.classify(s)
        assert result == SubIntentType.EXPLOITATION_PRIV_ESC

    def test_priv_esc_via_cve(self, classifier, make_schema):
        """CVE-2021-4034 maps to PRIV_ESC sub-intent."""
        s = make_schema(intent=IntentType.EXPLOITATION, cve_ids=["CVE-2021-4034"])
        result = classifier.classify(s)
        assert result == SubIntentType.EXPLOITATION_PRIV_ESC

    def test_lateral_via_modifier(self, classifier, make_schema):
        """'lateral movement' modifier maps to LATERAL sub-intent."""
        s = make_schema(intent=IntentType.EXPLOITATION, modifiers=["lateral movement"])
        result = classifier.classify(s)
        assert result == SubIntentType.EXPLOITATION_LATERAL

    def test_persistence_via_modifier(self, classifier, make_schema):
        """'backdoor' modifier maps to PERSISTENCE sub-intent."""
        s = make_schema(intent=IntentType.EXPLOITATION, modifiers=["backdoor"])
        result = classifier.classify(s)
        assert result == SubIntentType.EXPLOITATION_PERSISTENCE


class TestVulnerabilityAuditSubIntents:

    def test_cve_specific_with_cves(self, classifier, make_schema):
        """Having CVE IDs maps to CVE_SPECIFIC sub-intent."""
        s = make_schema(intent=IntentType.VULNERABILITY_AUDIT, cve_ids=["CVE-2017-0144"])
        result = classifier.classify(s)
        assert result == SubIntentType.VULN_AUDIT_CVE_SPECIFIC

    def test_service_specific_with_ports_no_cves(self, classifier, make_schema):
        """Having ports but no CVEs maps to SERVICE_SPECIFIC sub-intent."""
        s = make_schema(intent=IntentType.VULNERABILITY_AUDIT, ports=[22], cve_ids=[])
        result = classifier.classify(s)
        assert result == SubIntentType.VULN_AUDIT_SERVICE_SPECIFIC

    def test_full_scan_no_ports_no_cves(self, classifier, make_schema):
        """No ports and no CVEs maps to FULL_SCAN sub-intent."""
        s = make_schema(intent=IntentType.VULNERABILITY_AUDIT, ports=[], cve_ids=[])
        result = classifier.classify(s)
        assert result == SubIntentType.VULN_AUDIT_FULL_SCAN


class TestServiceEnumerationSubIntents:

    def test_smb_via_ports(self, classifier, make_schema):
        """Port 445 maps to SMB sub-intent."""
        s = make_schema(intent=IntentType.SERVICE_ENUMERATION, ports=[445])
        result = classifier.classify(s)
        assert result == SubIntentType.SERVICE_ENUM_SMB

    def test_smb_via_modifier(self, classifier, make_schema):
        """'smb' modifier maps to SMB sub-intent."""
        s = make_schema(intent=IntentType.SERVICE_ENUMERATION, modifiers=["smb"])
        result = classifier.classify(s)
        assert result == SubIntentType.SERVICE_ENUM_SMB

    def test_snmp_via_ports(self, classifier, make_schema):
        """Port 161 maps to SNMP sub-intent."""
        s = make_schema(intent=IntentType.SERVICE_ENUMERATION, ports=[161])
        result = classifier.classify(s)
        assert result == SubIntentType.SERVICE_ENUM_SNMP

    def test_version_detect_via_banner(self, classifier, make_schema):
        """'banner grabbing' modifier maps to VERSION_DETECT sub-intent."""
        s = make_schema(intent=IntentType.SERVICE_ENUMERATION, modifiers=["banner grabbing"])
        result = classifier.classify(s)
        assert result == SubIntentType.SERVICE_ENUM_VERSION_DETECT

    def test_banner_grab_fallback(self, classifier, make_schema):
        """BANNER_GRAB is the fallback (always matches last)."""
        s = make_schema(intent=IntentType.SERVICE_ENUMERATION, ports=[], modifiers=[])
        result = classifier.classify(s)
        assert result == SubIntentType.SERVICE_ENUM_BANNER_GRAB


class TestPasswordAttackSubIntents:

    def test_password_spray_via_modifier(self, classifier, make_schema):
        """'spray' modifier maps to PASSWORD_SPRAY sub-intent."""
        s = make_schema(intent=IntentType.PASSWORD_ATTACK, modifiers=["spray"])
        result = classifier.classify(s)
        assert result == SubIntentType.PASSWORD_SPRAY

    def test_credential_stuffing_via_modifier(self, classifier, make_schema):
        """'credential stuffing' modifier maps to CREDENTIAL_STUFFING."""
        s = make_schema(intent=IntentType.PASSWORD_ATTACK, modifiers=["credential stuffing"])
        result = classifier.classify(s)
        assert result == SubIntentType.PASSWORD_CREDENTIAL_STUFFING

    def test_brute_force_fallback(self, classifier, make_schema):
        """BRUTE_FORCE is the fallback for PASSWORD_ATTACK."""
        s = make_schema(intent=IntentType.PASSWORD_ATTACK, modifiers=[])
        result = classifier.classify(s)
        assert result == SubIntentType.PASSWORD_BRUTE_FORCE


class TestPassiveReconSubIntents:

    def test_dns_via_port(self, classifier, make_schema):
        """Port 53 maps to DNS sub-intent."""
        s = make_schema(intent=IntentType.PASSIVE_RECON, ports=[53])
        result = classifier.classify(s)
        assert result == SubIntentType.PASSIVE_RECON_DNS

    def test_dns_via_dig_modifier(self, classifier, make_schema):
        """'dig' modifier maps to DNS sub-intent."""
        s = make_schema(intent=IntentType.PASSIVE_RECON, modifiers=["dig"])
        result = classifier.classify(s)
        assert result == SubIntentType.PASSIVE_RECON_DNS

    def test_whois_via_modifier(self, classifier, make_schema):
        """'whois' modifier maps to WHOIS sub-intent."""
        s = make_schema(intent=IntentType.PASSIVE_RECON, modifiers=["whois"])
        result = classifier.classify(s)
        assert result == SubIntentType.PASSIVE_RECON_WHOIS

    def test_osint_fallback(self, classifier, make_schema):
        """OSINT is the fallback for PASSIVE_RECON."""
        s = make_schema(intent=IntentType.PASSIVE_RECON, ports=[], modifiers=[])
        result = classifier.classify(s)
        assert result == SubIntentType.PASSIVE_RECON_OSINT


class TestDirectoryBruteForceSubIntents:

    def test_api_brute_via_port(self, classifier, make_schema):
        """Port 8080 maps to API brute-force sub-intent."""
        s = make_schema(intent=IntentType.DIRECTORY_BRUTEFORCE, ports=[8080])
        result = classifier.classify(s)
        assert result == SubIntentType.DIR_BRUTE_API

    def test_api_brute_via_modifier(self, classifier, make_schema):
        """'api' modifier maps to API brute-force sub-intent."""
        s = make_schema(intent=IntentType.DIRECTORY_BRUTEFORCE, modifiers=["api"])
        result = classifier.classify(s)
        assert result == SubIntentType.DIR_BRUTE_API

    def test_files_brute_via_modifier(self, classifier, make_schema):
        """'backup' modifier maps to FILES brute-force sub-intent."""
        s = make_schema(intent=IntentType.DIRECTORY_BRUTEFORCE, modifiers=["backup"])
        result = classifier.classify(s)
        assert result == SubIntentType.DIR_BRUTE_FILES

    def test_web_brute_fallback(self, classifier, make_schema):
        """WEB is the fallback for DIRECTORY_BRUTEFORCE."""
        s = make_schema(intent=IntentType.DIRECTORY_BRUTEFORCE, ports=[], modifiers=[])
        result = classifier.classify(s)
        assert result == SubIntentType.DIR_BRUTE_WEB


class TestEdgeCases:

    def test_ambiguous_intent_returns_none(self, classifier, make_schema):
        """AMBIGUOUS intent always returns None (no sub-intent)."""
        s = make_schema(intent=IntentType.AMBIGUOUS, confidence=0.4, modifiers=["ping"])
        result = classifier.classify(s)
        assert result is None

    def test_rejected_intent_returns_none(self, classifier, make_schema):
        """REJECTED intent always returns None (no sub-intent)."""
        s = make_schema(intent=IntentType.REJECTED, rejection_reason="blocked")
        result = classifier.classify(s)
        assert result is None

    def test_below_confidence_threshold_returns_none(self, classifier, make_schema):
        """Confidence below threshold returns None."""
        s = make_schema(confidence=0.3, modifiers=["stealth"])
        result = classifier.classify(s)
        assert result is None

    def test_unknown_intent_returns_none(self, classifier, make_schema, monkeypatch):
        """Intent not present in _rules dict returns None."""
        monkeypatch.setattr(classifier, "_rules", {})
        s = make_schema(intent=IntentType.NETWORK_SCAN, confidence=0.9, modifiers=["stealth"])
        result = classifier.classify(s)
        assert result is None

    def test_classifier_disabled_returns_none(self, classifier_disabled, make_schema):
        """classify returns None when sub_intent feature flag is disabled."""
        s = make_schema(modifiers=["stealth"])
        result = classifier_disabled.classify(s)
        assert result is None


class TestEnrichMethod:

    def test_enrich_sets_sub_intent_on_v2_response(self, classifier, make_v2_response):
        """enrich adds sub_intent to a successful V2 response."""
        resp = make_v2_response(modifiers=["stealth"])
        result = classifier.enrich(resp)
        assert result.sub_intent == SubIntentType.NETWORK_SCAN_SYN_STEALTH

    def test_enrich_returns_unchanged_for_error_response(self, classifier, make_v2_response):
        """enrich returns unchanged response when status is error."""
        resp = make_v2_response(status="error", intent=IntentType.NETWORK_SCAN)
        result = classifier.enrich(resp)
        assert result.sub_intent is None

    def test_enrich_returns_unchanged_when_no_intent(self, classifier, make_v2_response):
        """enrich returns unchanged response when intent is None."""
        resp = make_v2_response(status="success")
        resp.intent = None
        result = classifier.enrich(resp)
        assert result.sub_intent is None

    def test_enrich_disabled_is_noop(self, classifier_disabled, make_v2_response):
        """enrich is a no-op when sub_intent feature flag is disabled."""
        resp = make_v2_response(modifiers=["stealth"])
        result = classifier_disabled.enrich(resp)
        assert result.sub_intent is None

    def test_enrich_with_custom_schema(self, classifier, make_v2_response, make_schema):
        """enrich uses provided schema instead of reconstructing from response."""
        resp = make_v2_response(intent=IntentType.NETWORK_SCAN)
        schema = make_schema(modifiers=["udp"])
        result = classifier.enrich(resp, schema=schema)
        assert result.sub_intent == SubIntentType.NETWORK_SCAN_UDP_SWEEP

    def test_enrich_handles_none_response_fields(self, classifier):
        """enrich handles response with None for ports, modifiers, cve_ids."""
        resp = IREResponseV2(
            status="success",
            intent=IntentType.NETWORK_SCAN,
            target=Target(type=TargetType.IP, value="10.0.0.1"),
            confidence=0.9,
        )
        result = classifier.enrich(resp)
        assert result.sub_intent is not None
