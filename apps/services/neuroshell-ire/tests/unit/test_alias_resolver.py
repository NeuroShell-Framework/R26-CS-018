import pytest
from src.preprocessing.alias_resolver import AliasResolver


@pytest.fixture
def resolver():
    return AliasResolver()


class TestAliasResolver:

    # === KNOWN ALIASES (8 tests) ===

    def test_enrich_eternalblue_resolved(self, resolver):
        """EternalBlue resolves to CVE-2017-0144."""
        result = resolver.enrich("exploit EternalBlue on target")
        assert "CVE-2017-0144" in result

    def test_enrich_log4shell_resolved(self, resolver):
        """Log4Shell resolves to CVE-2021-44228."""
        result = resolver.enrich("check for Log4Shell vulnerability")
        assert "CVE-2021-44228" in result

    def test_enrich_bluekeep_resolved(self, resolver):
        """BlueKeep resolves to CVE-2019-0708."""
        result = resolver.enrich("test BlueKeep on rdp")
        assert "CVE-2019-0708" in result

    def test_enrich_shellshock_resolved(self, resolver):
        """ShellShock resolves to CVE-2014-6271."""
        result = resolver.enrich("exploit ShellShock bash")
        assert "CVE-2014-6271" in result

    def test_enrich_heartbleed_resolved(self, resolver):
        """Heartbleed resolves to CVE-2014-0160."""
        result = resolver.enrich("check Heartbleed on ssl")
        assert "CVE-2014-0160" in result

    def test_enrich_printnightmare_resolved(self, resolver):
        """PrintNightmare resolves to CVE-2021-34527."""
        result = resolver.enrich("exploit PrintNightmare spooler")
        assert "CVE-2021-34527" in result

    def test_enrich_zerologon_resolved(self, resolver):
        """ZeroLogon resolves to CVE-2020-1472."""
        result = resolver.enrich("test ZeroLogon on dc")
        assert "CVE-2020-1472" in result

    def test_enrich_proxylogon_resolved(self, resolver):
        """ProxyLogon resolves to CVE-2021-26855."""
        result = resolver.enrich("exploit ProxyLogon on exchange")
        assert "CVE-2021-26855" in result

    # === ANNOTATION FORMAT (3 tests) ===

    def test_enrich_annotation_contains_alias_keyword(self, resolver):
        """Enriched output contains the '(alias: ...)' annotation."""
        result = resolver.enrich("check for EternalBlue")
        assert "(alias:" in result

    def test_enrich_annotation_contains_original_matched_text(self, resolver):
        """Annotation preserves the original matched text casing."""
        result = resolver.enrich("exploit EternalBlue")
        assert "EternalBlue" in result

    def test_enrich_annotation_format_correct(self, resolver):
        """Format is '{canonical} (alias: {original})'."""
        result = resolver.enrich("test EternalBlue on target")
        assert "CVE-2017-0144 (alias: EternalBlue)" in result

    # === CASE INSENSITIVITY (3 tests) ===

    def test_enrich_uppercase_alias_resolved(self, resolver):
        """Uppercase alias is resolved."""
        result = resolver.enrich("check ETERNALBLUE on server")
        assert "CVE-2017-0144" in result

    def test_enrich_lowercase_alias_resolved(self, resolver):
        """Lowercase alias is resolved."""
        result = resolver.enrich("check eternalblue on server")
        assert "CVE-2017-0144" in result

    def test_enrich_mixed_case_alias_resolved(self, resolver):
        """Mixed case alias is resolved."""
        result = resolver.enrich("check EtErNaLbLuE on server")
        assert "CVE-2017-0144" in result

    # === NO-MATCH BEHAVIOUR (3 tests) ===

    def test_enrich_unknown_term_unchanged(self, resolver):
        """Unknown terms are left unchanged."""
        result = resolver.enrich("scan the target")
        assert result == "scan the target"

    def test_enrich_plain_ip_unchanged(self, resolver):
        """Plain IP addresses are not modified."""
        result = resolver.enrich("scan 192.168.1.1")
        assert result == "scan 192.168.1.1"

    def test_enrich_empty_string_returns_unchanged(self, resolver):
        """Empty string returns as-is without error."""
        result = resolver.enrich("")
        assert result == ""

    # === EDGE CASES (3 tests) ===

    def test_enrich_multiple_aliases_in_one_input(self, resolver):
        """Multiple aliases in one input are all resolved."""
        result = resolver.enrich("check EternalBlue and Log4Shell")
        assert "CVE-2017-0144" in result
        assert "CVE-2021-44228" in result

    def test_enrich_partial_word_not_matched(self, resolver):
        """Partial word matches are not resolved (word boundary enforced)."""
        result = resolver.enrich("EternalBlueSomething is not a real thing")
        assert "CVE-2017-0144" not in result

    def test_enrich_alias_at_start_of_string(self, resolver):
        """Alias at the start of the string is resolved."""
        result = resolver.enrich("EternalBlue on 10.0.0.1")
        assert "CVE-2017-0144" in result
