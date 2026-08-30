import pytest
from src.preprocessing.input_normalizer import InputNormalizer


@pytest.fixture
def normalizer():
    return InputNormalizer()


class TestInputNormalizer:

    # === BASIC NORMALIZATION (5 tests) ===

    def test_normalize_strips_leading_trailing_whitespace(self, normalizer):
        """Input with extra whitespace is trimmed."""
        result = normalizer.normalize("  scan 10.0.0.1  ")
        assert result == "scan 10.0.0.1"

    def test_normalize_collapses_multiple_spaces(self, normalizer):
        """Multiple consecutive spaces collapsed to one."""
        result = normalizer.normalize("scan    the    target")
        assert result == "scan the target"

    def test_normalize_nfkc_nonbreaking_space(self, normalizer):
        """Non-breaking space (\u00a0) is normalized to regular space."""
        result = normalizer.normalize("scan\u00a0target")
        assert "\u00a0" not in result

    def test_normalize_returns_string(self, normalizer):
        """Output is always a string type."""
        result = normalizer.normalize("scan 192.168.1.1")
        assert isinstance(result, str)

    def test_normalize_preserves_valid_ip_addresses(self, normalizer):
        """Valid IP addresses are preserved in output."""
        result = normalizer.normalize("scan 192.168.1.1")
        assert "192.168.1.1" in result

    # === TERM STANDARDIZATIONS (8 tests) ===

    def test_normalize_syn_scan_standardized(self, normalizer):
        """syn scan -> SYN stealth scan."""
        result = normalizer.normalize("do a syn scan on 10.0.0.1")
        assert "SYN stealth scan" in result

    def test_normalize_ping_sweep_standardized(self, normalizer):
        """ping sweep -> ICMP discovery scan."""
        result = normalizer.normalize("run a ping sweep on 192.168.0.0/24")
        assert "ICMP discovery scan" in result

    def test_normalize_stealthy_sweep_standardized(self, normalizer):
        """stealthy sweep -> stealth ICMP discovery scan."""
        result = normalizer.normalize("do a stealthy sweep")
        assert "stealth ICMP discovery scan" in result

    def test_normalize_pwn_to_exploit(self, normalizer):
        """pwn -> exploit."""
        result = normalizer.normalize("pwn the server")
        assert "exploit" in result

    def test_normalize_box_to_host(self, normalizer):
        """box -> host."""
        result = normalizer.normalize("pwn the box")
        assert "host" in result

    def test_normalize_privesc_standardized(self, normalizer):
        """privesc -> privilege escalation."""
        result = normalizer.normalize("try to privesc on the host")
        assert "privilege escalation" in result

    def test_normalize_recon_standardized(self, normalizer):
        """recon -> reconnaissance."""
        result = normalizer.normalize("do recon on target")
        assert "reconnaissance" in result

    def test_normalize_enum_standardized(self, normalizer):
        """enum -> enumeration."""
        result = normalizer.normalize("run enum on the service")
        assert "enumeration" in result

    # === CONTROL CHARACTER STRIPPING (6 tests) ===

    def test_normalize_strips_null_bytes(self, normalizer):
        """Null bytes (\x00) are removed."""
        result = normalizer.normalize("scan\x00target")
        assert "\x00" not in result

    def test_normalize_strips_control_chars(self, normalizer):
        """Control characters (ord < 32, except space/tab/newline) are removed."""
        result = normalizer.normalize("scan\x01\x02\x03target")
        assert "\x01" not in result
        assert "\x02" not in result
        assert "\x03" not in result

    def test_normalize_tab_becomes_space(self, normalizer):
        """Tab characters become regular spaces."""
        result = normalizer.normalize("scan\ttarget")
        assert "\t" not in result
        assert " " in result

    def test_normalize_newline_becomes_space(self, normalizer):
        """Newline characters become regular spaces."""
        result = normalizer.normalize("scan\ntarget")
        assert "\n" not in result

    def test_normalize_gemma_im_start_token_stripped(self, normalizer):
        """Gemma <|think|> token is stripped from output."""
        text = '<|think|>scan 10.0.0.1'
        result = normalizer.normalize(text)
        assert '<|think|>' not in result
        assert 'scan 10.0.0.1' in result

    def test_normalize_gemma_think_token_stripped(self, normalizer):
        """Gemma <think>...</think> block is stripped."""
        text = '<think>thinking</think>\nscan 10.0.0.1'
        result = normalizer.normalize(text)
        assert '<think>' not in result
        assert '</think>' not in result

    # === UNICODE (4 tests) ===

    def test_normalize_unicode_nfkc_applied(self, normalizer):
        """Unicode NFKC normalization is applied."""
        # \u00a0 is non-breaking space, NFKC converts to regular space
        result = normalizer.normalize("scan\u00a0target")
        assert "\u00a0" not in result

    def test_normalize_unicode_ligature_decomposed(self, normalizer):
        """Unicode ligatures are decomposed by NFKC."""
        # \ufb01 is fi ligature
        result = normalizer.normalize("scan\ufb01le target")
        assert "\ufb01" not in result
        assert "file" in result or "fi" in result

    def test_normalize_arabic_numerals_normalized(self, normalizer):
        """Mixed unicode input with standard numerals is handled."""
        result = normalizer.normalize("scan 10.0.0.1 port 80")
        assert "10.0.0.1" in result

    def test_normalize_mixed_unicode_and_ascii(self, normalizer):
        """Mixed unicode and ASCII input is processed correctly."""
        result = normalizer.normalize("scan\u00e9target\u00a0now")
        assert isinstance(result, str)
        assert len(result) > 0

    # === ERROR HANDLING (3 tests) ===

    def test_normalize_empty_string_raises_value_error(self, normalizer):
        """Empty string raises ValueError."""
        with pytest.raises(ValueError):
            normalizer.normalize("")

    def test_normalize_whitespace_only_raises_value_error(self, normalizer):
        """Whitespace-only string raises ValueError."""
        with pytest.raises(ValueError):
            normalizer.normalize("   ")

    def test_normalize_none_raises_value_error(self, normalizer):
        """None input raises ValueError or TypeError."""
        with pytest.raises((ValueError, TypeError)):
            normalizer.normalize(None)

    # === EDGE CASES (5 tests) ===

    def test_normalize_single_word_input(self, normalizer):
        """Single word input passes through."""
        result = normalizer.normalize("scan")
        assert result == "scan"

    def test_normalize_already_normalized_input_unchanged_structure(self, normalizer):
        """Already clean input structure is preserved."""
        result = normalizer.normalize("scan 192.168.1.1 port 80")
        assert "192.168.1.1" in result
        assert "80" in result

    def test_normalize_long_input_handled(self, normalizer):
        """Long input strings are processed without error."""
        long_input = "scan " + "10.0.0.1 " * 50 + "for open ports"
        result = normalizer.normalize(long_input)
        assert isinstance(result, str)

    def test_normalize_case_insensitive_term_matching(self, normalizer):
        """Term matching is case insensitive."""
        result = normalizer.normalize("do a SYN SCAN on target")
        assert "SYN stealth scan" in result

    def test_normalize_multiple_terms_in_single_input(self, normalizer):
        """Multiple slang terms in one input are all standardized."""
        result = normalizer.normalize("pwn the box and do recon")
        assert "exploit" in result
        assert "host" in result
        assert "reconnaissance" in result