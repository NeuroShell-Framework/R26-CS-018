import pytest
from src.validation.json_parser import JSONParser
from src.schemas.intent_schema import JSONParseError


@pytest.fixture
def parser():
    return JSONParser()


class TestJSONParser:

    # === HAPPY PATH (5 tests) ===

    def test_parse_clean_json_object(self, parser):
        """Clean JSON object is parsed and returned as dict."""
        raw = '{"intent":"NETWORK_SCAN","target":{"type":"IP","value":"10.0.0.1"},"confidence":0.9}'
        result = parser.parse(raw)
        assert isinstance(result, dict)
        assert result["intent"] == "NETWORK_SCAN"

    def test_parse_json_with_surrounding_text(self, parser):
        """JSON surrounded by non-JSON text is extracted."""
        raw = 'Here is the output: {"intent":"PASSIVE_RECON","target":{"type":"DOMAIN","value":"example.com"},"confidence":0.8} done.'
        result = parser.parse(raw)
        assert result["intent"] == "PASSIVE_RECON"

    def test_parse_strips_markdown_json_fence(self, parser):
        """Markdown ```json code fence is stripped."""
        raw = '```json\n{"intent":"EXPLOITATION","target":{"type":"IP","value":"10.0.0.5"},"confidence":0.85}\n```'
        result = parser.parse(raw)
        assert result["intent"] == "EXPLOITATION"

    def test_parse_strips_markdown_plain_fence(self, parser):
        """Plain ``` code fence is stripped."""
        raw = '```\n{"intent":"SERVICE_ENUMERATION","target":{"type":"IP","value":"192.168.1.1"},"confidence":0.9}\n```'
        result = parser.parse(raw)
        assert result["intent"] == "SERVICE_ENUMERATION"

    def test_parse_returns_dict_type(self, parser):
        """Parsed result is always a dict."""
        raw = '{"intent":"REJECTED","target":{"type":"UNKNOWN","value":""},"confidence":0.0,"rejection_reason":"test"}'
        result = parser.parse(raw)
        assert isinstance(result, dict)

    # === THINK BLOCK STRIPPING (3 tests) ===

    def test_parse_strips_think_block_before_json(self, parser):
        """Think block before JSON is removed."""
        raw = '<think>I need to figure this out</think>\n{"intent":"NETWORK_SCAN","target":{"type":"IP","value":"10.0.0.1"},"confidence":0.9}'
        result = parser.parse(raw)
        assert result["intent"] == "NETWORK_SCAN"

    def test_parse_strips_think_block_with_newlines(self, parser):
        """Multi-line think block with newlines is removed."""
        raw = '<think>Let me think\n\nabout this carefully</think>\n\n{"intent":"VULNERABILITY_AUDIT","target":{"type":"IP","value":"10.0.0.1"},"confidence":0.9}'
        result = parser.parse(raw)
        assert result["intent"] == "VULNERABILITY_AUDIT"

    def test_parse_strips_think_token(self, parser):
        """<|think|> token is stripped."""
        pipe_char = chr(124)
        raw = '<|think|>{"intent":"DIRECTORY_BRUTEFORCE","target":{"type":"URL","value":"http://example.com"},"confidence":0.85}'
        result = parser.parse(raw)
        assert result["intent"] == "DIRECTORY_BRUTEFORCE"

    # === ERROR CASES (5 tests) ===

    def test_parse_empty_string_raises_json_parse_error(self, parser):
        """Empty string raises JSONParseError."""
        with pytest.raises(JSONParseError):
            parser.parse("")

    def test_parse_no_json_object_raises_json_parse_error(self, parser):
        """Text with no JSON object raises JSONParseError."""
        with pytest.raises(JSONParseError):
            parser.parse("Sorry, I cannot help with that request.")

    def test_parse_malformed_json_raises_json_parse_error(self, parser):
        """Malformed JSON raises JSONParseError."""
        with pytest.raises(JSONParseError):
            parser.parse('{"intent": "NETWORK_SCAN", "target": ')

    def test_parse_json_array_raises_json_parse_error(self, parser):
        """JSON array (not object) raises JSONParseError."""
        with pytest.raises(JSONParseError):
            parser.parse('[1, 2, 3]')

    def test_parse_plain_text_raises_json_parse_error(self, parser):
        """Plain text without any JSON raises JSONParseError."""
        with pytest.raises(JSONParseError):
            parser.parse("This is just plain text with no json at all")

    # === EDGE CASES (2 tests) ===

    def test_parse_nested_json_object(self, parser):
        """Nested JSON objects are parsed correctly."""
        raw = '{"intent":"NETWORK_SCAN","target":{"type":"SUBNET","value":"192.168.1.0/24"},"confidence":0.95}'
        result = parser.parse(raw)
        assert isinstance(result["target"], dict)
        assert result["target"]["type"] == "SUBNET"

    def test_parse_json_with_null_values(self, parser):
        """JSON with null values is parsed correctly."""
        raw = '{"intent":"NETWORK_SCAN","target":{"type":"IP","value":"10.0.0.1"},"tool_hint":null,"schedule":null,"confidence":0.9}'
        result = parser.parse(raw)
        assert result["tool_hint"] is None
        assert result["schedule"] is None
