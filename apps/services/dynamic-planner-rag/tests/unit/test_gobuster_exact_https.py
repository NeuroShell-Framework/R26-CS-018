import shlex
import copy
import pytest
from src.rag.context_assembler import ContextAssembler


@pytest.mark.parametrize("target,ports,expected", [
    ("192.168.1.50", [443], "https://192.168.1.50:443"),
    ("10.20.30.40/admin", [8443], "https://10.20.30.40:8443/admin"),
    ("172.16.5.25:8443/admin?q=test", [8443],
     "https://172.16.5.25:8443/admin?q=test"),
    ("192.168.1.50", [], "https://192.168.1.50:443"),
])
def test_exact_https_is_derived_without_mutating_request(target, ports, expected):
    params = {
        "intent": "DIRECTORY_BRUTEFORCE",
        "tool_hint": "gobuster",
        "target_value": target,
        "target_type": "URL",
        "ports": ports,
        "modifiers": ["ssl", "silent"],
        "wordlist": "common.txt",
    }
    original = copy.deepcopy(params)
    prompt = ContextAssembler().assemble([], params)
    rule = next(
        line for line in prompt.splitlines()
        if line.startswith("EXACT REQUESTED TRANSPORT:")
    )
    rendered_url = rule.split("Use -u ", 1)[1].split(
        ". The request requires HTTPS", 1
    )[0]
    assert shlex.split(rendered_url) == [expected]
    assert "Include -q for requested silent mode." in prompt
    assert params == original


def test_explicit_http_is_not_silently_rewritten():
    prompt = ContextAssembler().assemble([], {
        "intent": "DIRECTORY_BRUTEFORCE",
        "tool_hint": "gobuster",
        "target_value": "http://192.168.1.50/admin",
        "target_type": "URL",
        "ports": [443],
        "modifiers": ["ssl"],
        "wordlist": "common.txt",
    })
    assert "EXACT REQUESTED TRANSPORT:" not in prompt


def test_conflicting_explicit_port_is_rejected():
    with pytest.raises(ValueError, match="Conflicting URL port"):
        ContextAssembler().assemble([], {
            "intent": "DIRECTORY_BRUTEFORCE",
            "tool_hint": "gobuster",
            "target_value": "192.168.1.50:8080/admin",
            "target_type": "URL",
            "ports": [443],
            "modifiers": ["ssl"],
            "wordlist": "common.txt",
        })
