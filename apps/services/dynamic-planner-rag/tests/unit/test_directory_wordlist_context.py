import copy
import pytest

from src.intent.query_constructor import (
    QueryConstructor, needs_directory_wordlist_context,
)
from src.rag.context_assembler import ContextAssembler
from src.validation.command_validator import CommandValidator


def directory_params():
    return {
        "intent": "DIRECTORY_BRUTEFORCE",
        "sub_intent": "directory_enumeration",
        "tool_hint": "gobuster",
        "target_value": "192.168.1.50",
        "target_type": "URL",
        "ports": [80],
        "modifiers": [],
    }


def test_missing_wordlist_expands_query_and_removes_placeholder_instruction():
    params = directory_params()
    original = copy.deepcopy(params)
    query = QueryConstructor().build_query(params)
    prompt = ContextAssembler().assemble([{
        "tool": "gobuster",
        "content": "Directory wordlist: /usr/share/wordlists/dirb/common.txt",
    }], params)

    assert "common Kali wordlist paths" in query
    assert "WORDLIST REQUIREMENT: No exact wordlist was supplied." in prompt
    assert not any(
        "Because no additional modifiers were requested" in line
        and "<wordlist>" in line
        for line in prompt.splitlines()
    )
    assert params == original


@pytest.mark.parametrize("override", [
    {"wordlist": "custom.txt"},
    {"tool_parameters": {"wordlist": "custom.txt"}},
    {"modifiers": ["-w custom.txt"]},
    {"modifiers": ["-w", "custom.txt"]},
    {"modifiers": ["--wordlist=custom.txt"]},
    {"modifiers": ["dns"]},
    {"modifiers": ["vhost"]},
    {"modifiers": ["fuzz"]},
    {"mode": "dns"},
    {"tool_parameters": {"mode": "vhost"}},
    {"sub_intent": "subdomain_enumeration"},
    {"tool_hint": "nmap"},
    {"multi_step": True},
])
def test_explicit_wordlists_and_other_modes_are_not_changed(override):
    params = directory_params()
    params.update(override)
    assert needs_directory_wordlist_context(params) is False
    assert "common Kali wordlist paths" not in QueryConstructor().build_query(params)


@pytest.mark.parametrize("wordlist", [
    "/path/to/wordlist", "path/to/wordlist", "<wordlist>", "{wordlist}",
])
def test_placeholder_wordlist_rejected_without_expected_wordlist(wordlist):
    passed, issues = CommandValidator().validate(
        "gobuster dir -u http://192.168.1.50 -w " + wordlist,
        "gobuster",
        target_value="http://192.168.1.50",
        target_type="URL",
    )
    assert not passed
    assert any("placeholder" in issue for issue in issues)


def test_malformed_quotes_do_not_raise_during_query_scope_detection():
    params = directory_params()
    params["modifiers"] = ['-w "unclosed quote']
    assert needs_directory_wordlist_context(params) is False
    assert isinstance(QueryConstructor().build_query(params), str)
