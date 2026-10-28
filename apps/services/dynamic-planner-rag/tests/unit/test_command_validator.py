import pytest
from src.validation.command_validator import CommandValidator

def test_validator_valid_commands():
    cv = CommandValidator()
    passed, issues = cv.validate("nmap -sS 192.168.1.1", "nmap")
    assert passed is True

    passed, issues = cv.validate("nikto -h 10.0.0.1", "nikto")
    assert passed is True

def test_validator_tool_mismatch():
    cv = CommandValidator()
    passed, issues = cv.validate("ls -la 192.168.1.1", "nmap")
    assert passed is False
    assert any("does not start with expected tool" in i for i in issues)

def test_validator_empty_and_multiline():
    cv = CommandValidator()
    passed, issues = cv.validate("", "nmap")
    assert passed is False

    passed, issues = cv.validate("nmap -sS 192.168.1.1\nrm -rf /", "nmap")
    assert passed is False
    assert any("multi-line" in i for i in issues)
