import pytest
from src.intent.query_constructor import QueryConstructor, MODIFIER_TEXT_MAP

def test_query_constructor_network_scan():
    constructor = QueryConstructor()
    params = {
        "intent": "NETWORK_SCAN",
        "modifiers": ["stealth"],
        "target_type": "IP",
        "ports": [],
        "cve_ids": []
    }
    query = constructor.build_query(params)
    assert "nmap" in query
    assert "SYN stealth scan" in query
    assert "network port scan syntax" in query

def test_query_constructor_vulnerability_audit():
    constructor = QueryConstructor()
    params = {
        "intent": "VULNERABILITY_AUDIT",
        "modifiers": ["ssl"],
        "target_type": "URL",
        "ports": [443],
        "cve_ids": []
    }
    query = constructor.build_query(params)
    assert "nikto web vulnerability scan" in query
    assert "HTTPS SSL TLS" in query
    assert "443" in query

def test_query_constructor_whitespace_normalization():
    constructor = QueryConstructor()
    params = {
        "intent": "DIRECTORY_BRUTEFORCE",
        "modifiers": [],
        "target_type": "IP",
        "ports": [],
        "cve_ids": []
    }
    query = constructor.build_query(params)
    assert "  " not in query
    assert query == query.strip()
