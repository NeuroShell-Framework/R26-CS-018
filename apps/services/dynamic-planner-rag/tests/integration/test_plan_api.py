import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient
from src.api.main import app, API_KEY

client = TestClient(app)

def test_plan_endpoint_auth_failure():
    payload = {
        "session_id": "integration-001",
        "intent": "NETWORK_SCAN",
        "target_value": "192.168.1.1"
    }
    response = client.post("/plan", json=payload, headers={"x-api-key": "invalid-key"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid API key"

def test_plan_endpoint_rejected_intent():
    payload = {
        "session_id": "integration-002",
        "intent_contract": {
            "intent": "REJECTED",
            "rejection_reason": "Out of bounds intent classified by C1"
        }
    }
    response = client.post("/plan", json=payload, headers={"x-api-key": API_KEY})
    assert response.status_code == 400
    data = response.json()["detail"]
    assert data["stage"] == "intent_filter"
    assert data["error"] == "INTENT_REJECTED"

def test_plan_endpoint_safety_block_public_ip():
    payload = {
        "session_id": "integration-003",
        "intent": "NETWORK_SCAN",
        "target_value": "8.8.8.8",
        "primary_tool": "nmap"
    }
    response = client.post("/plan", json=payload, headers={"x-api-key": API_KEY})
    assert response.status_code == 400
    assert "Safety check failed" in response.json()["detail"]

def test_plan_endpoint_strict_validator_failure():
    # Mock synthesizer returning a command that fails CommandValidator (binary mismatch)
    with patch("src.synthesis.command_synthesizer.CommandSynthesizer.synthesize") as mock_synth:
        mock_synth.return_value = {
            "command": "echo 'invalid command for nmap' 192.168.1.1",
            "retrieval_sources": ["nmap.txt"],
            "query_used": "test"
        }
        payload = {
            "session_id": "integration-004",
            "intent": "NETWORK_SCAN",
            "target_value": "192.168.1.1",
            "primary_tool": "nmap"
        }
        response = client.post("/plan", json=payload, headers={"x-api-key": API_KEY})
        assert response.status_code == 422
        data = response.json()["detail"]
        assert data["stage"] == "command_validator"
        assert data["error"] == "VALIDATION_FAILED"

def test_plan_endpoint_session_target_recovery():
    # Request 1 with target 192.168.1.99
    with patch("src.synthesis.command_synthesizer.CommandSynthesizer.synthesize") as mock_synth:
        mock_synth.return_value = {
            "command": "nmap -sS 192.168.1.99",
            "retrieval_sources": ["nmap.txt"],
            "query_used": "test"
        }
        payload1 = {
            "session_id": "session-recovery-test",
            "intent": "NETWORK_SCAN",
            "target_value": "192.168.1.99",
            "primary_tool": "nmap"
        }
        resp1 = client.post("/plan", json=payload1, headers={"x-api-key": API_KEY})
        assert resp1.status_code == 200

        # Request 2 missing target_value -> recovers 192.168.1.99 from session history
        payload2 = {
            "session_id": "session-recovery-test",
            "intent": "NETWORK_SCAN",
            "target_value": "UNKNOWN",
            "primary_tool": "nmap"
        }
        resp2 = client.post("/plan", json=payload2, headers={"x-api-key": API_KEY})
        assert resp2.status_code == 200
        assert resp2.json()["status"] == "success"

def test_health_tools_and_metrics_endpoints():
    res_health = client.get("/health")
    assert res_health.status_code == 200
    assert res_health.json()["component"] == "C2-DynamicPlanner"

    res_tools = client.get("/tools/available")
    assert res_tools.status_code == 200
    assert "nmap" in res_tools.json()["tools"]

    res_metrics = client.get("/metrics", headers={"x-api-key": API_KEY})
    assert res_metrics.status_code == 200
    assert "total" in res_metrics.json()

def test_plan_endpoint_nikto_default_url_port_with_p_flag_success():
    with patch("src.synthesis.command_synthesizer.CommandSynthesizer.synthesize") as mock_synth:
        mock_synth.return_value = {
            "command": "nikto -h http://10.0.0.5 -p 8080",
            "command_sequence": ["nikto -h http://10.0.0.5 -p 8080"],
            "retrieval_sources": ["nikto.txt"],
            "query_used": "test"
        }
        payload = {
            "session_id": "reg-nikto-001",
            "intent": "VULNERABILITY_AUDIT",
            "target_value": "http://10.0.0.5",
            "target_type": "URL",
            "ports": [8080],
            "primary_tool": "nikto"
        }
        res = client.post("/plan", json=payload, headers={"x-api-key": API_KEY})
        assert res.status_code == 200
        assert res.json()["validation_passed"] is True
        assert res.json()["command"] == "nikto -h http://10.0.0.5 -p 8080"

def test_plan_endpoint_nikto_contradictory_url_port_rejected():
    with patch("src.synthesis.command_synthesizer.CommandSynthesizer.synthesize") as mock_synth:
        mock_synth.return_value = {
            "command": "nikto -h http://10.0.0.5:8080 -p 80",
            "command_sequence": ["nikto -h http://10.0.0.5:8080 -p 80"],
            "retrieval_sources": ["nikto.txt"],
            "query_used": "test"
        }
        payload = {
            "session_id": "reg-nikto-002",
            "intent": "VULNERABILITY_AUDIT",
            "target_value": "http://10.0.0.5:8080",
            "target_type": "URL",
            "ports": [8080],
            "primary_tool": "nikto"
        }
        res = client.post("/plan", json=payload, headers={"x-api-key": API_KEY})
        assert res.status_code == 422
        data = res.json()["detail"]
        assert data["stage"] == "command_validator"
        assert data["error"] == "VALIDATION_FAILED"

def test_plan_endpoint_url_port_mismatch_isolated():
    with patch("src.synthesis.command_synthesizer.CommandSynthesizer.synthesize") as mock_synth:
        mock_synth.return_value = {
            "command": "gobuster dir -u http://192.168.1.50:80/admin -w /usr/share/wordlists/common.txt",
            "command_sequence": ["gobuster dir -u http://192.168.1.50:80/admin -w /usr/share/wordlists/common.txt"],
            "retrieval_sources": ["gobuster.txt"],
            "query_used": "test"
        }
        payload = {
            "session_id": "reg-iso-001",
            "intent": "DIRECTORY_BRUTEFORCE",
            "target_value": "http://192.168.1.50:8080/admin",
            "target_type": "URL",
            "ports": [8080],
            "primary_tool": "gobuster"
        }
        res = client.post("/plan", json=payload, headers={"x-api-key": API_KEY})
        assert res.status_code == 422
        assert res.json()["detail"]["error"] == "VALIDATION_FAILED"

def test_plan_endpoint_trailing_slash_mismatch_rejected():
    with patch("src.synthesis.command_synthesizer.CommandSynthesizer.synthesize") as mock_synth:
        mock_synth.return_value = {
            "command": "gobuster dir -u http://192.168.1.50/admin/ -w /usr/share/wordlists/common.txt",
            "command_sequence": ["gobuster dir -u http://192.168.1.50/admin/ -w /usr/share/wordlists/common.txt"],
            "retrieval_sources": ["gobuster.txt"],
            "query_used": "test"
        }
        payload = {
            "session_id": "reg-slash-001",
            "intent": "DIRECTORY_BRUTEFORCE",
            "target_value": "http://192.168.1.50/admin",
            "target_type": "URL",
            "ports": [80],
            "primary_tool": "gobuster"
        }
        res = client.post("/plan", json=payload, headers={"x-api-key": API_KEY})
        assert res.status_code == 422
        assert res.json()["detail"]["error"] == "VALIDATION_FAILED"

def test_plan_endpoint_cidr_prefix_mismatch_rejected():
    with patch("src.synthesis.command_synthesizer.CommandSynthesizer.synthesize") as mock_synth:
        mock_synth.return_value = {
            "command": "nmap -sS 192.168.0.0/16",
            "command_sequence": ["nmap -sS 192.168.0.0/16"],
            "retrieval_sources": ["nmap.txt"],
            "query_used": "test"
        }
        payload = {
            "session_id": "reg-cidr-001",
            "intent": "NETWORK_SCAN",
            "target_value": "192.168.0.0/24",
            "target_type": "SUBNET",
            "ports": [],
            "primary_tool": "nmap"
        }
        res = client.post("/plan", json=payload, headers={"x-api-key": API_KEY})
        assert res.status_code == 422
        assert res.json()["detail"]["error"] == "VALIDATION_FAILED"

def test_plan_endpoint_extra_target_rejected():
    with patch("src.synthesis.command_synthesizer.CommandSynthesizer.synthesize") as mock_synth:
        mock_synth.return_value = {
            "command": "nmap -sS 192.168.1.50 192.168.1.51",
            "command_sequence": ["nmap -sS 192.168.1.50 192.168.1.51"],
            "retrieval_sources": ["nmap.txt"],
            "query_used": "test"
        }
        payload = {
            "session_id": "reg-extra-001",
            "intent": "NETWORK_SCAN",
            "target_value": "192.168.1.50",
            "target_type": "IP",
            "ports": [],
            "primary_tool": "nmap"
        }
        res = client.post("/plan", json=payload, headers={"x-api-key": API_KEY})
        assert res.status_code == 422
        assert res.json()["detail"]["error"] == "VALIDATION_FAILED"

def test_plan_endpoint_malformed_quotes_rejected():
    with patch("src.synthesis.command_synthesizer.CommandSynthesizer.synthesize") as mock_synth:
        mock_synth.return_value = {
            "command": 'nmap -sS "192.168.1.50',
            "command_sequence": ['nmap -sS "192.168.1.50'],
            "retrieval_sources": ["nmap.txt"],
            "query_used": "test"
        }
        payload = {
            "session_id": "reg-quote-001",
            "intent": "NETWORK_SCAN",
            "target_value": "192.168.1.50",
            "target_type": "IP",
            "ports": [],
            "primary_tool": "nmap"
        }
        res = client.post("/plan", json=payload, headers={"x-api-key": API_KEY})
        assert res.status_code == 422
        assert res.json()["detail"]["error"] == "VALIDATION_FAILED"

def test_plan_endpoint_nmap_malformed_attached_port_rejected():
    with patch("src.synthesis.command_synthesizer.CommandSynthesizer.synthesize") as mock_synth:
        mock_synth.return_value = {
            "command": "nmap -p-abc 192.168.1.50",
            "command_sequence": ["nmap -p-abc 192.168.1.50"],
            "retrieval_sources": ["nmap.txt"],
            "query_used": "test"
        }
        payload = {
            "session_id": "reg-nmap-001",
            "intent": "NETWORK_SCAN",
            "target_value": "192.168.1.50",
            "target_type": "IP",
            "ports": [],
            "primary_tool": "nmap"
        }
        res = client.post("/plan", json=payload, headers={"x-api-key": API_KEY})
        assert res.status_code == 422
        assert res.json()["detail"]["error"] == "VALIDATION_FAILED"

def test_plan_endpoint_client_malformed_quotes_returns_http_400():
    payload = {
        "session_id": "reg-client-quote-001",
        "intent": "DIRECTORY_BRUTEFORCE",
        "target_value": "http://192.168.1.50",
        "target_type": "URL",
        "ports": [80],
        "primary_tool": "gobuster",
        "modifiers": ['-w "unclosed quote']
    }
    res = client.post("/plan", json=payload, headers={"x-api-key": API_KEY})
    assert res.status_code == 400
    detail = res.json()["detail"]
    assert detail["status"] == "error"
    assert detail["error"] == "INVALID_INPUT_PARAMETER"
    assert "Malformed quoting in modifier" in detail["detail"]

def test_plan_endpoint_client_missing_wordlist_returns_http_400():
    payload = {
        "session_id": "reg-client-wl-001",
        "intent": "DIRECTORY_BRUTEFORCE",
        "target_value": "http://192.168.1.50",
        "target_type": "URL",
        "ports": [80],
        "primary_tool": "gobuster",
        "modifiers": ["-w"]
    }
    res = client.post("/plan", json=payload, headers={"x-api-key": API_KEY})
    assert res.status_code == 400
    detail = res.json()["detail"]
    assert detail["status"] == "error"
    assert detail["error"] == "INVALID_INPUT_PARAMETER"
    assert "missing a wordlist argument" in detail["detail"]

def test_plan_endpoint_client_empty_wordlist_returns_http_400():
    payload = {
        "session_id": "reg-client-wl-002",
        "intent": "DIRECTORY_BRUTEFORCE",
        "target_value": "http://192.168.1.50",
        "target_type": "URL",
        "ports": [80],
        "primary_tool": "gobuster",
        "modifiers": ["--wordlist="]
    }
    res = client.post("/plan", json=payload, headers={"x-api-key": API_KEY})
    assert res.status_code == 400
    detail = res.json()["detail"]
    assert detail["status"] == "error"
    assert detail["error"] == "INVALID_INPUT_PARAMETER"
    assert "specifies an empty wordlist" in detail["detail"]
