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
