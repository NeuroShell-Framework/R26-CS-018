import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient
from src.api.main import app, API_KEY
from src.rag.context_assembler import ContextAssembler


@pytest.mark.parametrize("options,status", [
    ("-sn", 200),
    ("-sP", 200),
    ("-sn -PE", 200),
    ("-sS -T4", 422),
    ("-PE", 422),
    ("-Pn", 422),
])
def test_public_plan_preserves_ping_mode(options, status):
    command = "nmap " + options + " 10.0.0.20"
    payload = {
        "session_id": "reg-nmap-ping",
        "intent_contract": {
            "intent": "NETWORK_SCAN",
            "target": {"type": "IP", "value": "10.0.0.20"},
            "ports": [],
            "modifiers": ["ping"],
            "tool_hint": "nmap",
            "confidence": 0.93,
        },
    }
    result = {
        "command": command,
        "command_sequence": [command],
        "retrieval_sources": ["nmap"],
    }
    with (
        patch("src.api.main.retriever.retrieve", return_value=[]),
        patch("src.api.main.synthesizer.synthesize", return_value=result),
        patch("src.api.main.session_mgr.update_session"),
        TestClient(app) as client,
    ):
        response = client.post(
            "/plan", json=payload, headers={"x-api-key": API_KEY}
        )
    assert response.status_code == status, response.text
    if status == 422:
        detail = response.json()["detail"]
        assert detail["stage"] == "command_validator"
        assert "requested ping mode" in detail["detail"]


def test_prompt_explains_ping_requirement():
    prompt = ContextAssembler().assemble([], {
        "intent": "NETWORK_SCAN",
        "tool_hint": "nmap",
        "target_value": "10.0.0.20",
        "target_type": "IP",
        "ports": [],
        "modifiers": ["ping"],
    })
    assert "NMAP PING REQUIREMENT" in prompt
    assert "Include -sn" in prompt
