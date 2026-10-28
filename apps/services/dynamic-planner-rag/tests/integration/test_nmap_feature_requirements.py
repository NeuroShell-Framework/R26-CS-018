import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient
from src.api.main import app, API_KEY
from src.rag.context_assembler import ContextAssembler


@pytest.mark.parametrize("options,status", [
    ("-sS -T4", 422),
    ("-A", 422),
    ("-p-", 422),
    ("-A -p-", 200),
    ("-A -p1-65535", 200),
    ("-A -p 1-65535", 200),
    ("-O -sV -sC --traceroute -p-", 200),
    ("-A -p 1-1000", 422),
    ("-A -p- -F", 422),
    ("-A -p- --top-ports 100", 422),
    ("-A -p- -sn", 422),
])
def test_public_plan_preserves_nmap_features(options, status):
    command = "nmap " + options + " 192.168.1.5"
    payload = {
        "session_id": "reg-nmap-features",
        "intent_contract": {
            "intent": "NETWORK_SCAN",
            "target": {"type": "IP", "value": "192.168.1.5"},
            "ports": [],
            "modifiers": ["aggressive", "all-ports"],
            "tool_hint": "nmap",
            "confidence": 0.9,
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
        assert response.json()["detail"]["stage"] == "command_validator"


def test_prompt_explains_features_without_forcing_timing():
    prompt = ContextAssembler().assemble([], {
        "intent": "NETWORK_SCAN",
        "tool_hint": "nmap",
        "target_value": "192.168.1.5",
        "target_type": "IP",
        "ports": [],
        "modifiers": ["aggressive", "all-ports"],
    })
    assert "aggressive modifier requires -A" in prompt
    assert "all-ports modifier requires -p-" in prompt
    assert "Timing -T4 alone does not satisfy it" in prompt
