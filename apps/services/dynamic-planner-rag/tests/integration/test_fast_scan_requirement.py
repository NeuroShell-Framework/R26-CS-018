import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient
from src.api.main import app, API_KEY
from src.rag.context_assembler import ContextAssembler


@pytest.mark.parametrize("modifier", ["fast", "quick"])
@pytest.mark.parametrize("has_fast_flag", [False, True])
def test_public_plan_enforces_fast_selection(modifier, has_fast_flag):
    command = (
        "nmap -F 192.168.0.1"
        if has_fast_flag else "nmap -sS -T4 192.168.0.1"
    )
    payload = {
        "session_id": "reg-fast-" + modifier + str(has_fast_flag),
        "intent_contract": {
            "intent": "NETWORK_SCAN",
            "target": {"type": "IP", "value": "192.168.0.1"},
            "ports": [],
            "modifiers": [modifier],
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

    assert response.status_code == (200 if has_fast_flag else 422)
    if has_fast_flag:
        assert response.json()["command"] == command
    else:
        detail = response.json()["detail"]
        assert detail["stage"] == "command_validator"
        assert "requires -F" in detail["detail"]


@pytest.mark.parametrize("modifier", ["fast", "quick"])
def test_prompt_explains_fast_port_selection(modifier):
    prompt = ContextAssembler().assemble([], {
        "intent": "NETWORK_SCAN",
        "tool_hint": "nmap",
        "target_value": "192.168.0.1",
        "target_type": "IP",
        "ports": [],
        "modifiers": [modifier],
    })
    assert "FAST PORT SELECTION REQUIREMENT" in prompt
    assert "Include -F" in prompt


def test_explicit_ports_do_not_receive_fast_selection_rule():
    prompt = ContextAssembler().assemble([], {
        "intent": "NETWORK_SCAN",
        "tool_hint": "nmap",
        "target_value": "192.168.0.1",
        "target_type": "IP",
        "ports": [80, 443],
        "modifiers": ["fast"],
    })
    assert "FAST PORT SELECTION REQUIREMENT" not in prompt
