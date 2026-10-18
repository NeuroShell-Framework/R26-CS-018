import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient
from src.api.main import app, API_KEY
from src.rag.context_assembler import ContextAssembler


@pytest.mark.parametrize("commands,status", [
    (["nikto -h 172.16.0.1 -p 8443"], 422),
    (["nikto -h 172.16.0.1 -p 8443 -ssl"], 200),
    (["nikto -h https://172.16.0.1:8443"], 200),
    (["nikto -h 172.16.0.1 -p 8443 -ssl -nossl"], 422),
    (["nikto -h https://172.16.0.1:8443 -nossl"], 422),
    ([
        "nikto -h 172.16.0.1 -p 8443 -ssl",
        "nikto -h 172.16.0.1 -p 8443",
    ], 422),
])
def test_public_plan_preserves_nikto_ssl(commands, status):
    payload = {
        "session_id": "reg-nikto-ssl",
        "intent_contract": {
            "intent": "VULNERABILITY_AUDIT",
            "target": {"type": "IP", "value": "172.16.0.1"},
            "ports": [8443],
            "modifiers": ["ssl"],
            "tool_hint": "nikto",
            "confidence": 0.96,
        },
    }
    result = {
        "command": commands[0],
        "command_sequence": commands,
        "retrieval_sources": ["nikto"],
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
        assert "requested Nikto SSL" in detail["detail"]


def test_ssl_prompt_requirement_applies_to_multistep():
    prompt = ContextAssembler().assemble([], {
        "intent": "VULNERABILITY_AUDIT",
        "tool_hint": "nikto",
        "target_value": "172.16.0.1",
        "target_type": "IP",
        "ports": [8443],
        "modifiers": ["ssl", "-p 8443"],
        "multi_step": True,
    })
    assert "NIKTO SSL REQUIREMENT" in prompt
    assert "Include -ssl" in prompt
    assert prompt.endswith("COMMAND SEQUENCE:")
