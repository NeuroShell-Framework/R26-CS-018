import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient
from src.api.main import app, API_KEY
from src.rag.context_assembler import ContextAssembler


@pytest.mark.parametrize("url,options,status", [
    ("https://192.168.1.50", "-w common.txt -q", 200),
    ("https://192.168.1.50:443", "-w common.txt --quiet", 200),
    ("http://192.168.1.50:443", "-w common.txt -k -q", 422),
    ("https://192.168.1.50", "-w common.txt", 422),
    ("https://192.168.1.50:8443", "-w common.txt -q", 422),
    ("https://192.168.1.50", "-q", 422),
    ("https://192.168.1.51", "-w common.txt -q", 422),
])
def test_public_plan_gobuster_ssl_and_silent(url, options, status):
    command = "gobuster dir -u " + url + " " + options
    # Explicit wordlist regression case; not the original BENCH-015 input.
    payload = {
        "session_id": "reg-gobuster-transport",
        "intent": "DIRECTORY_BRUTEFORCE",
        "target_value": "192.168.1.50",
        "target_type": "URL",
        "ports": [443],
        "modifiers": ["ssl", "silent"],
        "primary_tool": "gobuster",
        "tool_parameters": {"wordlist": "common.txt"},
    }
    result = {
        "command": command,
        "command_sequence": [command],
        "retrieval_sources": ["gobuster"],
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


def test_prompt_explains_https_and_quiet():
    prompt = ContextAssembler().assemble([], {
        "intent": "DIRECTORY_BRUTEFORCE",
        "tool_hint": "gobuster",
        "target_value": "192.168.1.50",
        "target_type": "URL",
        "ports": [443],
        "modifiers": ["ssl", "silent"],
        "wordlist": "common.txt",
    })
    assert "https:// target URL in -u" in prompt
    assert "silent modifier requires -q or --quiet" in prompt
