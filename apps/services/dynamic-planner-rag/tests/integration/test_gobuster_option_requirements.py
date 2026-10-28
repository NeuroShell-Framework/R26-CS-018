import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient
from src.api.main import app, API_KEY
from src.rag.context_assembler import ContextAssembler


@pytest.mark.parametrize("options,status", [
    ("-w common.txt -x php,html -t 20", 200),
    ("--wordlist=common.txt --extensions=html,php --threads=20", 200),
    ("-wcommon.txt -xphp,html -t20", 200),
    ("-x php,html -t 20", 422),
    ('-w "" -x php,html -t 20', 422),
    ("-w -x php,html -t 20", 422),
    ("-w <wordlist> -x php,html -t 20", 422),
    ("-w {wordlist} -x php,html -t 20", 422),
    ("-w other.txt -x php,html -t 20", 422),
    ("-w common.txt -t 20", 422),
    ("-w common.txt -x txt -t 20", 422),
    ("-w common.txt -x php,html", 422),
    ("-w common.txt -x php,html -t 50", 422),
    ("-w common.txt -w other.txt -x php,html -t 20", 422),
])
def test_public_plan_gobuster_options(options, status):
    command = "gobuster dir -u http://192.168.1.50 " + options
    payload = {
        "session_id": "reg-gobuster-options",
        "intent": "DIRECTORY_BRUTEFORCE",
        "target_value": "http://192.168.1.50",
        "target_type": "URL",
        "ports": [80],
        "primary_tool": "gobuster",
        "modifiers": ["extension:php,html", "threads:20"],
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


def test_gobuster_prompt_explains_requested_options():
    prompt = ContextAssembler().assemble([], {
        "intent": "DIRECTORY_BRUTEFORCE",
        "tool_hint": "gobuster",
        "target_value": "http://192.168.1.50",
        "target_type": "URL",
        "ports": [80],
        "modifiers": ["extension:php,html", "threads:20"],
        "wordlist": "common.txt",
    })
    assert "Use -x php,html" in prompt
    assert "Use -t 20" in prompt
