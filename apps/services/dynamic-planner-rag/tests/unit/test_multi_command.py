import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient

from src.schemas.models import IREIntentContract, ToolParameters, PlannerOutput
from src.intent.intent_interpreter import IntentInterpreter
from src.rag.context_assembler import ContextAssembler
from src.synthesis.command_synthesizer import CommandSynthesizer
from src.api.main import app, API_KEY

client = TestClient(app)


def test_suggested_command_prompt_assembly():
    assembler = ContextAssembler()
    docs = [{"tool": "nmap", "content": "TOOL: nmap\n-sS SYN stealth scan", "score": 0.3}]
    
    # Case A: suggested_command present
    contract_with_hint = {
        "intent": "NETWORK_SCAN",
        "target_value": "192.168.1.1",
        "ports": [80],
        "modifiers": ["stealth"],
        "suggested_command": "nmap -sS -p 80 192.168.1.1",
        "multi_step": False
    }
    prompt_a = assembler.assemble(docs, contract_with_hint)
    assert "SUGGESTED COMMAND REFERENCE:" in prompt_a
    assert "nmap -sS -p 80 192.168.1.1" in prompt_a
    assert "COMMAND:" in prompt_a

    # Case B: suggested_command absent
    contract_without_hint = {
        "intent": "NETWORK_SCAN",
        "target_value": "192.168.1.1",
        "ports": [80],
        "modifiers": ["stealth"],
        "multi_step": False
    }
    prompt_b = assembler.assemble(docs, contract_without_hint)
    assert "SUGGESTED COMMAND REFERENCE:" not in prompt_b


def test_multi_step_prompt_assembly():
    assembler = ContextAssembler()
    docs = [{"tool": "nikto", "content": "TOOL: nikto\n-h <host>", "score": 0.3}]
    
    contract_multi = {
        "intent": "VULNERABILITY_AUDIT",
        "target_value": "192.168.1.10",
        "ports": [80],
        "modifiers": [],
        "multi_step": True
    }
    prompt = assembler.assemble(docs, contract_multi)
    assert "COMMAND SEQUENCE:" in prompt
    assert "ordered sequence of valid bash commands" in prompt


def test_command_synthesizer_output_parser():
    synth = CommandSynthesizer()
    
    raw_llm_output = """
```bash
1. nmap -sS -p 80 192.168.1.1
2. nmap -sV -p 80 192.168.1.1
```
Here is the summary of commands.
"""
    parsed_single = synth.parse_command_output(raw_llm_output, multi_step=False)
    assert len(parsed_single) == 1
    assert parsed_single[0] == "nmap -sS -p 80 192.168.1.1"

    parsed_multi = synth.parse_command_output(raw_llm_output, multi_step=True)
    assert len(parsed_multi) == 2
    assert parsed_multi[0] == "nmap -sS -p 80 192.168.1.1"
    assert parsed_multi[1] == "nmap -sV -p 80 192.168.1.1"


def test_multi_step_plan_endpoint_success():
    with patch("src.synthesis.command_synthesizer.CommandSynthesizer.synthesize") as mock_synth:
        mock_synth.return_value = {
            "command": "nmap -sS -p 80 192.168.1.50",
            "command_sequence": [
                "nmap -sS -p 80 192.168.1.50",
                "nmap -sV -p 80 192.168.1.50"
            ],
            "retrieval_sources": ["nmap.txt"],
            "query_used": "nmap scan"
        }
        
        payload = {
            "session_id": "test-multi-001",
            "intent_contract": {
                "intent": "EXPLOITATION",
                "target_value": "192.168.1.50",
                "primary_tool": "nmap",
                "confidence": 0.95
            }
        }
        
        response = client.post("/plan", json=payload, headers={"x-api-key": API_KEY})
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["command"] == "nmap -sS -p 80 192.168.1.50"
        assert len(data["command_sequence"]) == 2
        assert data["command_sequence"][1] == "nmap -sV -p 80 192.168.1.50"


def test_multi_step_sequence_safety_failure():
    with patch("src.synthesis.command_synthesizer.CommandSynthesizer.synthesize") as mock_synth:
        mock_synth.return_value = {
            "command": "nmap -sS -p 80 192.168.1.50",
            "command_sequence": [
                "nmap -sS -p 80 192.168.1.50",
                "rm -rf /"  # Dangerous command pattern inside sequence
            ],
            "retrieval_sources": ["nmap.txt"],
            "query_used": "test"
        }
        
        payload = {
            "session_id": "test-multi-unsafe",
            "intent_contract": {
                "intent": "EXPLOITATION",
                "target_value": "192.168.1.50",
                "primary_tool": "nmap",
                "confidence": 0.95
            }
        }
        
        response = client.post("/plan", json=payload, headers={"x-api-key": API_KEY})
        assert response.status_code == 400
        assert "Safety check failed" in response.json()["detail"]


def test_multi_step_sequence_validator_failure():
    with patch("src.synthesis.command_synthesizer.CommandSynthesizer.synthesize") as mock_synth:
        mock_synth.return_value = {
            "command": "nmap -sS -p 80 192.168.1.50",
            "command_sequence": [
                "nmap -sS -p 80 192.168.1.50",
                "echo invalid_binary 192.168.1.50"  # Binary validation failure
            ],
            "retrieval_sources": ["nmap.txt"],
            "query_used": "test"
        }
        
        payload = {
            "session_id": "test-multi-invalid",
            "intent_contract": {
                "intent": "EXPLOITATION",
                "target_value": "192.168.1.50",
                "primary_tool": "nmap",
                "confidence": 0.95
            }
        }
        
        response = client.post("/plan", json=payload, headers={"x-api-key": API_KEY})
        assert response.status_code == 422
        data = response.json()["detail"]
        assert data["stage"] == "command_validator"
        assert data["error"] == "VALIDATION_FAILED"
