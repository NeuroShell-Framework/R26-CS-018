import pytest
from src.schemas.models import IREIntentContract, ToolParameters
from src.intent.intent_interpreter import IntentInterpreter

def test_interpret_enriched_c1_format():
    interpreter = IntentInterpreter()
    contract = IREIntentContract(
        intent="NETWORK_SCAN",
        target_type="IP",
        target_value="192.168.1.50",
        primary_tool="nmap",
        tool_parameters=ToolParameters(flags=["stealth"], ports=[80, 443])
    )
    params = interpreter.interpret(contract)
    assert params["intent"] == "NETWORK_SCAN"
    assert params["target_value"] == "192.168.1.50"
    assert params["target_type"] == "IP"
    assert params["ports"] == [80, 443]
    assert params["modifiers"] == ["stealth"]
    assert params["tool_hint"] == "nmap"

def test_interpret_legacy_c1_format():
    interpreter = IntentInterpreter()
    contract = IREIntentContract(
        intent="VULNERABILITY_AUDIT",
        target={"type": "IP", "value": "10.0.0.5"},
        ports=[443],
        modifiers=["ssl"],
        tool_hint="nikto"
    )
    params = interpreter.interpret(contract)
    assert params["intent"] == "VULNERABILITY_AUDIT"
    assert params["target_value"] == "10.0.0.5"
    assert params["ports"] == [443]
    assert params["modifiers"] == ["ssl"]
    assert params["tool_hint"] == "nikto"

def test_interpret_default_ports_fallback():
    interpreter = IntentInterpreter()
    contract = IREIntentContract(
        intent="DIRECTORY_BRUTEFORCE",
        target_value="10.0.0.10",
        tool_hint="gobuster"
    )
    params = interpreter.interpret(contract)
    assert params["ports"] == [80]

def test_interpret_multi_step_calculation():
    interpreter = IntentInterpreter()
    contract = IREIntentContract(
        intent="EXPLOITATION",
        target_value="192.168.1.100",
        confidence=0.90
    )
    params = interpreter.interpret(contract)
    assert params["multi_step"] is True

    contract_low_conf = IREIntentContract(
        intent="EXPLOITATION",
        target_value="192.168.1.100",
        confidence=0.50
    )
    params_low = interpreter.interpret(contract_low_conf)
    assert params_low["multi_step"] is False
