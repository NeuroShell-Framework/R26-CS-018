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
    assert "stealth" in params["modifiers"]
    assert "-p 80,443" in params["modifiers"]
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
    assert "ssl" in params["modifiers"]
    assert "-p 443" in params["modifiers"]
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


def test_interpret_target_type_inference_ip_and_cidr():
    interpreter = IntentInterpreter()

    # Valid IP inference
    contract_ip = IREIntentContract(
        intent="NETWORK_SCAN",
        target_value="192.168.1.10",
        primary_tool="nmap"
    )
    params_ip = interpreter.interpret(contract_ip)
    assert params_ip["target_type"] == "IP"

    # Valid CIDR Subnet inference
    contract_cidr = IREIntentContract(
        intent="NETWORK_SCAN",
        target_value="10.0.0.0/24",
        primary_tool="nmap"
    )
    params_cidr = interpreter.interpret(contract_cidr)
    assert params_cidr["target_type"] == "SUBNET"

    # HTTP/HTTPS URL inference
    contract_url = IREIntentContract(
        intent="VULNERABILITY_AUDIT",
        target_value="http://192.168.1.10:8080/app",
        primary_tool="nikto"
    )
    params_url = interpreter.interpret(contract_url)
    assert params_url["target_type"] == "URL"

    # Domain inference
    contract_domain = IREIntentContract(
        intent="DIRECTORY_BRUTEFORCE",
        target_value="example.com",
        primary_tool="gobuster"
    )
    params_domain = interpreter.interpret(contract_domain)
    assert params_domain["target_type"] == "DOMAIN"

    # Preservation of C1 supplied target_type
    contract_c1_override = IREIntentContract(
        intent="NETWORK_SCAN",
        target_type="CUSTOM_TYPE",
        target_value="192.168.1.10",
        primary_tool="nmap"
    )
    params_override = interpreter.interpret(contract_c1_override)
    assert params_override["target_type"] == "CUSTOM_TYPE"


def test_nmap_and_nikto_explicit_port_preservation_and_rejection():
    from scripts.cli_ast_validator import CLIASTValidator
    validator = CLIASTValidator()

    # 1. Nmap Port Preservation & Rejection
    # Correct Nmap command containing requested ports 80, 443
    valid_nmap_cmd = "nmap -p 80,443 192.168.1.50"
    nmap_tokens = valid_nmap_cmd.split()
    assert validator._check_ports_preservation(nmap_tokens, [80, 443], "nmap", valid_nmap_cmd) is True

    # Missing port 443 in Nmap command (only port 80 present) -> Rejection
    invalid_nmap_cmd = "nmap -p 80 192.168.1.50"
    invalid_nmap_tokens = invalid_nmap_cmd.split()
    assert validator._check_ports_preservation(invalid_nmap_tokens, [80, 443], "nmap", invalid_nmap_cmd) is False

    # 2. Nikto Port Preservation & Rejection
    # Correct Nikto command with explicit port 8080
    valid_nikto_cmd = "nikto -h 10.0.0.5 -p 8080"
    nikto_tokens = valid_nikto_cmd.split()
    assert validator._check_ports_preservation(nikto_tokens, [8080], "nikto", valid_nikto_cmd) is True

    # Incorrect port 80 in Nikto command when 8080 requested -> Rejection
    invalid_nikto_cmd = "nikto -h 10.0.0.5 -p 80"
    invalid_nikto_tokens = invalid_nikto_cmd.split()
    assert validator._check_ports_preservation(invalid_nikto_tokens, [8080], "nikto", invalid_nikto_cmd) is False


