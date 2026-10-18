import pytest
from src.rag.context_assembler import ContextAssembler


def test_context_assembler_prompt_ordering_single_step():
    assembler = ContextAssembler()
    docs = [{"tool": "gobuster", "content": "TOOL: gobuster\n-u <url>", "score": 0.4}]
    contract = {
        "intent": "DIRECTORY_BRUTEFORCE",
        "target_value": "http://192.168.1.50",
        "ports": [80],
        "modifiers": ["-w common.txt"],
        "multi_step": False
    }
    prompt = assembler.assemble(docs, contract)

    # Verify sequential ordering of sections
    idx_header = prompt.find("You are NeuroShell Component 2")
    idx_docs = prompt.find("TOOL DOCUMENTATION:")
    idx_rules = prompt.find("RULES:")
    idx_input = prompt.find("Planner input:")
    idx_cmd = prompt.rfind("COMMAND:")

    assert idx_header != -1
    assert idx_docs != -1
    assert idx_rules != -1
    assert idx_input != -1
    assert idx_cmd != -1

    assert idx_header < idx_docs < idx_rules < idx_input < idx_cmd
    assert prompt.endswith("COMMAND:")


def test_context_assembler_prompt_ordering_multi_step():
    assembler = ContextAssembler()
    docs = [{"tool": "nmap", "content": "TOOL: nmap", "score": 0.4}]
    contract = {
        "intent": "VULNERABILITY_AUDIT",
        "target_value": "192.168.1.10",
        "ports": [80],
        "modifiers": [],
        "multi_step": True
    }
    prompt = assembler.assemble(docs, contract)

    idx_rules = prompt.find("RULES:")
    idx_input = prompt.find("Planner input:")
    idx_cmd_seq = prompt.rfind("COMMAND SEQUENCE:")

    assert idx_rules != -1
    assert idx_input != -1
    assert idx_cmd_seq != -1
    assert idx_rules < idx_input < idx_cmd_seq
    assert prompt.endswith("COMMAND SEQUENCE:")


def test_gobuster_dir_minimal_options_rule():
    assembler = ContextAssembler()
    docs = [{"tool": "gobuster", "content": "TOOL: gobuster", "score": 0.5}]
    contract = {
        "intent": "DIRECTORY_BRUTEFORCE",
        "target_value": "http://192.168.1.50",
        "ports": [80],
        "modifiers": ["-w common.txt"],
        "multi_step": False
    }
    prompt = assembler.assemble(docs, contract)

    assert "For DIRECTORY_BRUTEFORCE directory enumeration, you MUST use 'gobuster dir' mode with the '-u' flag." in prompt
    assert "Use the exact target URL and port from Planner input (http://192.168.1.50) with the '-u' flag." in prompt
    assert "Use the exact wordlist specified (common.txt) with the '-w' flag. Output exactly one '-w' flag." in prompt
    assert "Because no additional modifiers were requested, the command must contain ONLY 'gobuster dir -u http://192.168.1.50 -w common.txt' with NO additional flags or options" in prompt


def test_gobuster_dir_combined_modifiers_preserved():
    assembler = ContextAssembler()
    docs = []
    # Combined modifier string "-w common.txt -t 50"
    contract = {
        "intent": "DIRECTORY_BRUTEFORCE",
        "target_value": "http://192.168.1.50",
        "ports": [80],
        "modifiers": ["-w common.txt -t 50"],
        "multi_step": False
    }
    prompt = assembler.assemble(docs, contract)

    assert "Use the exact wordlist specified (common.txt) with the '-w' flag." in prompt
    assert "Include the requested modifiers (-t 50)." in prompt
    assert "Because no additional modifiers were requested" not in prompt


def test_gobuster_dir_aliased_wordlist_and_extra_flags():
    assembler = ContextAssembler()
    docs = []
    # Wordlist via --wordlist=common.txt with separate extra flag
    contract = {
        "intent": "DIRECTORY_BRUTEFORCE",
        "target_value": "http://10.0.0.15",
        "ports": [80],
        "modifiers": ["--wordlist=common.txt", "-x php,html"],
        "multi_step": False
    }
    prompt = assembler.assemble(docs, contract)

    assert "Use the exact wordlist specified (common.txt) with the '-w' flag." in prompt
    assert "Include the requested modifiers (-x php,html)." in prompt


def test_gobuster_quoted_values_with_spaces():
    assembler = ContextAssembler()
    docs = []
    # Wordlist with spaces and header with spaces
    contract = {
        "intent": "DIRECTORY_BRUTEFORCE",
        "target_value": "http://192.168.1.50",
        "ports": [80],
        "modifiers": ['-w "custom wordlist.txt"', '-H "Authorization: Bearer token123"'],
        "multi_step": False
    }
    prompt = assembler.assemble(docs, contract)

    # Wordlist quoting preserved
    assert "'custom wordlist.txt'" in prompt or '"custom wordlist.txt"' in prompt
    # Header quoting preserved via shlex.join
    assert "-H 'Authorization: Bearer token123'" in prompt or '-H "Authorization: Bearer token123"' in prompt


def test_gobuster_malformed_quotes_raises_value_error():
    assembler = ContextAssembler()
    contract = {
        "intent": "DIRECTORY_BRUTEFORCE",
        "target_value": "http://192.168.1.50",
        "ports": [80],
        "modifiers": ['-w "unclosed quote string'],
        "multi_step": False
    }
    with pytest.raises(ValueError, match="Malformed quoting in modifier"):
        assembler.assemble([], contract)


def test_gobuster_missing_wordlist_argument_raises_value_error():
    assembler = ContextAssembler()
    
    # Trailing -w with no value
    contract1 = {
        "intent": "DIRECTORY_BRUTEFORCE",
        "target_value": "http://192.168.1.50",
        "modifiers": ["-w"],
        "multi_step": False
    }
    with pytest.raises(ValueError, match="missing a wordlist argument"):
        assembler.assemble([], contract1)

    # -w immediately followed by another flag
    contract2 = {
        "intent": "DIRECTORY_BRUTEFORCE",
        "target_value": "http://192.168.1.50",
        "modifiers": ["-w -t 50"],
        "multi_step": False
    }
    with pytest.raises(ValueError, match="missing a wordlist argument"):
        assembler.assemble([], contract2)

    # Empty --wordlist= value
    contract3 = {
        "intent": "DIRECTORY_BRUTEFORCE",
        "target_value": "http://192.168.1.50",
        "modifiers": ["--wordlist="],
        "multi_step": False
    }
    with pytest.raises(ValueError, match="specifies an empty wordlist"):
        assembler.assemble([], contract3)


def test_boundary_invariance_other_tools():
    assembler = ContextAssembler()
    
    # Nmap scan
    contract_nmap = {
        "intent": "NETWORK_SCAN",
        "target_value": "192.168.1.1",
        "ports": [80, 443],
        "modifiers": ["stealth"],
        "primary_tool": "nmap",
        "multi_step": False
    }
    prompt_nmap = assembler.assemble([], contract_nmap)
    assert "gobuster dir" not in prompt_nmap
    assert "DIRECTORY_BRUTEFORCE" not in prompt_nmap
    assert "Replace placeholder IPs with the actual target." in prompt_nmap
    assert prompt_nmap.endswith("COMMAND:")

    # Nikto audit
    contract_nikto = {
        "intent": "VULNERABILITY_AUDIT",
        "target_value": "10.0.0.5",
        "ports": [8080],
        "primary_tool": "nikto",
        "multi_step": False
    }
    prompt_nikto = assembler.assemble([], contract_nikto)
    assert "gobuster dir" not in prompt_nikto
    assert "Replace placeholder IPs with the actual target." in prompt_nikto
    assert prompt_nikto.endswith("COMMAND:")


def test_boundary_invariance_gobuster_dns_mode():
    assembler = ContextAssembler()
    
    # Explicit mode="dns"
    contract_dns = {
        "intent": "DIRECTORY_BRUTEFORCE",
        "sub_intent": "dns_enumeration",
        "mode": "dns",
        "target_value": "example.com",
        "primary_tool": "gobuster",
        "modifiers": ["-d example.com", "-w subdomains.txt"],
        "multi_step": False
    }
    prompt_dns = assembler.assemble([], contract_dns)
    # Must NOT force gobuster dir
    assert "MUST use 'gobuster dir' mode" not in prompt_dns
    assert "Replace placeholder IPs with the actual target." in prompt_dns
    assert prompt_dns.endswith("COMMAND:")
