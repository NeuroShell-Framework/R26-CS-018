import copy
import json

import pytest

from src.rag.context_assembler import ContextAssembler


@pytest.mark.parametrize("target", [
    "192.168.0.0/24",
    "10.20.30.0/24",
    "172.16.5.25",
])
def test_nmap_masks_documentation_without_changing_input(target):
    docs = [{
        "tool": "nmap",
        "content": (
            "nmap -sS -T4 192.168.1.1 "
            "nmap -sn 192.168.1.0/24 "
            "-p 80,443 --top-ports 1000"
        ),
    }]
    contract = {
        "intent": "NETWORK_SCAN",
        "target": {
            "type": "SUBNET" if "/" in target else "IP",
            "value": target,
        },
        "tool_hint": "nmap",
        "ports": [],
        "modifiers": ["stealth"],
    }
    original_docs = copy.deepcopy(docs)
    original_contract = copy.deepcopy(contract)

    prompt = ContextAssembler().assemble(docs, contract)
    context, planner = prompt.split("Planner input:\n", 1)
    planner_json = planner.split("\n\nCOMMAND:", 1)[0]

    assert "192.168.1.1" not in context
    assert "192.168.1.0/24" not in context
    assert context.count("<EXAMPLE_TARGET>") == 2
    assert "-p 80,443 --top-ports 1000" in context
    assert json.loads(planner_json)["target"]["value"] == target
    assert docs == original_docs
    assert contract == original_contract


def test_other_tool_documentation_is_unchanged():
    content = "nikto -h http://192.168.1.1:8080"
    prompt = ContextAssembler().assemble(
        [{"tool": "nikto", "content": content}],
        {
            "intent": "VULNERABILITY_AUDIT",
            "target_value": "10.20.30.40",
            "target_type": "IP",
            "tool_hint": "nikto",
        },
    )
    assert content in prompt
    assert "<EXAMPLE_TARGET>" not in prompt
