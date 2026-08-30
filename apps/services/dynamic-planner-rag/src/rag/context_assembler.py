from typing import List, Dict

class ContextAssembler:

    def assemble(self, retrieved_docs: List[Dict], intent_contract: dict) -> str:

        tool_sections = {}
        for doc in retrieved_docs:
            tool = doc['tool']
            if tool not in tool_sections:
                tool_sections[tool] = []
            tool_sections[tool].append(doc['content'])

        context_parts = []
        for tool, contents in tool_sections.items():
            context_parts.append(f"=== {tool.upper()} DOCUMENTATION ===")
            for content in contents:
                context_parts.append(content)

        context = "\n\n".join(context_parts)

        # Extract suggested_command if present
        suggested_cmd = intent_contract.get("suggested_command")
        if not suggested_cmd and isinstance(intent_contract.get("tool_parameters"), dict):
            suggested_cmd = intent_contract.get("tool_parameters", {}).get("suggested_command")
        elif not suggested_cmd and hasattr(intent_contract.get("tool_parameters"), "suggested_command"):
            suggested_cmd = getattr(intent_contract.get("tool_parameters"), "suggested_command")

        suggested_block = ""
        if suggested_cmd:
            suggested_block = (
                f"SUGGESTED COMMAND REFERENCE:\n{suggested_cmd}\n"
                f"(Note: Use this reference as a guideline, but ensure output targets the specified target and uses documented syntax.)\n\n"
            )

        multi_step = bool(intent_contract.get("multi_step", False))

        if multi_step:
            rules_block = """RULES:
1. Output an ordered sequence of valid bash commands (one command per line) required for this multi-step plan.
2. Use ONLY flags and options shown in the documentation above.
3. Replace placeholder IPs with the actual target.
4. Output ONLY the bash commands — no markdown code fences, no explanations."""
            cmd_header = "COMMAND SEQUENCE:"
            role_desc = "generate an ordered sequence of syntactically correct bash commands"
        else:
            rules_block = """RULES:
1. Output ONLY the bash command - no explanation, no markdown, no backticks
2. Use ONLY flags and options shown in the documentation above
3. Replace placeholder IPs with the actual target
4. If ports are specified, include them in the command"""
            cmd_header = "COMMAND:"
            role_desc = "generate ONE syntactically correct bash command"

        prompt = f"""You are a Kali Linux penetration testing command expert.
Your job is to {role_desc} based on the intent and documentation below.

INTENT: {intent_contract.get('intent')}
TARGET: {intent_contract.get('target_value') or intent_contract.get('target', {}).get('value', 'unknown')}
PORTS: {intent_contract.get('ports', [])}
MODIFIERS: {intent_contract.get('modifiers', [])}
{suggested_block}TOOL DOCUMENTATION:
{context}

{rules_block}

{cmd_header}"""

        return prompt


if __name__ == "__main__":
    assembler = ContextAssembler()

    docs = [{"tool": "nmap", "content": "TOOL: nmap\n-sS SYN stealth scan\n-T4 Aggressive timing", "score": 0.3}]
    intent = {"intent": "NETWORK_SCAN", "target": {"value": "192.168.1.1"}, "ports": [80, 443], "modifiers": ["stealth"]}

    prompt = assembler.assemble(docs, intent)
    print(prompt)