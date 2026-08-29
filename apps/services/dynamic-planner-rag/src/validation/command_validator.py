import re
from typing import Tuple, List

TOOL_REQUIRED_FLAGS = {
    "nmap"    : ["-s", "-p", "--top-ports", "-A", "-sn"],
    "nikto"   : ["-h"],
    "gobuster": ["-u", "-w"],
}

TOOL_PATTERNS = {
    "nmap"    : r"^nmap\s+",
    "nikto"   : r"^nikto\s+",
    "gobuster": r"^gobuster\s+(dir|dns|vhost|fuzz)\s+",
}

class CommandValidator:

    def validate(self, command: str, expected_tool: str) -> Tuple[bool, List[str]]:
        issues = []
        command = command.strip()

        if not command:
            issues.append("ERROR: empty command")
            return False, issues

        if "\n" in command:
            issues.append("ERROR: multi-line command not allowed")
            return False, issues

        pattern = TOOL_PATTERNS.get(expected_tool)
        if pattern and not re.match(pattern, command, re.IGNORECASE):
            issues.append(f"ERROR: command does not start with expected tool '{expected_tool}'")
            return False, issues

        required = TOOL_REQUIRED_FLAGS.get(expected_tool, [])
        has_required = any(flag in command for flag in required)
        if required and not has_required:
            issues.append(f"WARNING: command missing expected flags for {expected_tool}")

        if re.search(r"192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+", command):
            pass
        else:
            issues.append("WARNING: no private IP found in command")

        return True, issues


if __name__ == "__main__":
    cv = CommandValidator()

    tests = [
        ("nmap -sS 192.168.1.1", "nmap"),
        ("nikto -h 192.168.1.1", "nikto"),
        ("gobuster dir -u http://192.168.1.1 -w common.txt", "gobuster"),
        ("", "nmap"),
        ("ls -la", "nmap"),
    ]

    for cmd, tool in tests:
        passed, issues = cv.validate(cmd, tool)
        print(f"\nCommand: {cmd}")
        print(f"Tool:    {tool}")
        print(f"Passed:  {passed}")
        print(f"Issues:  {issues}")