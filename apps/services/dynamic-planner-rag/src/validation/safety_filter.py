import re
from typing import Tuple, List
from urllib.parse import urlparse

BLOCKED_PATTERNS = [
    r"rm\s+-rf",
    r"mkfs",
    r"dd\s+if=",
    r":\(\)\{:\|:&\};:",
    r"chmod\s+777\s+/",
    r"> /dev/sd",
    r"wget.+\|\s*bash",
    r"curl.+\|\s*bash",
    r"nc\s+-e\s+/bin",
    r"bash\s+-i\s+>&",
]

ALLOWED_TARGETS = [
    r"^192\.168\.",
    r"^10\.",
    r"^172\.(1[6-9]|2[0-9]|3[01])\.",
    r"^127\.",
    r"localhost",
]

ALLOWED_TOOLS = [
    "nmap", "nikto", "gobuster",
    "hydra", "metasploit", "whois",
    "dig", "curl", "wget"
]

class SafetyFilter:

    def validate(self, command: str, target: str) -> Tuple[bool, List[str]]:
        flags = []

        for pattern in BLOCKED_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                flags.append(f"BLOCKED: dangerous pattern detected: {pattern}")
                return False, flags

        if not self._is_allowed_target(target):
            flags.append(f"BLOCKED: target {target} is not RFC-1918 private range")
            return False, flags

        tool = command.split()[0] if command else ""
        if tool not in ALLOWED_TOOLS:
            flags.append(f"WARNING: tool '{tool}' not in approved list")

        return True, flags

    def _is_allowed_target(self, target: str) -> bool:
        normalized = self._normalize_target(target)
        for pattern in ALLOWED_TARGETS:
            if re.search(pattern, normalized):
                return True
        return False

    @staticmethod
    def _normalize_target(target: str) -> str:
        parsed = urlparse(target.strip())
        return parsed.hostname or parsed.path or target.strip()


if __name__ == "__main__":
    sf = SafetyFilter()

    tests = [
        ("nmap -sS 192.168.1.1", "192.168.1.1"),
        ("rm -rf /", "192.168.1.1"),
        ("nmap -sS 8.8.8.8", "8.8.8.8"),
        ("nikto -h 10.0.0.1", "10.0.0.1"),
    ]

    for cmd, target in tests:
        passed, flags = sf.validate(cmd, target)
        print(f"\nCommand: {cmd}")
        print(f"Target:  {target}")
        print(f"Passed:  {passed}")
        print(f"Flags:   {flags}")