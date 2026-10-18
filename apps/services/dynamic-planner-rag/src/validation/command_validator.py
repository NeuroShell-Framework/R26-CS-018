import re
import shlex
from typing import Tuple, List, Optional, Any

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

    def __init__(self, ast_validator: Optional[Any] = None):
        if ast_validator is None:
            from scripts.cli_ast_validator import CLIASTValidator
            self.ast_validator = CLIASTValidator(command_validator=self)
        else:
            self.ast_validator = ast_validator

    def validate(
        self,
        command: str,
        expected_tool: str,
        target_value: Optional[str] = None,
        target_type: Optional[str] = None,
        expected_ports: Optional[List[int]] = None,
        requested_modifiers: Optional[List[str]] = None,
        expected_wordlist: Optional[str] = None
    ) -> Tuple[bool, List[str]]:
        issues = []
        command = (command or "").strip()

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

        try:
            tokens = shlex.split(command)
        except ValueError as e:
            issues.append(f"ERROR: malformed quotes or tokenization syntax error: {e}")
            return False, issues

        from scripts.cli_ast_validator import validate_port_syntax
        port_syntax_ok, port_err = validate_port_syntax(tokens, expected_tool)
        if not port_syntax_ok:
            issues.append(f"ERROR: {port_err}")
            return False, issues

        if target_value:
            t_type = target_type or "IP"
            gobuster_mode = tokens[1] if (expected_tool == "gobuster" and len(tokens) > 1) else None

            comparison_target = target_value
            if (
                expected_tool == "gobuster"
                and t_type == "URL"
                and "ssl" in (requested_modifiers or [])
                and "://" not in target_value
            ):
                comparison_target = "https://" + target_value

            target_ok = self.ast_validator._check_target_position(
                tokens, comparison_target, t_type, expected_tool, gobuster_mode
            )
            if not target_ok:
                issues.append(f"ERROR: target '{target_value}' (type: {t_type}) missing, misplaced, mismatched, or extra targets present")

        if expected_ports:
            ports_ok = self.ast_validator._check_ports_preservation(tokens, expected_ports, expected_tool, command)
            if not ports_ok:
                issues.append(f"ERROR: expected ports {expected_ports} missing or invalid in command")

        if (
            expected_tool == "nmap"
            and not expected_ports
            and any(m in ("fast", "quick") for m in (requested_modifiers or []))
            and "-F" not in tokens
        ):
            issues.append(
                "ERROR: requested fast/quick port selection requires -F"
            )

        if expected_tool == "gobuster" and tokens[1:2] == ["dir"]:
            def read_option(short, long):
                values = []
                for index, token in enumerate(tokens):
                    if token in (short, long):
                        value = tokens[index + 1] if index + 1 < len(tokens) else ""
                        values.append(value)
                    elif token.startswith(long + "="):
                        values.append(token.split("=", 1)[1])
                    elif token.startswith(short) and token != short:
                        values.append(token[len(short):].removeprefix("="))
                if len(values) > 1:
                    issues.append(f"ERROR: duplicate Gobuster option {short}")
                    return None
                if not values:
                    return None
                value = values[0]
                if not value or (value.startswith("-") and value != "-"):
                    issues.append(f"ERROR: Gobuster option {short} has no value")
                    return None
                return value

            wordlist = read_option("-w", "--wordlist")
            if wordlist is None:
                issues.append("ERROR: Gobuster dir requires a concrete wordlist")
            elif (
                re.search(r"<[^>]+>|\{[^}]+\}", wordlist)
                or wordlist.replace("\\\\", "/").lower().startswith("path/to/")
                or wordlist.replace("\\\\", "/").lower().startswith("/path/to/")
            ):
                issues.append("ERROR: Gobuster wordlist contains a placeholder")
            elif expected_wordlist is not None and wordlist != expected_wordlist:
                issues.append("ERROR: requested Gobuster wordlist was not preserved")

            extensions = read_option("-x", "--extensions")
            threads = read_option("-t", "--threads")
            for modifier in requested_modifiers or []:
                if modifier.startswith("extension:"):
                    expected = set(modifier.split(":", 1)[1].split(","))
                    actual = set(extensions.split(",")) if extensions else set()
                    if actual != expected:
                        issues.append("ERROR: requested Gobuster extensions were not preserved")
                elif modifier.startswith("threads:"):
                    expected = modifier.split(":", 1)[1]
                    if threads != expected:
                        issues.append("ERROR: requested Gobuster thread count was not preserved")

        if expected_tool == "nikto" and "ssl" in (requested_modifiers or []):
            host_arguments = [
                tokens[index + 1]
                for index, token in enumerate(tokens[:-1])
                if token in ("-h", "-host")
            ]
            has_https_target = bool(host_arguments) and all(
                host.lower().startswith("https://")
                for host in host_arguments
            )
            if "-nossl" in tokens or not (
                "-ssl" in tokens or has_https_target
            ):
                issues.append(
                    "ERROR: requested Nikto SSL requires -ssl or an HTTPS target"
                )

        if expected_tool == "nmap":
            requested = requested_modifiers or []
            if "aggressive" in requested:
                equivalent_features = all(
                    flag in tokens
                    for flag in ("-O", "-sV", "-sC", "--traceroute")
                )
                if "-A" not in tokens and not equivalent_features:
                    issues.append(
                        "ERROR: requested aggressive features require -A "
                        "or equivalent OS/version/default-script/traceroute options"
                    )

            if "all-ports" in requested:
                port_specs = []
                for index, token in enumerate(tokens):
                    if token == "-p" and index + 1 < len(tokens):
                        port_specs.append(tokens[index + 1])
                    elif token.startswith("-p") and token != "-p":
                        port_specs.append(token[2:])

                full_range = (
                    len(port_specs) == 1
                    and port_specs[0] in ("-", "1-65535")
                )
                restricted = any(
                    token == "-F" or token.startswith("--top-ports")
                    or token in ("-sn", "-sP")
                    for token in tokens
                )
                if not full_range or restricted:
                    issues.append(
                        "ERROR: requested all-ports requires the full "
                        "1-65535 port range without fast/top-port restrictions"
                    )

        if expected_tool == "nmap" and "ping" in (requested_modifiers or []):
            if not any(flag in tokens for flag in ("-sn", "-sP")):
                issues.append(
                    "ERROR: requested ping mode requires host discovery "
                    "with -sn or -sP"
                )

        if expected_tool == "gobuster":
            requested = requested_modifiers or []
            if "ssl" in requested:
                url_arguments = []
                for index, token in enumerate(tokens):
                    if token in ("-u", "--url") and index + 1 < len(tokens):
                        url_arguments.append(tokens[index + 1])
                    elif token.startswith("--url="):
                        url_arguments.append(token.split("=", 1)[1])
                if len(url_arguments) != 1 or not url_arguments[0].lower().startswith("https://"):
                    issues.append(
                        "ERROR: requested Gobuster SSL requires HTTPS in the target URL"
                    )
            if "silent" in requested and not any(
                flag in tokens for flag in ("-q", "--quiet")
            ):
                issues.append(
                    "ERROR: requested Gobuster silent mode requires -q or --quiet"
                )

        required = TOOL_REQUIRED_FLAGS.get(expected_tool, [])
        has_required = any(flag in command for flag in required)
        if required and not has_required:
            issues.append(f"WARNING: command missing expected flags for {expected_tool}")

        if not target_value:
            if not re.search(r"192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|127\.\d+\.\d+\.\d+|localhost", command):
                issues.append("WARNING: no private IP found in command")

        passed = not any(issue.startswith("ERROR") for issue in issues)
        return passed, issues


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