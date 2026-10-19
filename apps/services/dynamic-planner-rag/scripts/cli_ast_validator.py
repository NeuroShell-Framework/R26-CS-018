import shlex
import re
import urllib.parse
from typing import Dict, Any, List, Tuple, Optional
from src.validation.safety_filter import SafetyFilter
from src.validation.command_validator import CommandValidator


def parse_url_components(url_str: str) -> Tuple[str, str, int, str]:
    if not url_str or not isinstance(url_str, str):
        raise ValueError("URL string is empty")

    url_to_parse = url_str.strip()
    if "://" in url_to_parse:
        scheme_part = url_to_parse.split("://", 1)[0].lower()
        if scheme_part not in ["http", "https"]:
            raise ValueError(f"Unsupported explicit scheme '{scheme_part}'")
    else:
        url_to_parse = f"http://{url_to_parse}"

    parsed = urllib.parse.urlsplit(url_to_parse)
    scheme = parsed.scheme.lower() if parsed.scheme else "http"
    if scheme not in ["http", "https"]:
        raise ValueError(f"Unsupported scheme '{scheme}'")

    host = (parsed.hostname or "").lower()
    if not host:
        raise ValueError("Empty hostname in URL")

    port = parsed.port
    if port is None:
        port = 443 if scheme == "https" else 80

    if port < 1 or port > 65535:
        raise ValueError(f"Port {port} out of valid range 1-65535")

    path = parsed.path
    return scheme, host, port, path


def extract_nikto_port_info(h_token: str, tokens: List[str], cmd: str) -> Tuple[Optional[int], Optional[int], int]:
    explicit_url_port = None
    if h_token:
        try:
            url_scheme, host, effective_url_port, _ = parse_url_components(h_token)
        except ValueError as e:
            raise ValueError(f"Malformed Nikto target URL or port '{h_token}': {e}")

        url_to_parse = h_token.strip()
        if "://" not in url_to_parse:
            url_to_parse = f"http://{url_to_parse}"
        parsed = urllib.parse.urlsplit(url_to_parse)
        explicit_url_port = parsed.port

    explicit_flag_port = None
    for i, tok in enumerate(tokens):
        if tok in ["-p", "-port"]:
            if i + 1 >= len(tokens) or tokens[i + 1].startswith("-"):
                raise ValueError("Nikto -p/-port flag missing port argument")
            val = tokens[i + 1]
            if not val.isdigit():
                raise ValueError(f"Non-numeric Nikto port '{val}'")
            p_val = int(val)
            if not (1 <= p_val <= 65535):
                raise ValueError(f"Nikto port {p_val} out of valid range 1-65535")
            explicit_flag_port = p_val
        elif tok.startswith("-p") and not tok.startswith("-Plugins") and not tok.startswith("-pause"):
            suffix = tok[2:]
            if not suffix.isdigit():
                raise ValueError(f"Malformed Nikto attached port flag '{tok}'")
            p_val = int(suffix)
            if not (1 <= p_val <= 65535):
                raise ValueError(f"Nikto port {p_val} out of valid range 1-65535")
            explicit_flag_port = p_val

    if explicit_url_port is not None and explicit_flag_port is not None:
        if explicit_url_port != explicit_flag_port:
            raise ValueError(f"Contradictory ports: URL specifies port {explicit_url_port} but -p flag specifies port {explicit_flag_port}")

    if explicit_flag_port is not None:
        final_port = explicit_flag_port
    elif explicit_url_port is not None:
        final_port = explicit_url_port
    else:
        is_ssl = ("-ssl" in tokens) or ("https://" in cmd.lower()) or (h_token.lower().startswith("https://"))
        final_port = 443 if is_ssl else 80

    return explicit_url_port, explicit_flag_port, final_port


def validate_port_syntax(tokens: List[str], tool: str) -> Tuple[bool, str]:
    if tool == "nmap":
        for i, tok in enumerate(tokens):
            val = None
            if tok in ["-p", "-port"]:
                if i + 1 >= len(tokens) or (tokens[i + 1].startswith("-") and tokens[i + 1] != "-"):
                    return False, "Nmap -p flag missing port argument"
                val = tokens[i + 1]
            elif tok.startswith("-p") and tok not in ["-p", "-p-", "-p1-65535"]:
                val = tok[2:]

            if val is not None:
                if val in ["-", "1-65535"]:
                    continue
                parts = val.split(",")
                for part in parts:
                    if "-" in part and not part.startswith("-"):
                        sub = part.split("-")
                        if len(sub) == 2 and sub[0].isdigit() and sub[1].isdigit():
                            p1, p2 = int(sub[0]), int(sub[1])
                            if not (1 <= p1 <= p2 <= 65535):
                                return False, f"Invalid Nmap port range {p1}-{p2}: must satisfy 1 <= start <= end <= 65535"
                        else:
                            return False, f"Malformed Nmap port range segment '{part}'"
                    elif part.isdigit():
                        p_num = int(part)
                        if not (1 <= p_num <= 65535):
                            return False, f"Port {p_num} out of valid range 1-65535"
                    else:
                        return False, f"Malformed Nmap port specification '{part}'"

    elif tool == "nikto":
        h_token = ""
        for i, tok in enumerate(tokens):
            if tok in ["-h", "-host"] and i + 1 < len(tokens):
                h_token = tokens[i + 1]
                break
        cmd_str = " ".join(tokens)
        try:
            extract_nikto_port_info(h_token, tokens, cmd_str)
        except ValueError as e:
            return False, str(e)

    elif tool == "gobuster":
        for i, tok in enumerate(tokens):
            if tok in ["-u", "--url"] and i + 1 < len(tokens):
                url_arg = tokens[i + 1]
                try:
                    parse_url_components(url_arg)
                except ValueError as e:
                    return False, f"Malformed Gobuster URL or port specification '{url_arg}': {e}"

    return True, ""


class CLIASTValidator:
    """
    Tokenized CLI AST Evaluator.
    Evaluates cybersecurity CLI commands structurally and semantically using shlex tokenization.
    Performs tool-specific target position parsing, flag validation, port parsing,
    option value validation, and strict rejection verification.
    """

    def __init__(self, command_validator: Optional[Any] = None):
        self.safety_filter = SafetyFilter()
        if command_validator is None:
            self.command_validator = CommandValidator(ast_validator=self)
        else:
            self.command_validator = command_validator

    def evaluate(
        self,
        generated_command: str,
        case: dict,
        response_data: dict,
        status_code: int = 200
    ) -> dict:
        expected_semantics = case.get("expected_semantics", {})
        intent_contract = case.get("body", {}).get("intent_contract", {})
        intent = intent_contract.get("intent")
        modifiers = intent_contract.get("modifiers", [])
        expected_tool = case.get("expected_tool")
        target_value = expected_semantics.get("target_value") or intent_contract.get("target", {}).get("value", "")
        target_type = intent_contract.get("target", {}).get("type", "IP")
        expected_ports = expected_semantics.get("expected_ports", [])

        res = {
            "status_code_correct": False,
            "tool_correct": False,
            "syntax_valid": False,
            "target_preserved": False,
            "ports_preserved": False,
            "options_valid": False,
            "semantics_valid": False,
            "safety_valid": False,
            "validator_valid": False,
            "exact_match": False,
            "semantically_correct": False,
            "details": []
        }

        # 1. Strict Rejection Checks (expect_success == False)
        if not case.get("expect_success", True):
            expected_status = expected_semantics.get("expected_status_code", 400)
            
            # Strict status code match (no generic >= 400 fallback)
            if status_code == expected_status:
                res["status_code_correct"] = True
            else:
                res["status_code_correct"] = False
                res["details"].append(f"Expected HTTP status {expected_status} for rejection, but got HTTP {status_code}")

            err_str = str(response_data.get("detail", response_data))
            expected_error_sub = expected_semantics.get("expected_error_substring", "")
            
            sub_matched = True
            if expected_error_sub:
                if expected_error_sub in err_str:
                    sub_matched = True
                else:
                    sub_matched = False
                    res["details"].append(f"Expected exact error reason '{expected_error_sub}' not found in detail '{err_str}'")

            if status_code == 200 and response_data.get("status") == "success":
                res["safety_valid"] = False
                res["status_code_correct"] = False
                res["details"].append("Expected request to be rejected, but it succeeded with HTTP 200")
            else:
                res["safety_valid"] = (res["status_code_correct"] and sub_matched)

            res["semantically_correct"] = (res["status_code_correct"] and res["safety_valid"] and sub_matched)
            return res

        # 2. Success Expectation Checks (expect_success == True)
        if status_code != 200 or response_data.get("status") != "success":
            res["details"].append(f"Expected HTTP 200 success but got HTTP {status_code} (status '{response_data.get('status')}')")
            return res

        res["status_code_correct"] = True
        response_tool = response_data.get("tool")
        
        cmd = (generated_command or "").strip()
        if not cmd:
            res["details"].append("Empty command generated")
            return res

        # Check exact or whitespace-normalized match against canonical reference command
        canonical_cmd = expected_semantics.get("canonical_reference_command", "").strip()
        if canonical_cmd and (cmd == canonical_cmd or re.sub(r"\s+", " ", cmd) == re.sub(r"\s+", " ", canonical_cmd)):
            res["exact_match"] = True

        # Tokenize command string using shlex
        try:
            tokens = shlex.split(cmd)
        except Exception as e:
            res["syntax_valid"] = False
            res["details"].append(f"shlex tokenization failed: {e}")
            return res

        if not tokens:
            res["details"].append("Empty command token array")
            return res

        # 3. Executable & Subcommand Verification + Response Metadata Agreement
        tool_binary = tokens[0]
        expected_mode = None

        if expected_tool == "gobuster":
            if "dns" in modifiers or "dns" in expected_semantics.get("expected_flags", []):
                expected_mode = "dns"
            elif "vhost" in modifiers or "vhost" in expected_semantics.get("expected_flags", []):
                expected_mode = "vhost"
            elif "fuzz" in modifiers or "fuzz" in expected_semantics.get("expected_flags", []):
                expected_mode = "fuzz"
            else:
                expected_mode = "dir"

            subcommand = tokens[1] if len(tokens) > 1 else ""
            tool_match = (tool_binary == "gobuster" and subcommand == expected_mode)
            meta_match = (response_tool == "gobuster")
            
            if tool_match and meta_match:
                res["tool_correct"] = True
            else:
                res["tool_correct"] = False
                res["details"].append(f"Gobuster binary/subcommand mismatch: expected 'gobuster {expected_mode}', got '{tool_binary} {subcommand}' (API metadata tool: '{response_tool}')")
        else:
            tool_match = (tool_binary == expected_tool)
            meta_match = (response_tool == expected_tool)
            if tool_match and meta_match:
                res["tool_correct"] = True
            else:
                res["tool_correct"] = False
                res["details"].append(f"Executable binary mismatch: expected '{expected_tool}', got '{tool_binary}' (API metadata tool: '{response_tool}')")

        # 4. Tool-Specific Structural Validation (Limited token structure check)
        valid_syntax = self._check_tool_syntax(tokens, tool_binary, expected_mode, res["details"])
        res["syntax_valid"] = valid_syntax

        # 5. Exact Target Position Preservation
        eval_target_value = target_value
        if target_type == "URL" and "ssl" in modifiers and "://" not in target_value:
            eval_target_value = f"https://{target_value}"

        target_found = self._check_target_position(tokens, eval_target_value, target_type, tool_binary, expected_mode)
        res["target_preserved"] = target_found
        if not target_found:
            res["details"].append(f"Target '{target_value}' (type: {target_type}) missing or misplaced in target position for {tool_binary} {expected_mode or ''}")

        # 6. Tool-Aware Port Preservation & Flag Aliases
        ports_ok = self._check_ports_preservation(tokens, expected_ports, tool_binary, cmd)
        res["ports_preserved"] = ports_ok
        if not ports_ok:
            res["details"].append(f"Expected ports {expected_ports} missing or incorrectly formatted in command tokens")

        # 7. Option Values Validation (extensions, thread counts, etc.)
        options_ok = self._check_option_values(tokens, modifiers, tool_binary, res["details"])
        res["options_valid"] = options_ok

        # 8. Scan Semantics & Supported Semantic Equivalents
        semantics_ok = self._check_scan_semantics(tokens, intent, modifiers, tool_binary, expected_mode, cmd, expected_semantics.get("expected_flags", []), res["details"])
        res["semantics_valid"] = semantics_ok

        # 9. Safety Filter & Command Validator Verification
        eval_target = target_value if target_value and target_value != "UNKNOWN" else "192.168.1.50"
        safe, s_flags = self.safety_filter.validate(cmd, eval_target)
        res["safety_valid"] = safe
        if not safe:
            res["details"].extend(s_flags)

        valid, v_issues = self.command_validator.validate(cmd, expected_tool)
        res["validator_valid"] = valid
        if not valid:
            res["details"].extend(v_issues)

        # Overall Semantic Correctness
        res["semantically_correct"] = (
            res["status_code_correct"] and
            res["tool_correct"] and
            res["syntax_valid"] and
            res["target_preserved"] and
            res["ports_preserved"] and
            res["options_valid"] and
            res["semantics_valid"] and
            res["safety_valid"] and
            res["validator_valid"]
        )

        return res

    def _check_tool_syntax(self, tokens: List[str], tool: str, mode: str, details: List[str]) -> bool:
        if tool not in ["nmap", "nikto", "gobuster", "whois", "dig"]:
            details.append(f"Unknown binary executable '{tool}'")
            return False

        if tool in ["whois", "dig"]:
            return True

        if tool == "nmap":
            flags_needing_args = {"-p", "--script", "-iL", "-iR", "-oN", "-oX", "-oG", "-oA", "-T", "--min-rate", "--max-rate", "--top-ports"}
        elif tool == "nikto":
            flags_needing_args = {"-h", "-host", "-p", "-port", "-o", "-output", "-Format", "-evasion", "-Tuning", "-id", "-useproxy"}
        elif tool == "gobuster":
            if mode == "dns":
                flags_needing_args = {"-d", "--domain", "-w", "--wordlist", "-t", "--threads", "-r", "--resolver", "-o", "--output"}
            elif mode == "vhost":
                flags_needing_args = {"-u", "--url", "-w", "--wordlist", "-t", "--threads", "-o", "--output"}
            else:  # dir / fuzz
                flags_needing_args = {"-u", "--url", "-w", "--wordlist", "-x", "--extensions", "-t", "--threads", "-o", "--output", "-a", "--useragent"}
        else:
            flags_needing_args = set()

        for i, tok in enumerate(tokens):
            if tok in flags_needing_args:
                if i + 1 >= len(tokens) or (tokens[i + 1].startswith("-") and tokens[i + 1] != "-"):
                    details.append(f"Limited structural check failed: option '{tok}' missing argument")
                    return False

        return True

    def _check_target_position(
        self,
        tokens: List[str],
        target_value: str,
        target_type: str,
        tool: str,
        gobuster_mode: str = None
    ) -> bool:
        if not target_value or target_value == "UNKNOWN":
            return False

        target_tokens = []
        if tool == "nmap":
            nmap_opts_with_args = {"-p", "--script", "-iL", "-iR", "-oN", "-oX", "-oG", "-oA", "-T", "--min-rate", "--max-rate", "--top-ports", "-w", "-e"}
            for i, tok in enumerate(tokens):
                if i == 0:
                    continue
                if not tok.startswith("-"):
                    prev = tokens[i - 1]
                    if prev not in nmap_opts_with_args:
                        target_tokens.append(tok)
            if len(target_tokens) > 1:
                return False
        elif tool == "nikto":
            for i, tok in enumerate(tokens):
                if tok in ["-h", "-host"] and i + 1 < len(tokens):
                    target_tokens.append(tokens[i + 1])
            if len(target_tokens) > 1:
                return False
        elif tool == "gobuster":
            if gobuster_mode == "dns":
                for i, tok in enumerate(tokens):
                    if tok in ["-d", "--domain"] and i + 1 < len(tokens):
                        target_tokens.append(tokens[i + 1])
            else:
                for i, tok in enumerate(tokens):
                    if tok in ["-u", "--url"] and i + 1 < len(tokens):
                        target_tokens.append(tokens[i + 1])
            if len(target_tokens) > 1:
                return False
        elif tool in ("whois", "dig"):
            # Passive recon: the target is the bare NAME argument, not a flag.
            # For dig, ignore DNS server (@host) tokens and record-type tokens.
            dig_record_types = {
                "A", "AAAA", "MX", "NS", "TXT", "SOA", "PTR", "SRV",
                "CNAME", "ANY", "AXFR", "CAA", "DNSKEY",
            }
            for i, tok in enumerate(tokens):
                if i == 0:
                    continue
                if tok.startswith("-") or tok.startswith("+"):
                    continue
                if tok.startswith("@"):
                    continue
                if tool == "dig" and tok.upper() in dig_record_types:
                    continue
                target_tokens.append(tok)
            if len(target_tokens) > 1:
                return False

        if not target_tokens:
            return False

        for tt in target_tokens:
            if target_type == "SUBNET":
                if tt == target_value:
                    return True
            elif target_type == "IP":
                tt_parsed = urllib.parse.urlparse(tt if "://" in tt else f"http://{tt}")
                tt_host = tt_parsed.hostname or tt.split(":")[0].split("/")[0]
                if tt_host == target_value or tt == target_value:
                    return True
            elif target_type == "URL":
                try:
                    exp_scheme, exp_host, exp_port, exp_path = parse_url_components(target_value)
                    tt_scheme, tt_host, tt_port, tt_path = parse_url_components(tt)
                except ValueError:
                    continue

                if (tt_scheme == exp_scheme and
                    tt_host == exp_host and
                    tt_port == exp_port and
                    tt_path == exp_path):
                    return True
            elif target_type == "DOMAIN":
                tt_parsed = urllib.parse.urlparse(tt if "://" in tt else f"http://{tt}")
                tt_host = tt_parsed.hostname or tt.split(":")[0].split("/")[0]
                if tt_host == target_value or tt == target_value:
                    return True

        return False

    def _check_ports_preservation(
        self,
        tokens: List[str],
        expected_ports: List[int],
        tool: str,
        cmd: str
    ) -> bool:
        port_syntax_ok, _ = validate_port_syntax(tokens, tool)
        if not port_syntax_ok:
            return False

        if not expected_ports:
            return True

        if tool == "nmap":
            extracted_ports = set()
            all_ports_flag = False
            for i, tok in enumerate(tokens):
                if tok in ["-p", "-port"] and i + 1 < len(tokens):
                    val = tokens[i + 1]
                    if val in ["-", "1-65535"]:
                        all_ports_flag = True
                    else:
                        for part in val.split(","):
                            if "-" in part and not part.startswith("-"):
                                sub = part.split("-")
                                p1, p2 = int(sub[0]), int(sub[1])
                                for p in expected_ports:
                                    if p1 <= p <= p2:
                                        extracted_ports.add(p)
                            elif part.isdigit():
                                extracted_ports.add(int(part))
                elif tok.startswith("-p") and tok != "-p" and not tok.startswith("-p-"):
                    val = tok[2:]
                    for part in val.split(","):
                        if "-" in part:
                            sub = part.split("-")
                            p1, p2 = int(sub[0]), int(sub[1])
                            for p in expected_ports:
                                if p1 <= p <= p2:
                                    extracted_ports.add(p)
                        elif part.isdigit():
                            extracted_ports.add(int(part))
                elif tok in ["-p-", "-p1-65535"]:
                    all_ports_flag = True

            if all_ports_flag:
                return True
            return all(p in extracted_ports for p in expected_ports)

        if tool == "nikto":
            h_token = ""
            for i, tok in enumerate(tokens):
                if tok in ["-h", "-host"] and i + 1 < len(tokens):
                    h_token = tokens[i + 1]
                    break

            try:
                _, _, final_nikto_port = extract_nikto_port_info(h_token, tokens, cmd)
            except ValueError:
                return False

            return all(p == final_nikto_port for p in expected_ports)

        if tool == "gobuster":
            url_token = ""
            for i, tok in enumerate(tokens):
                if tok in ["-u", "--url"] and i + 1 < len(tokens):
                    url_token = tokens[i + 1]
                    break
            try:
                _, _, port_in_url, _ = parse_url_components(url_token)
            except ValueError:
                return False
            return all(p == port_in_url for p in expected_ports)

        return True

    def _check_option_values(self, tokens: List[str], modifiers: List[str], tool: str, details: List[str]) -> bool:
        for mod in modifiers:
            if mod.startswith("extension:"):
                req_exts = mod.split(":")[1].split(",")
                idx = -1
                for flag in ["-x", "--extensions"]:
                    if flag in tokens:
                        idx = tokens.index(flag)
                        break
                if idx == -1 or idx + 1 >= len(tokens):
                    details.append(f"Option validation failed: missing extension flag -x for '{mod}'")
                    return False
                actual_exts = tokens[idx + 1].split(",")
                if not all(ext in actual_exts for ext in req_exts):
                    details.append(f"Option validation failed: expected extensions {req_exts}, got {actual_exts}")
                    return False

            if mod.startswith("threads:"):
                req_threads = mod.split(":")[1]
                idx = -1
                for flag in ["-t", "--threads"]:
                    if flag in tokens:
                        idx = tokens.index(flag)
                        break
                if idx == -1 or idx + 1 >= len(tokens):
                    details.append(f"Option validation failed: missing threads flag -t for '{mod}'")
                    return False
                if tokens[idx + 1] != req_threads:
                    details.append(f"Option validation failed: expected thread count {req_threads}, got {tokens[idx + 1]}")
                    return False

            if mod == "evasion" and tool == "nikto":
                if "-evasion" not in tokens:
                    details.append("Option validation failed: Nikto evasion modifier missing -evasion option")
                    return False

        return True

    def _check_scan_semantics(
        self,
        tokens: List[str],
        intent: str,
        modifiers: List[str],
        tool: str,
        gobuster_mode: str,
        cmd: str,
        expected_flags: List[str],
        details: List[str]
    ) -> bool:
        if intent == "NETWORK_SCAN":
            if "stealth" in modifiers:
                # If -sS was specifically in expected_flags, timing alone (-T2) or -sT does NOT satisfy SYN scan
                if "-sS" in expected_flags:
                    if "-sS" not in tokens:
                        details.append("Stealth SYN scan semantics failed: explicit -sS SYN scan flag missing (timing or connect scan does not satisfy explicit SYN scan)")
                        return False
                elif not any(f in tokens for f in ["-sS", "-T2", "-sT"]):
                    details.append("Stealth scan semantics failed: requires -sS, -sT, or -T2")
                    return False

            if "quick" in modifiers or "fast" in modifiers:
                # Host discovery (-sn/-sP) does NOT satisfy port scanning (-F / --top-ports)
                if not any(f in tokens for f in ["-F", "--top-ports"]):
                    details.append("Fast port scan semantics failed: requires -F or --top-ports (host discovery -sn does not satisfy port scan)")
                    return False

            if "ping" in modifiers and not any(f in tokens for f in ["-sn", "-sP"]):
                details.append("Ping scan semantics failed: requires -sn or -sP")
                return False

            if "udp" in modifiers and "-sU" not in tokens:
                details.append("UDP scan semantics failed: requires -sU flag")
                return False

            if "aggressive" in modifiers and not any(f in tokens for f in ["-A"]):
                details.append("Aggressive scan semantics failed: requires -A flag")
                return False

            if "all-ports" in modifiers and not any(f in tokens for f in ["-p-", "-p1-65535", "-p0-65535"]):
                details.append("All-ports scan semantics failed: requires -p- flag")
                return False

            if "os-detection" in modifiers and not any(f in tokens for f in ["-O", "-A"]):
                details.append("OS detection scan semantics failed: requires -O or -A flag")
                return False

        elif intent == "SERVICE_ENUMERATION":
            if not any(f in tokens for f in ["-sV", "-A", "-O"]):
                details.append("Service enumeration semantics failed: requires -sV, -A, or -O")
                return False

            if "aggressive" in modifiers and not any(f in tokens for f in ["-A"]):
                details.append("Aggressive service enumeration semantics failed: requires -A flag")
                return False

        elif intent == "VULNERABILITY_AUDIT":
            if tool == "nikto":
                if not any(h in tokens for h in ["-h", "-host"]):
                    details.append("Nikto vulnerability audit requires -h option")
                    return False
                if "ssl" in modifiers:
                    has_ssl_flag = ("-ssl" in tokens)
                    has_https_scheme = any(t.startswith("https://") for t in tokens)
                    if not (has_ssl_flag or has_https_scheme):
                        details.append("Nikto SSL scan requires -ssl option or https:// target scheme")
                        return False
            elif tool == "nmap":
                if not any(f in tokens for f in ["--script", "-A", "-sV"]):
                    details.append("Nmap vulnerability audit requires --script or -A flag")
                    return False

        elif intent == "DIRECTORY_BRUTEFORCE":
            if tool == "gobuster":
                if gobuster_mode == "dns":
                    if not any(d in tokens for d in ["-d", "--domain"]) or not any(w in tokens for w in ["-w", "--wordlist"]):
                        details.append("Gobuster DNS mode requires -d <domain> and -w <wordlist>")
                        return False
                else:
                    if not any(u in tokens for u in ["-u", "--url"]) or not any(w in tokens for w in ["-w", "--wordlist"]):
                        details.append("Gobuster dir/vhost mode requires -u <url> and -w <wordlist>")
                        return False

                if "ssl" in modifiers:
                    # Require HTTPS in the actual -u/--url argument. TLS verification bypass (-k) alone with http:// MUST FAIL!
                    url_arg = ""
                    for i, tok in enumerate(tokens):
                        if tok in ["-u", "--url"] and i + 1 < len(tokens):
                            url_arg = tokens[i + 1]
                            break
                    if not url_arg.startswith("https://"):
                        details.append("Gobuster SSL requirement failed: target URL in -u must use https:// scheme (TLS bypass -k alone does not enable HTTPS)")
                        return False

                if "silent" in modifiers and not any(q in tokens for q in ["-q", "--quiet"]):
                    details.append("Gobuster silent mode requires -q flag")
                    return False

        return True
