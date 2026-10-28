import re
import json
import ipaddress
from typing import List, Dict


class ContextAssembler:

    def assemble(self, retrieved_docs: List[Dict], intent_contract: dict) -> str:
        target_val = (
            intent_contract.get("target_value")
            or intent_contract.get("target", {}).get("value", "")
        )
        target_type = (
            intent_contract.get("target_type")
            or intent_contract.get("target", {}).get("type", "UNKNOWN")
        )
        if not target_type or target_type == "UNKNOWN":
            if target_val.startswith("http://") or target_val.startswith("https://"):
                target_type = "URL"
            else:
                try:
                    ipaddress.ip_interface(target_val)
                    target_type = "SUBNET" if "/" in target_val else "IP"
                except ValueError:
                    target_type = "DOMAIN" if target_val else "UNKNOWN"

        sub_intent = intent_contract.get("sub_intent")
        if not sub_intent:
            intent = intent_contract.get("intent", "")
            ports = intent_contract.get("ports", [])
            if intent == "NETWORK_SCAN":
                sub_intent = "specific_ports_scan" if ports else "port_scan"
            elif intent == "VULNERABILITY_AUDIT":
                sub_intent = "vulnerability_scan"
            elif intent == "DIRECTORY_BRUTEFORCE":
                sub_intent = "directory_enumeration"
            elif intent == "SERVICE_ENUMERATION":
                sub_intent = "service_version_detection"
            else:
                sub_intent = "general"

        planner_input = {
            "intent": intent_contract.get("intent", ""),
            "sub_intent": sub_intent,
            "target": {
                "type": target_type,
                "value": target_val,
            },
            "ports": intent_contract.get("ports", []),
            "modifiers": intent_contract.get("modifiers", []),
            "tool_hint": intent_contract.get("tool_hint") or "nmap",
        }

        json_payload = json.dumps(planner_input, ensure_ascii=False, sort_keys=True)

        header = (
            "You are NeuroShell Component 2, a Dynamic Planner for authorized cybersecurity tasks.\n"
            "Generate exactly one valid shell command using the requested tool.\n"
            "Return only the command. Do not explain it."
        )

        doc_blocks = []
        if retrieved_docs:
            tool_sections = {}
            for doc in retrieved_docs:
                tool = doc.get("tool", "unknown")
                if tool not in tool_sections:
                    tool_sections[tool] = []
                content = doc.get("content", "")
                if str(tool).lower() == "nmap":
                    # Mask documentation examples, never the requested input.
                    content = re.sub(
                        r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\w.])",
                        "<EXAMPLE_TARGET>",
                        content,
                    )
                tool_sections[tool].append(content)

            context_parts = []
            for tool, contents in tool_sections.items():
                context_parts.append(f"=== {tool.upper()} DOCUMENTATION ===")
                for content in contents:
                    context_parts.append(content)
            doc_blocks.append("TOOL DOCUMENTATION:\n" + "\n\n".join(context_parts))

        suggested_cmd = intent_contract.get("suggested_command")
        if not suggested_cmd and isinstance(intent_contract.get("tool_parameters"), dict):
            suggested_cmd = intent_contract.get("tool_parameters", {}).get("suggested_command")

        if suggested_cmd:
            doc_blocks.append(
                f"SUGGESTED COMMAND REFERENCE:\n{suggested_cmd}\n"
                f"(Note: Use this reference as a guideline, but ensure output targets the specified target and uses documented syntax.)"
            )

        multi_step = bool(intent_contract.get("multi_step", False))
        if multi_step:
            rules = [
                "RULES:",
                "1. Output an ordered sequence of valid bash commands (one command per line) required for this multi-step plan.",
                "2. Use ONLY flags and options shown in the documentation above.",
                "3. Replace placeholder IPs with the actual target.",
                "4. Output ONLY the bash commands — no markdown code fences, no explanations."
            ]
            completion_header = "COMMAND SEQUENCE:"
        else:
            import shlex

            # Resolve primary/hinted tool
            tool_hint = (intent_contract.get("tool_hint") or intent_contract.get("primary_tool") or "").lower()
            intent_name = intent_contract.get("intent", "")
            if not tool_hint:
                if intent_name == "DIRECTORY_BRUTEFORCE":
                    tool_hint = "gobuster"
                elif intent_name in ["NETWORK_SCAN", "SERVICE_ENUMERATION"]:
                    tool_hint = "nmap"
                elif intent_name == "VULNERABILITY_AUDIT":
                    tool_hint = "nikto"

            # Check explicit mode fields
            explicit_mode = (
                intent_contract.get("mode")
                or (intent_contract.get("tool_parameters", {}).get("mode") if isinstance(intent_contract.get("tool_parameters"), dict) else None)
                or getattr(intent_contract.get("tool_parameters"), "mode", None)
            )

            sub_intent_str = str(sub_intent or "").lower()
            if explicit_mode:
                gobuster_mode = str(explicit_mode).lower()
            elif "dns" in sub_intent_str or "subdomain" in sub_intent_str:
                gobuster_mode = "dns"
            elif "vhost" in sub_intent_str or "virtual_host" in sub_intent_str:
                gobuster_mode = "vhost"
            elif "fuzz" in sub_intent_str:
                gobuster_mode = "fuzz"
            elif sub_intent_str in ["directory_enumeration", "wordlist_scan", "dir", "directory_bruteforce"] or intent_name == "DIRECTORY_BRUTEFORCE":
                gobuster_mode = "dir"
            else:
                gobuster_mode = "dir"

            is_gobuster_dir = (
                tool_hint == "gobuster"
                and gobuster_mode == "dir"
                and (intent_name == "DIRECTORY_BRUTEFORCE" or sub_intent_str in ["directory_enumeration", "wordlist_scan", "dir"])
            )

            modifiers = intent_contract.get("modifiers", [])

            if is_gobuster_dir:
                discovered_wordlist = intent_contract.get("wordlist")
                if not discovered_wordlist and isinstance(intent_contract.get("tool_parameters"), dict):
                    discovered_wordlist = intent_contract.get("tool_parameters", {}).get("wordlist")

                extra_modifiers = []
                for mod in modifiers:
                    if not mod or not str(mod).strip():
                        continue
                    try:
                        tokens = shlex.split(str(mod).strip())
                    except ValueError as ve:
                        raise ValueError(f"Malformed quoting in modifier '{mod}': {ve}") from ve

                    current_extra = []
                    i = 0
                    while i < len(tokens):
                        tok = tokens[i]
                        if tok in ["-w", "--wordlist"]:
                            if i + 1 >= len(tokens) or (tokens[i + 1].startswith("-") and tokens[i + 1] != "-"):
                                raise ValueError(f"Option '{tok}' in modifier is missing a wordlist argument")
                            val = tokens[i + 1].strip()
                            if not val:
                                raise ValueError(f"Option '{tok}' in modifier specifies an empty wordlist")
                            if not discovered_wordlist:
                                discovered_wordlist = val
                            i += 2
                            continue
                        elif tok.startswith("-w=") or tok.startswith("--wordlist="):
                            flag_name = tok.split("=", 1)[0]
                            val = tok.split("=", 1)[1].strip()
                            if not val:
                                raise ValueError(f"Option '{flag_name}' in modifier specifies an empty wordlist")
                            if not discovered_wordlist:
                                discovered_wordlist = val
                            i += 1
                            continue
                        else:
                            current_extra.append(tok)
                            i += 1

                    if current_extra:
                        if hasattr(shlex, "join"):
                            extra_modifiers.append(shlex.join(current_extra))
                        else:
                            extra_modifiers.append(" ".join(shlex.quote(t) for t in current_extra))

                rules = [
                    "RULES:",
                    "1. Output ONLY the executable command — no markdown code fences, no explanations.",
                    "2. For DIRECTORY_BRUTEFORCE directory enumeration, you MUST use 'gobuster dir' mode with the '-u' flag.",
                ]
                if target_val:
                    rules.append(
                        f"3. Use the exact target URL and port from Planner input ({target_val}) with the '-u' flag. Replace any example or placeholder IPs or URLs with this exact target."
                    )
                else:
                    rules.append("3. Replace placeholder IPs or URLs with the actual target from Planner input.")

                if discovered_wordlist:
                    rendered_wl = shlex.quote(discovered_wordlist) if " " in discovered_wordlist else discovered_wordlist
                    rules.append(
                        f"4. Use the exact wordlist specified ({rendered_wl}) with the '-w' flag. Output exactly one '-w' flag."
                    )

                if not extra_modifiers:
                    rendered_wl = shlex.quote(discovered_wordlist) if (discovered_wordlist and " " in discovered_wordlist) else (discovered_wordlist or '<wordlist>')
                    rules.append(
                        f"5. Because no additional modifiers were requested, the command must contain ONLY 'gobuster dir -u {target_val or '<target>'} -w {rendered_wl}' with NO additional flags or options (do NOT include -k, -m, -x, -t, or any other option)."
                    )
                else:
                    mod_str = " ".join(extra_modifiers)
                    rules.append(
                        f"5. Include the requested modifiers ({mod_str}). Do NOT add any unrequested flags or options from the documentation examples."
                    )
            else:
                rules = [
                    "RULES:",
                    "1. Output ONLY the executable command — no markdown code fences, no explanations.",
                    "2. Use ONLY flags and options shown in the documentation above.",
                    "3. Replace placeholder IPs with the actual target."
                ]

            completion_header = "COMMAND:"

        # Preserve the requested Nmap target explicitly.
        resolved_tool = (
            intent_contract.get("tool_hint")
            or intent_contract.get("primary_tool")
            or planner_input.get("tool_hint", "")
        ).lower()
        if resolved_tool == "nmap" and target_val:
            rules.extend([
                (
                    f"TARGET REQUIREMENT: Use exactly {target_val} as the "
                    "Nmap target argument. Preserve every IP octet and the "
                    "complete CIDR prefix when present."
                ),
                (
                    "Documentation commands are syntax examples only. "
                    "Replace their example targets with the requested target. "
                    "Do not copy example IPs, shorten a subnet to one host, "
                    "or add other targets."
                ),
            ])

        if (
            resolved_tool == "nmap"
            and intent_contract.get("intent") == "NETWORK_SCAN"
            and not multi_step
            and not intent_contract.get("ports")
            and any(
                m in ("fast", "quick")
                for m in intent_contract.get("modifiers", [])
            )
        ):
            rules.append(
                "FAST PORT SELECTION REQUIREMENT: The requested fast/quick "
                "modifier means Nmap fast port selection. Include -F to scan "
                "the top 100 ports. A timing flag such as -T4 alone does not "
                "satisfy this requirement. Preserve the requested target."
            )

        if resolved_tool == "gobuster" and not multi_step:
            option_rules = []
            for modifier in intent_contract.get("modifiers", []):
                if modifier.startswith("extension:"):
                    value = modifier.split(":", 1)[1]
                    option_rules.append(
                        f"Use -x {value} for the requested extensions. "
                        "Do not output literal extension: notation."
                    )
                elif modifier.startswith("threads:"):
                    value = modifier.split(":", 1)[1]
                    option_rules.append(
                        f"Use -t {value} for the requested thread count. "
                        "Do not output literal threads: notation."
                    )
            if option_rules:
                rules.append(
                    "GOBUSTER OPTION REQUIREMENTS:\n"
                    + "\n".join(option_rules)
                )

        if (
            resolved_tool == "nikto"
            and "ssl" in intent_contract.get("modifiers", [])
        ):
            rules.append(
                "NIKTO SSL REQUIREMENT: The requested ssl modifier requires "
                "SSL/TLS on the requested target port. Nikto documentation "
                "defines -ssl as forcing SSL/TLS encryption. Include -ssl "
                "in every Nikto command, or use an https:// target in -h. "
                "A port number alone does not satisfy SSL. Do not use -nossl. "
                "Preserve the requested host and port."
            )

        if resolved_tool == "nmap" and not multi_step:
            feature_rules = []
            requested = intent_contract.get("modifiers", [])
            if "aggressive" in requested:
                feature_rules.append(
                    "The aggressive modifier requires -A, enabling OS "
                    "detection, version detection, default scripts and "
                    "traceroute. Timing -T4 alone does not satisfy it."
                )
            if "all-ports" in requested:
                feature_rules.append(
                    "The all-ports modifier requires -p- to cover ports "
                    "1 through 65535. Do not substitute -F or --top-ports."
                )
            if feature_rules:
                rules.append(
                    "NMAP FEATURE REQUIREMENTS: " + " ".join(feature_rules)
                )

        if (
            resolved_tool == "nmap"
            and not multi_step
            and intent_contract.get("intent") == "NETWORK_SCAN"
            and "ping" in intent_contract.get("modifiers", [])
        ):
            rules.append(
                "NMAP PING REQUIREMENT: The requested ping modifier means "
                "host discovery only. Include -sn to disable port scanning. "
                "Do not substitute -sS or timing flags for host discovery. "
                "Preserve the exact requested target."
            )

        if resolved_tool == "gobuster" and not multi_step:
            transport_rules = []
            requested = intent_contract.get("modifiers", [])
            if "ssl" in requested:
                transport_rules.append(
                    "The ssl modifier requires an https:// target URL in -u. "
                    "Preserve the requested host, path and port. "
                    "-k only disables certificate verification and does not "
                    "enable HTTPS. Do not add -k unless explicitly requested."
                )
            if "silent" in requested:
                transport_rules.append(
                    "The silent modifier requires -q or --quiet."
                )
            if transport_rules:
                rules.append(
                    "GOBUSTER TRANSPORT REQUIREMENTS: "
                    + " ".join(transport_rules)
                )

        sections = [header]
        if doc_blocks:
            sections.append("\n\n".join(doc_blocks))
        if rules:
            sections.append("\n".join(rules))
        if (
            resolved_tool == "gobuster"
            and not multi_step
            and "ssl" in intent_contract.get("modifiers", [])
            and target_val
            and "://" not in target_val
        ):
            from urllib.parse import urlsplit, urlunsplit
            import shlex

            parsed_target = urlsplit("//" + target_val)
            host = parsed_target.hostname
            if not host:
                raise ValueError("Missing hostname for requested HTTPS target")

            requested_ports = intent_contract.get("ports") or []
            url_port = parsed_target.port
            if len(requested_ports) == 1:
                port = requested_ports[0]
                if url_port is not None and url_port != port:
                    raise ValueError("Conflicting URL port and requested HTTPS port")
            elif not requested_ports:
                port = url_port if url_port is not None else 443
            else:
                raise ValueError("One Gobuster URL cannot represent multiple requested ports")

            port = int(port)
            if not 1 <= port <= 65535:
                raise ValueError("Requested HTTPS port is outside 1-65535")

            if ":" in host:
                host = "[" + host + "]"
            exact_url = urlunsplit((
                "https",
                host + ":" + str(port),
                parsed_target.path,
                parsed_target.query,
                parsed_target.fragment,
            ))
            transport_rule = (
                "EXACT REQUESTED TRANSPORT: Use -u " + shlex.quote(exact_url)
                + ". The request requires HTTPS, not HTTP. "
                "Copy this requested URL exactly; documentation URLs are examples."
            )
            if "silent" in intent_contract.get("modifiers", []):
                transport_rule += " Include -q for requested silent mode."
            sections.append(transport_rule)

        sections.append(f"Planner input:\n{json_payload}")
        sections.append(completion_header)

        prompt = "\n\n".join(sections)
        from src.intent.query_constructor import needs_directory_wordlist_context
        if needs_directory_wordlist_context(intent_contract):
            prompt = "\n".join(
                line for line in prompt.splitlines()
                if not (
                    "Because no additional modifiers were requested" in line
                    and "<wordlist>" in line
                )
            )
            wordlist_rule = (
                "WORDLIST REQUIREMENT: No exact wordlist was supplied. "
                "Select a concrete directory-enumeration wordlist path shown "
                "in the documentation and include it with -w. "
                "Never output <wordlist>, /path/to/wordlist or another placeholder. "
                "Preserve the requested target, extensions and threads. "
                "Do not copy example targets or unrequested example flags.\n\n"
            )
            marker = "Planner input:\n"
            if prompt.count(marker) != 1:
                raise ValueError("Unexpected planner prompt structure")
            prompt = prompt.replace(marker, wordlist_rule + marker, 1)

        return prompt


if __name__ == "__main__":
    assembler = ContextAssembler()

    docs = [{"tool": "nmap", "content": "TOOL: nmap\n-sS SYN stealth scan\n-T4 Aggressive timing", "score": 0.3}]
    intent = {"intent": "NETWORK_SCAN", "target": {"value": "192.168.1.1"}, "ports": [80, 443], "modifiers": ["stealth"]}

    prompt = assembler.assemble(docs, intent)
    print(prompt)