import ipaddress
from src.schemas.models import IREIntentContract

MULTI_STEP_INTENTS = {"EXPLOITATION", "VULNERABILITY_AUDIT"}


class IntentInterpreter:

    def _infer_target_type(self, target_val: str) -> str:
        if not target_val:
            return "UNKNOWN"
        if target_val.startswith("http://") or target_val.startswith("https://"):
            return "URL"
        try:
            ipaddress.ip_interface(target_val)
            if "/" in target_val:
                return "SUBNET"
            return "IP"
        except ValueError:
            pass
        return "DOMAIN"

    def interpret(self, contract: IREIntentContract) -> dict:

        # ── NEW C1 FORMAT SUPPORT ─────────────────────────────

        if contract.target_value:
            target_value = contract.target_value
            supplied_type = contract.target_type

        # ── OLD FORMAT FALLBACK ───────────────────────────────

        elif contract.target:
            target_value = contract.target.get("value", "")
            supplied_type = contract.target.get("type", None)

        else:
            target_value = ""
            supplied_type = None

        if supplied_type and str(supplied_type).upper() != "UNKNOWN":
            target_type = supplied_type
        else:
            target_type = self._infer_target_type(target_value)

        # ── PORTS ─────────────────────────────────────────────

        ports = []

        # New format ports
        if contract.tool_parameters and contract.tool_parameters.ports:
            ports = contract.tool_parameters.ports

        # Old format ports fallback
        elif contract.ports:
            ports = contract.ports

        # Default ports fallback
        if not ports:
            ports = self._default_ports(
                contract.intent,
                contract.primary_tool or contract.tool_hint
            )

        # ── MODIFIERS / FLAGS ─────────────────────────────────

        modifiers = []

        # New format flags
        if contract.tool_parameters and contract.tool_parameters.flags:
            modifiers = list(contract.tool_parameters.flags)

        # Old format fallback
        elif contract.modifiers:
            modifiers = list(contract.modifiers)

        # ── TOOL HINT ─────────────────────────────────────────

        tool_hint = contract.primary_tool or contract.tool_hint

        # ── PORT PARAMETER NORMALIZATION ─────────────────────
        # If ports are present but modifiers has no port flag, consistently append tool-specific port flag
        if ports:
            tool_name = (tool_hint or "").lower()
            if tool_name == "nmap" or contract.intent in ["NETWORK_SCAN", "SERVICE_ENUMERATION"]:
                has_port_flag = any("-p" in m or "--top-ports" in m or "-F" in m for m in modifiers)
                if not has_port_flag:
                    modifiers.append(f"-p {','.join(str(p) for p in ports)}")
            elif tool_name == "nikto":
                has_port_flag = any("-p" in m for m in modifiers)
                if not has_port_flag:
                    modifiers.append(f"-p {ports[0]}")

        # ── WORDLIST NORMALIZATION FOR GOBUSTER ───────────────
        resolved_tool = (tool_hint or "").lower()
        if not resolved_tool and contract.intent == "DIRECTORY_BRUTEFORCE":
            resolved_tool = "gobuster"

        wordlist_val = (
            contract.tool_parameters.wordlist
            if contract.tool_parameters and contract.tool_parameters.wordlist
            else None
        )
        if resolved_tool == "gobuster" and wordlist_val:
            modifiers = self._normalize_wordlist_for_gobuster(wordlist_val, modifiers)

        # ── SUB_INTENT ───────────────────────────────────────
        sub_intent = contract.sub_intent
        if not sub_intent:
            if contract.intent == "NETWORK_SCAN":
                sub_intent = "specific_ports_scan" if ports else "port_scan"
            elif contract.intent == "VULNERABILITY_AUDIT":
                sub_intent = "vulnerability_scan"
            elif contract.intent == "DIRECTORY_BRUTEFORCE":
                sub_intent = "directory_enumeration"
            elif contract.intent == "SERVICE_ENUMERATION":
                sub_intent = "service_version_detection"
            else:
                sub_intent = "general"

        return {
            "intent": contract.intent,
            "sub_intent": sub_intent,
            "target_value": target_value,
            "target_type": target_type,
            "ports": ports,
            "modifiers": modifiers,
            "cve_ids": contract.cve_ids,
            "tool_hint": tool_hint,
            "confidence": contract.confidence,

            # Optional adapter fields
            "wordlist": (
                contract.tool_parameters.wordlist
                if contract.tool_parameters else None
            ),

            "suggested_command": (
                contract.tool_parameters.suggested_command
                if contract.tool_parameters else None
            ),

            "multi_step": (
                contract.intent in MULTI_STEP_INTENTS
                and contract.confidence > 0.85
            ),
        }

    def _default_ports(self, intent: str, tool_hint: str | None) -> list:

        if tool_hint == "nikto" or intent == "VULNERABILITY_AUDIT":
            return [80]

        if intent == "DIRECTORY_BRUTEFORCE":
            return [80]

        return []

    def _normalize_wordlist_for_gobuster(self, wordlist_val: str, modifiers: list) -> list:
        import shlex
        if not wordlist_val:
            return modifiers

        wordlist_str = str(wordlist_val).strip()
        if not wordlist_str:
            return modifiers

        placed_wordlist = False
        new_modifiers = []

        for mod in modifiers:
            mod_str = str(mod).strip()
            if not mod_str:
                continue

            # Parse tokens with shlex.split (raises ValueError on unclosed quotes)
            try:
                tokens = shlex.split(mod_str)
            except ValueError as ve:
                raise ValueError(f"Malformed quoting in modifier '{mod_str}': {ve}") from ve
            if not tokens:
                continue

            rebuilt_tokens = []
            i = 0
            while i < len(tokens):
                tok = tokens[i]

                if tok in ["-w", "--wordlist"]:
                    # Skip old wordlist argument token if present
                    if i + 1 < len(tokens) and not tokens[i + 1].startswith("-"):
                        i += 2
                    else:
                        i += 1

                    if not placed_wordlist:
                        rebuilt_tokens.append("-w")
                        rebuilt_tokens.append(wordlist_str)
                        placed_wordlist = True

                elif tok.startswith("-w=") or tok.startswith("--wordlist="):
                    i += 1
                    if not placed_wordlist:
                        rebuilt_tokens.append("-w")
                        rebuilt_tokens.append(wordlist_str)
                        placed_wordlist = True

                else:
                    rebuilt_tokens.append(tok)
                    i += 1

            if rebuilt_tokens:
                if hasattr(shlex, 'join'):
                    new_mod_str = shlex.join(rebuilt_tokens)
                else:
                    new_mod_str = " ".join(shlex.quote(t) for t in rebuilt_tokens)
                new_modifiers.append(new_mod_str)

        if not placed_wordlist:
            if hasattr(shlex, 'join'):
                new_modifiers.append(shlex.join(["-w", wordlist_str]))
            else:
                new_modifiers.append(f"-w {shlex.quote(wordlist_str)}")

        return new_modifiers