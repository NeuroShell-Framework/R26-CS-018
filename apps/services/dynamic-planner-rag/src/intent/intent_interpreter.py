from __future__ import annotations

from src.schemas.models import IREIntentContract

MULTI_STEP_INTENTS = {"EXPLOITATION", "VULNERABILITY_AUDIT"}


class IntentInterpreter:

    def interpret(self, contract: IREIntentContract) -> dict:

        # ── NEW C1 FORMAT SUPPORT ─────────────────────────────

        if contract.target_value:
            target_value = contract.target_value
            target_type = contract.target_type or "UNKNOWN"

        # ── OLD FORMAT FALLBACK ───────────────────────────────

        elif contract.target:
            target_value = contract.target.get("value", "")
            target_type = contract.target.get("type", "UNKNOWN")

        else:
            target_value = ""
            target_type = "UNKNOWN"

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
            modifiers = contract.tool_parameters.flags

        # Old format fallback
        elif contract.modifiers:
            modifiers = contract.modifiers

        # ── TOOL HINT ─────────────────────────────────────────

        tool_hint = contract.primary_tool or contract.tool_hint

        return {
            "intent": contract.intent,
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