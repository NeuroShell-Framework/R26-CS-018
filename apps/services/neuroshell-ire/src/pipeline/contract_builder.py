import uuid
from enum import Enum
from typing import Optional, List, Dict, Any

from src.schemas.intent_schema import (
    IntentSchema, IntentType, SubIntentType, TargetType,
)
from src.schemas.planner_contract import (
    PlannerContract, PlannerTarget,
)
from src.utils.logging_config import get_logger


CVE_DESCRIPTIONS: Dict[str, str] = {
    "CVE-2017-0144": "EternalBlue — SMB Remote Code Execution (MS17-010)",
    "CVE-2021-44228": "Log4Shell — Apache Log4j Remote Code Execution",
    "CVE-2019-0708": "BlueKeep — RDP Remote Code Execution",
    "CVE-2014-6271": "ShellShock — Bash Remote Code Execution",
    "CVE-2014-0160": "Heartbleed — OpenSSL Memory Disclosure",
    "CVE-2021-34527": "PrintNightmare — Windows Print Spooler RCE",
    "CVE-2020-1472": "ZeroLogon — Netlogon Privilege Escalation",
    "CVE-2021-26855": "ProxyLogon — Exchange Server SSRF",
    "CVE-2022-0847": "DirtyPipe — Linux Kernel Privilege Escalation",
    "CVE-2021-4034": "PwnKit — Polkit Privilege Escalation",
}


class _ToolName(str, Enum):
    NMAP     = "nmap"
    GOBUSTER = "gobuster"
    NIKTO    = "nikto"
    MANUAL   = "manual"
    NONE     = "none"


class ContractBuilder:
    def __init__(self):
        self.logger = get_logger(__name__)

    def _determine_priority(self, schema: IntentSchema) -> str:
        if schema.schedule:
            return "SCHEDULED"
        if schema.intent == IntentType.EXPLOITATION:
            return "CRITICAL"
        if schema.intent == IntentType.VULNERABILITY_AUDIT and schema.cve_ids:
            return "HIGH"
        if schema.intent in (
            IntentType.NETWORK_SCAN,
            IntentType.SERVICE_ENUMERATION,
            IntentType.VULNERABILITY_AUDIT,
        ):
            return "MEDIUM"
        return "LOW"

    def _determine_tool(self, schema: IntentSchema) -> _ToolName:
        if schema.intent == IntentType.NETWORK_SCAN:
            return _ToolName.NMAP
        if schema.intent == IntentType.VULNERABILITY_AUDIT:
            if schema.target.type == TargetType.URL:
                return _ToolName.NIKTO
            return _ToolName.NMAP
        if schema.intent == IntentType.SERVICE_ENUMERATION:
            return _ToolName.NMAP
        if schema.intent == IntentType.EXPLOITATION:
            return _ToolName.MANUAL
        if schema.intent == IntentType.PASSWORD_ATTACK:
            return _ToolName.MANUAL
        if schema.intent == IntentType.DIRECTORY_BRUTEFORCE:
            return _ToolName.GOBUSTER
        if schema.intent == IntentType.PASSIVE_RECON:
            return _ToolName.NONE
        if schema.intent == IntentType.AMBIGUOUS:
            return _ToolName.NONE
        if schema.intent == IntentType.REJECTED:
            return _ToolName.NONE
        return _ToolName.MANUAL

    def _build_human_readable(self, schema: IntentSchema) -> str:
        target_val = schema.target.value
        if schema.intent == IntentType.NETWORK_SCAN:
            modifiers_str = ""
            if schema.modifiers:
                modifiers_str = " ".join(schema.modifiers) + " "
            ports_str = ""
            if schema.ports:
                ports_str = f" on ports {', '.join(str(p) for p in schema.ports)}"
            return f"{modifiers_str}network scan of {target_val}{ports_str}"
        if schema.intent == IntentType.VULNERABILITY_AUDIT:
            cve_str = ""
            if schema.cve_ids:
                descs = []
                for c in schema.cve_ids:
                    d = CVE_DESCRIPTIONS.get(c, "")
                    descs.append(f"{c} ({d})" if d else c)
                cve_str = " for " + ", ".join(descs)
            return f"Vulnerability audit of {target_val}{cve_str}"
        if schema.intent == IntentType.EXPLOITATION:
            return f"Exploitation of {target_val} — requires human approval"
        if schema.intent == IntentType.DIRECTORY_BRUTEFORCE:
            return f"Directory bruteforce of {target_val}"
        if schema.intent == IntentType.PASSWORD_ATTACK:
            return f"Password attack against {target_val} — requires human approval"
        if schema.intent == IntentType.SERVICE_ENUMERATION:
            return f"Service enumeration of {target_val}"
        if schema.intent == IntentType.PASSIVE_RECON:
            return f"Passive reconnaissance of {target_val}"
        if schema.intent == IntentType.AMBIGUOUS:
            return f"Ambiguous request — could not determine intent for {target_val}"
        if schema.intent == IntentType.REJECTED:
            return f"Rejected request for {target_val}"
        return f"Unknown intent for target {target_val}"

    def _build_tool_parameters(self, schema: IntentSchema) -> Optional[Dict[str, Any]]:
        if schema.intent in (IntentType.AMBIGUOUS, IntentType.REJECTED, IntentType.PASSIVE_RECON):
            return None

        MODIFIER_TO_FLAG = {
            "stealth":                      "stealth",
            "SYN stealth scan":             "stealth",
            "ICMP discovery scan":          "stealth",
            "stealth ICMP discovery scan":  "stealth",
            "aggressive":                   "aggressive",
            "version detection":            "version_detect",
            "OS detection":                 "os_detect",
            "udp":                          "udp",
            "full":                         "full_port",
            "all ports":                    "full_port",
            "verbose":                      "verbose",
            "recursive":                    "recursive",
            "ssl":                          "ssl",
            "banner grabbing":              "version_detect",
            "enumeration":                  "version_detect",
        }

        flags = []
        for mod in schema.modifiers:
            flag = MODIFIER_TO_FLAG.get(mod)
            if flag and flag not in flags:
                flags.append(flag)

        if not flags and schema.intent == IntentType.NETWORK_SCAN:
            flags = ["stealth"]

        return {
            "target": schema.target.value,
            "ports": schema.ports or [],
            "flags": flags,
        }

    def _build_suggested_command(
        self, tool: _ToolName, target: str, ports: List[int], flags: List[str]
    ) -> str:
        FLAG_MAP = {
            "stealth":       "-sS",
            "aggressive":    "-A",
            "version_detect": "-sV",
            "os_detect":     "-O",
            "udp":           "-sU",
            "full_port":     "-p-",
            "verbose":       "-v",
        }

        if tool == _ToolName.NMAP:
            parts = ["nmap"]
            nmap_flags = [FLAG_MAP[f] for f in flags if f in FLAG_MAP]
            if not nmap_flags:
                nmap_flags = ["-sS"]
            parts += nmap_flags
            timing = "-T1" if "stealth" in flags else "-T3"
            parts.append(timing)
            if ports:
                parts += ["-p", ",".join(str(p) for p in sorted(ports))]
            parts.append(target)
            return " ".join(parts)

        elif tool == _ToolName.GOBUSTER:
            url = target if target.startswith("http") else f"http://{target}"
            return f"gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt -q"

        elif tool == _ToolName.NIKTO:
            port = ports[0] if ports else 80
            ssl = "-ssl" if port in [443, 8443] else ""
            return f"nikto -h {target} -p {port} {ssl}".strip()

        return ""

    def _build_cve_context(self, cve_ids: List[str]) -> List[Dict[str, str]]:
        result = []
        for cve_id in cve_ids:
            description = CVE_DESCRIPTIONS.get(cve_id, "No description available")
            result.append({"cve_id": cve_id, "description": description})
        return result

    def _build_safety_notes(self, schema: IntentSchema) -> List[str]:
        notes = []
        if schema.intent == IntentType.EXPLOITATION:
            notes.append("EXPLOITATION intent — manual review required before execution")
            notes.append("Ensure written authorisation is in place for this target")
        if schema.intent == IntentType.PASSWORD_ATTACK:
            notes.append("PASSWORD_ATTACK intent — risk of account lockout")
            notes.append("Verify target lockout policy before executing")
        if schema.cve_ids:
            notes.append("CVE-targeting scan — verify patch status before exploit attempt")
        if not schema.ports and schema.intent == IntentType.NETWORK_SCAN:
            notes.append("No ports specified — will scan nmap default ports (top 1000)")
        return notes

    def build(
        self,
        schema: IntentSchema,
        session_id: Optional[str] = None,
        scope_warnings: Optional[List[str]] = None,
    ) -> PlannerContract:
        scope_warnings = scope_warnings or []

        tool = self._determine_tool(schema)
        if tool in (_ToolName.NONE, _ToolName.MANUAL):
            tool_hint_str = None
        else:
            tool_hint_str = tool.value

        return PlannerContract(
            intent=schema.intent,
            sub_intent=None,
            target=PlannerTarget(
                type=schema.target.type.value,
                value=schema.target.value,
            ),
            ports=schema.ports or [],
            modifiers=schema.modifiers or [],
            cve_ids=schema.cve_ids or [],
            tool_hint=tool_hint_str,
            schedule=schema.schedule,
            confidence=schema.confidence,
            rejection_reason=schema.rejection_reason,
            scope_warnings=scope_warnings,
            session_id=session_id,
        )
