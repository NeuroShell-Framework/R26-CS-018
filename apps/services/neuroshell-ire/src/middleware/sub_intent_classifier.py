import re
from typing import Optional, List, Dict, Tuple, Callable

from config.feature_flags import get_feature_flags
from src.schemas.intent_schema import (
    IntentSchema, IntentType, SubIntentType, IREResponseV2
)
from src.utils.logging_config import get_logger

Rule = Tuple[SubIntentType, Callable[[IntentSchema], bool]]


class SubIntentClassifier:
    def __init__(self):
        self.logger = get_logger(__name__)
        self.flags = get_feature_flags()
        self._threshold = self.flags.get_tuning(
            "sub_intent_confidence_threshold", 0.6
        )
        self._rules: Dict[IntentType, List[Rule]] = {
            IntentType.NETWORK_SCAN: [
                (
                    SubIntentType.NETWORK_SCAN_SYN_STEALTH,
                    lambda s: any(m in [
                        "stealth", "syn stealth scan", "SYN stealth scan",
                        "stealthy"
                    ] for m in s.modifiers)
                    or 445 in s.ports,
                ),
                (
                    SubIntentType.NETWORK_SCAN_ICMP_DISCOVERY,
                    lambda s: any(m in [
                        "icmp", "ping", "ICMP discovery scan",
                        "stealth ICMP discovery scan"
                    ] for m in s.modifiers)
                    or (not s.ports and not s.modifiers),
                ),
                (
                    SubIntentType.NETWORK_SCAN_UDP_SWEEP,
                    lambda s: any(m in ["udp", "UDP"] for m in s.modifiers),
                ),
                (
                    SubIntentType.NETWORK_SCAN_VERSION_DETECT,
                    lambda s: any(m in [
                        "version", "version detection", "-sV"
                    ] for m in s.modifiers)
                    or any(p in [
                        21, 22, 23, 25, 80, 443, 3306,
                        3389, 5432
                    ] for p in s.ports),
                ),
                (
                    SubIntentType.NETWORK_SCAN_OS_DETECT,
                    lambda s: any(m in [
                        "os", "OS detection", "-O",
                        "os detection"
                    ] for m in s.modifiers),
                ),
                (
                    SubIntentType.NETWORK_SCAN_FULL_PORT,
                    lambda s: len(s.ports) > 10
                    or any(m in ["all ports", "full", "-p-"] for m in s.modifiers),
                ),
            ],
            IntentType.EXPLOITATION: [
                (
                    SubIntentType.EXPLOITATION_RCE,
                    lambda s: any(cve in [
                        "CVE-2021-44228", "CVE-2021-34527",
                        "CVE-2014-6271"
                    ] for cve in s.cve_ids)
                    or any(m in [
                        "rce", "remote code", "webshell",
                        "shell"
                    ] for m in s.modifiers),
                ),
                (
                    SubIntentType.EXPLOITATION_PRIV_ESC,
                    lambda s: any(m in [
                        "privilege escalation", "privesc", "priv esc",
                        "root", "SYSTEM"
                    ] for m in s.modifiers)
                    or any(cve in [
                        "CVE-2021-4034", "CVE-2020-1472"
                    ] for cve in s.cve_ids),
                ),
                (
                    SubIntentType.EXPLOITATION_LATERAL,
                    lambda s: any(m in [
                        "lateral", "lateral movement", "pivot",
                        "pass the hash", "pth"
                    ] for m in s.modifiers),
                ),
                (
                    SubIntentType.EXPLOITATION_PERSISTENCE,
                    lambda s: any(m in [
                        "persistence", "backdoor", "cron",
                        "scheduled task"
                    ] for m in s.modifiers),
                ),
            ],
            IntentType.VULNERABILITY_AUDIT: [
                (
                    SubIntentType.VULN_AUDIT_CVE_SPECIFIC,
                    lambda s: len(s.cve_ids) > 0,
                ),
                (
                    SubIntentType.VULN_AUDIT_SERVICE_SPECIFIC,
                    lambda s: len(s.ports) > 0 and len(s.cve_ids) == 0,
                ),
                (
                    SubIntentType.VULN_AUDIT_FULL_SCAN,
                    lambda s: len(s.ports) == 0 and len(s.cve_ids) == 0,
                ),
            ],
            IntentType.SERVICE_ENUMERATION: [
                (
                    SubIntentType.SERVICE_ENUM_SMB,
                    lambda s: any(p in [139, 445] for p in s.ports)
                    or any(m in ["smb", "SMB", "samba"] for m in s.modifiers),
                ),
                (
                    SubIntentType.SERVICE_ENUM_SNMP,
                    lambda s: any(p in [161, 162] for p in s.ports)
                    or any(m in ["snmp", "SNMP"] for m in s.modifiers),
                ),
                (
                    SubIntentType.SERVICE_ENUM_VERSION_DETECT,
                    lambda s: any(m in [
                        "version", "banner", "version detection",
                        "banner grabbing"
                    ] for m in s.modifiers),
                ),
                (
                    SubIntentType.SERVICE_ENUM_BANNER_GRAB,
                    lambda s: True,
                ),
            ],
            IntentType.PASSWORD_ATTACK: [
                (
                    SubIntentType.PASSWORD_SPRAY,
                    lambda s: any(m in [
                        "spray", "password spray attack",
                        "spraying"
                    ] for m in s.modifiers),
                ),
                (
                    SubIntentType.PASSWORD_CREDENTIAL_STUFFING,
                    lambda s: any(m in [
                        "credential stuffing", "stuffing",
                        "combo"
                    ] for m in s.modifiers),
                ),
                (
                    SubIntentType.PASSWORD_BRUTE_FORCE,
                    lambda s: True,
                ),
            ],
            IntentType.PASSIVE_RECON: [
                (
                    SubIntentType.PASSIVE_RECON_DNS,
                    lambda s: any(p in [53] for p in s.ports)
                    or any(m in ["dns", "DNS", "nslookup", "dig"] for m in s.modifiers),
                ),
                (
                    SubIntentType.PASSIVE_RECON_WHOIS,
                    lambda s: any(m in ["whois", "WHOIS"] for m in s.modifiers),
                ),
                (
                    SubIntentType.PASSIVE_RECON_OSINT,
                    lambda s: True,
                ),
            ],
            IntentType.DIRECTORY_BRUTEFORCE: [
                (
                    SubIntentType.DIR_BRUTE_API,
                    lambda s: any(m in [
                        "api", "API", "rest", "endpoint"
                    ] for m in s.modifiers)
                    or any(p in [8080, 8443, 8000, 3000] for p in s.ports),
                ),
                (
                    SubIntentType.DIR_BRUTE_FILES,
                    lambda s: any(m in [
                        "files", "backup", "config", "zip"
                    ] for m in s.modifiers),
                ),
                (
                    SubIntentType.DIR_BRUTE_WEB,
                    lambda s: True,
                ),
            ],
        }

    def classify(self, schema: IntentSchema) -> Optional[SubIntentType]:
        """Classifies the schema into a sub-intent."""
        if not self.flags.sub_intent:
            return None

        if schema.confidence < self._threshold:
            return None

        if schema.intent in (IntentType.AMBIGUOUS, IntentType.REJECTED):
            return None

        rules = self._rules.get(schema.intent, [])
        for sub_intent, predicate in rules:
            try:
                if predicate(schema):
                    self.logger.debug(
                        "sub_intent_classified",
                        intent=schema.intent.value,
                        sub_intent=sub_intent.value,
                    )
                    return sub_intent
            except Exception as e:
                self.logger.error(
                    "sub_intent_rule_error",
                    rule=sub_intent.value,
                    error=str(e),
                )
                continue

        return None

    def enrich(
        self,
        response: IREResponseV2,
        schema: Optional[IntentSchema] = None,
    ) -> IREResponseV2:
        """Adds sub_intent to a V2 response."""
        if not self.flags.sub_intent:
            return response

        if response.status != "success" or response.intent is None:
            return response

        try:
            if schema is None:
                from src.schemas.intent_schema import Target, TargetType

                schema = IntentSchema(
                    intent=response.intent,
                    target=response.target or Target(
                        type=TargetType.UNKNOWN, value=""
                    ),
                    ports=response.ports or [],
                    modifiers=response.modifiers or [],
                    cve_ids=response.cve_ids or [],
                    confidence=response.confidence or 0.0,
                )

            sub_intent = self.classify(schema)
            if sub_intent:
                response.sub_intent = sub_intent

        except Exception as e:
            self.logger.error("sub_intent_enrich_error", error=str(e))

        return response
