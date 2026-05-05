# NeuroShell IRE — Scope Guard
# Enforce scope restrictions on inferred intents

import ipaddress
import re
from typing import List, Tuple
from src.schemas.intent_schema import IntentSchema, TargetType, ScopeError
from src.utils.logging_config import get_logger
from config.settings import get_settings


class ScopeGuard:
    def __init__(self):
        self.logger = get_logger(__name__)
        self.settings = get_settings()

        self.PRIVATE_NETWORKS = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("127.0.0.0/8"),
            ipaddress.ip_network("169.254.0.0/16"),
            ipaddress.ip_network("::1/128"),
            ipaddress.ip_network("fc00::/7"),
        ]

        self.INJECTION_PATTERNS = [
            re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", re.I),
            re.compile(r"you\s+are\s+now\s+", re.I),
            re.compile(r"forget\s+(everything|all|your)", re.I),
            re.compile(r"act\s+as\s+(a\s+)?(different|new|another)", re.I),
            re.compile(r"jailbreak", re.I),
            re.compile(r"dan\s+mode", re.I),
            re.compile(r"prompt\s*injection", re.I),
        ]

    def check(self, schema: IntentSchema, raw_input: str = "") -> Tuple[IntentSchema, List[str]]:
        # Step 1 — Injection detection on raw_input
        for pattern in self.INJECTION_PATTERNS:
            if pattern.search(raw_input):
                raise ScopeError("Prompt injection pattern detected in input")

        # Step 2 — IP scope check
        warnings = []
        if self.settings.scope_mode == "research":
            if schema.target.type in (TargetType.IP, TargetType.SUBNET):
                try:
                    if schema.target.type == TargetType.IP:
                        addr = ipaddress.ip_address(schema.target.value)
                        is_private = any(addr in net for net in self.PRIVATE_NETWORKS)
                    else:
                        net = ipaddress.ip_network(schema.target.value, strict=False)
                        is_private = any(
                            net.overlaps(private) for private in self.PRIVATE_NETWORKS
                        )
                    if not is_private:
                        warnings.append(
                            f"SCOPE_WARNING: Target '{schema.target.value}' appears to be "
                            f"a public address. Research mode restricts operations to "
                            f"private/RFC-1918 ranges."
                        )
                except ValueError:
                    pass

        # Step 3 — Log result
        self.logger.info(
            "scope_check_complete",
            warnings_count=len(warnings),
            scope_mode=self.settings.scope_mode,
        )

        # Step 4 — Return
        return (schema, warnings)
