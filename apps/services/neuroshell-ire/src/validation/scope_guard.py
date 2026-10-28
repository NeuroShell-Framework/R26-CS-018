# NeuroShell IRE — Scope Guard
# Enforce scope restrictions on inferred intents driven by central EnforcementPolicy

import ipaddress
import re
from typing import List, Tuple
from config.enforcement_policy import get_enforcement_policy, EnforcementMode
from config.settings import get_settings
from src.schemas.intent_schema import IntentSchema, TargetType, ScopeError
from src.validation.hallucination_taxonomy import HallucinationClass, ValidationFinding
from src.utils.logging_config import get_logger


class ScopeGuard:
    def __init__(self):
        self.logger = get_logger(__name__)
        self.settings = get_settings()
        self.policy = get_enforcement_policy(self.settings)
        self.last_findings: List[ValidationFinding] = []

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

    def check(
        self, schema: IntentSchema, raw_input: str = ""
    ) -> Tuple[IntentSchema, List[str]]:
        self.last_findings = []
        policy = get_enforcement_policy(self.settings)

        # Step 1 — Injection detection on raw_input
        injection_detected = False
        for pattern in self.INJECTION_PATTERNS:
            if pattern.search(raw_input):
                injection_detected = True
                break

        if injection_detected:
            msg = "Prompt injection pattern detected in input"
            finding = ValidationFinding(
                validator="scope_guard",
                passed=False,
                hallucination_class=None,
                detail=msg,
                severity="block",
            )
            self.last_findings.append(finding)
            err = ScopeError(msg)
            err.findings = self.last_findings
            raise err

        self.last_findings.append(
            ValidationFinding(
                validator="scope_guard",
                passed=True,
                hallucination_class=None,
                detail="No prompt injection patterns detected in input",
                severity="block",
            )
        )

        # Step 2 — IP scope check driven by EnforcementPolicy
        warnings = []
        if schema.target.type in (TargetType.IP, TargetType.SUBNET):
            is_private = True
            try:
                if schema.target.type == TargetType.IP:
                    addr = ipaddress.ip_address(schema.target.value)
                    is_private = any(addr in net for net in self.PRIVATE_NETWORKS)
                else:
                    net = ipaddress.ip_network(schema.target.value, strict=False)
                    is_private = any(
                        net.overlaps(private) for private in self.PRIVATE_NETWORKS
                    )
            except ValueError:
                is_private = True

            if not is_private:
                severity = policy.get_severity(HallucinationClass.OUT_OF_SCOPE_TARGET)
                msg = (
                    f"SCOPE_WARNING: Target '{schema.target.value}' is a public address outside "
                    f"private RFC-1918 ranges (enforcement_mode={severity.upper()})."
                )
                finding = ValidationFinding(
                    validator="scope_guard",
                    passed=False,
                    hallucination_class=HallucinationClass.OUT_OF_SCOPE_TARGET,
                    detail=msg,
                    severity=severity,
                )
                self.last_findings.append(finding)

                if severity == "block":
                    err = ScopeError(msg)
                    err.findings = self.last_findings
                    raise err
                else:
                    warnings.append(msg)
            else:
                self.last_findings.append(
                    ValidationFinding(
                        validator="scope_guard",
                        passed=True,
                        hallucination_class=None,
                        detail=f"Target '{schema.target.value}' is within private RFC-1918 range",
                        severity="warn",
                    )
                )

        # Step 3 — Log result
        self.logger.info(
            "scope_check_complete",
            warnings_count=len(warnings),
            scope_mode=self.settings.scope_mode,
        )

        # Step 4 — Return
        return (schema, warnings)
