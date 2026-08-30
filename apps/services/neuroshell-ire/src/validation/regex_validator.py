# NeuroShell IRE — Regex Validator
# Regex-based fallback validation for structured fields with CVE grounding and hallucination classification

import json
import re
from pathlib import Path
from typing import Dict, List, Set

from config.enforcement_policy import get_enforcement_policy
from config.settings import get_settings
from src.schemas.intent_schema import IntentSchema, TargetType, RegexValidationError
from src.validation.hallucination_taxonomy import HallucinationClass, ValidationFinding
from src.utils.logging_config import get_logger


class RegexValidator:
    def __init__(self):
        self.logger = get_logger(__name__)
        self.settings = get_settings()
        self.last_findings: List[ValidationFinding] = []
        self.IPV4_RE = re.compile(r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$")
        self.CIDR_RE = re.compile(r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)/([0-9]|[1-2][0-9]|3[0-2])$")
        self.IPV6_RE = re.compile(r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$")
        self.DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
        self.HOST_SINGLE_RE = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")
        self.CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
        self.URL_RE = re.compile(r"^https?://[^\s/$.?#].[^\s]*$")
        self.SHELL_META_RE = re.compile(r"[;&|$\\`!><]")

        self.cve_grounding: Dict[str, dict] = self._load_cve_grounding()

    def _load_cve_grounding(self) -> Dict[str, dict]:
        path = Path(self.settings.cve_grounding_path)
        if not path.is_file():
            self.logger.warning("cve_grounding_file_missing", path=str(path))
            return {}
        try:
            raw = path.read_text(encoding="utf-8")
            data = json.loads(raw)
            return {k.upper(): v for k, v in data.items() if not k.startswith("_")}
        except Exception as e:
            self.logger.error("cve_grounding_load_failed", path=str(path), error=str(e))
            return {}

    def validate(self, schema: IntentSchema) -> IntentSchema:
        self.last_findings = []

        # CHECK 1 — Target value format
        target_valid = True
        target_msg = ""
        if schema.target.type == TargetType.IP:
            if not self.IPV4_RE.match(schema.target.value) and not self.IPV6_RE.match(schema.target.value):
                target_valid = False
                target_msg = f"'{schema.target.value}' is not a valid IPv4 or IPv6 address"
        elif schema.target.type == TargetType.SUBNET:
            if not self.CIDR_RE.match(schema.target.value):
                target_valid = False
                target_msg = f"'{schema.target.value}' is not a valid CIDR notation subnet"
        elif schema.target.type in (TargetType.DOMAIN, TargetType.HOSTNAME):
            if not (
                self.DOMAIN_RE.match(schema.target.value)
                or self.HOST_SINGLE_RE.match(schema.target.value)
            ):
                target_valid = False
                target_msg = f"'{schema.target.value}' is not a valid domain or hostname"
        elif schema.target.type == TargetType.URL:
            if not self.URL_RE.match(schema.target.value):
                target_valid = False
                target_msg = f"'{schema.target.value}' is not a valid URL"

        if target_valid:
            self.last_findings.append(
                ValidationFinding(
                    validator="regex_validator",
                    passed=True,
                    hallucination_class=None,
                    detail=f"Target value '{schema.target.value}' matches expected regex format for type {schema.target.type.value}",
                    severity="block",
                )
            )
        else:
            self.last_findings.append(
                ValidationFinding(
                    validator="regex_validator",
                    passed=False,
                    hallucination_class=HallucinationClass.TARGET_TYPE_MISMATCH,
                    detail=target_msg,
                    severity="block",
                )
            )
            err = RegexValidationError(target_msg, field="target.value")
            err.findings = self.last_findings
            raise err

        policy = get_enforcement_policy()

        # CHECK 2 — CVE ID formats & Grounding Lookup
        cve_syntax_sev = policy.get_severity(HallucinationClass.FABRICATED_CVE)
        cve_ungrounded_sev = policy.get_severity(HallucinationClass.UNGROUNDED_CONFIDENCE)

        for cve in schema.cve_ids:
            cve_upper = cve.upper()
            if not self.CVE_RE.match(cve_upper):
                detail = f"Invalid CVE format: '{cve}'. Expected CVE-YYYY-NNNNN"
                self.last_findings.append(
                    ValidationFinding(
                        validator="regex_validator",
                        passed=False,
                        hallucination_class=HallucinationClass.FABRICATED_CVE,
                        detail=detail,
                        severity=cve_syntax_sev,
                    )
                )
                if cve_syntax_sev == "block":
                    err = RegexValidationError(detail, field="cve_ids")
                    err.findings = self.last_findings
                    raise err

            # Grounding Dataset Check (for syntactically valid CVEs)
            if cve_upper in self.cve_grounding:
                info = self.cve_grounding[cve_upper]
                desc = info.get("description", "Grounded CVE entry")
                self.last_findings.append(
                    ValidationFinding(
                        validator="regex_validator",
                        passed=True,
                        hallucination_class=None,
                        detail=f"CVE '{cve_upper}' validated against local grounding dataset ({desc})",
                        severity="block",
                    )
                )
            else:
                detail = f"CVE '{cve_upper}' matches syntax but is not present in local offline grounding dataset"
                self.last_findings.append(
                    ValidationFinding(
                        validator="regex_validator",
                        passed=False,
                        hallucination_class=HallucinationClass.UNGROUNDED_CONFIDENCE,
                        detail=detail,
                        severity=cve_ungrounded_sev,
                    )
                )
                if cve_ungrounded_sev == "block":
                    err = RegexValidationError(detail, field="cve_ids")
                    err.findings = self.last_findings
                    raise err

        if not schema.cve_ids:
            self.last_findings.append(
                ValidationFinding(
                    validator="regex_validator",
                    passed=True,
                    hallucination_class=None,
                    detail="No CVE IDs present to validate",
                    severity="block",
                )
            )

        # CHECK 3 — Port bounds
        invalid_port = None
        for port in schema.ports:
            if not (1 <= port <= 65535):
                invalid_port = port
                break

        if invalid_port is None:
            self.last_findings.append(
                ValidationFinding(
                    validator="regex_validator",
                    passed=True,
                    hallucination_class=None,
                    detail=f"All {len(schema.ports)} ports fall within valid range [1, 65535]",
                    severity="block",
                )
            )
        else:
            detail = f"Port {invalid_port} out of valid range (1-65535)"
            self.last_findings.append(
                ValidationFinding(
                    validator="regex_validator",
                    passed=False,
                    hallucination_class=HallucinationClass.FABRICATED_PARAMETER,
                    detail=detail,
                    severity="block",
                )
            )
            err = RegexValidationError(detail, field="ports")
            err.findings = self.last_findings
            raise err

        # CHECK 4 — Shell metacharacter injection
        meta_found = False
        meta_msg = ""
        field = "target.value"
        if self.SHELL_META_RE.search(schema.target.value):
            meta_found = True
            meta_msg = "Shell metacharacters detected in target.value"
            field = "target.value"
        else:
            for mod in schema.modifiers:
                if self.SHELL_META_RE.search(mod):
                    meta_found = True
                    meta_msg = f"Shell metacharacters detected in modifier: {mod}"
                    field = "modifiers"
                    break

        if not meta_found:
            self.last_findings.append(
                ValidationFinding(
                    validator="regex_validator",
                    passed=True,
                    hallucination_class=None,
                    detail="No shell metacharacters detected in target or modifiers",
                    severity="block",
                )
            )
        else:
            self.last_findings.append(
                ValidationFinding(
                    validator="regex_validator",
                    passed=False,
                    hallucination_class=HallucinationClass.FABRICATED_PARAMETER,
                    detail=meta_msg,
                    severity="block",
                )
            )
            err = RegexValidationError(meta_msg, field=field)
            err.findings = self.last_findings
            raise err

        self.logger.debug("regex_validated", target_type=schema.target.type.value)
        return schema
