# NeuroShell IRE — Regex Validator
# Regex-based fallback validation for structured fields

import re
import ipaddress
from src.schemas.intent_schema import IntentSchema, TargetType, RegexValidationError
from src.utils.logging_config import get_logger


class RegexValidator:
    def __init__(self):
        self.logger = get_logger(__name__)
        self.IPV4_RE = re.compile(r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$")
        self.CIDR_RE = re.compile(r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)/([0-9]|[1-2][0-9]|3[0-2])$")
        self.IPV6_RE = re.compile(r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$")
        self.DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
        self.CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
        self.URL_RE = re.compile(r"^https?://[^\s/$.?#].[^\s]*$")

    def validate(self, schema: IntentSchema) -> IntentSchema:
        # CHECK 1 — Target value format
        if schema.target.type == TargetType.IP:
            if not self.IPV4_RE.match(schema.target.value) and not self.IPV6_RE.match(schema.target.value):
                raise RegexValidationError(
                    f"'{schema.target.value}' is not a valid IPv4 or IPv6 address",
                    field="target.value"
                )
        elif schema.target.type == TargetType.SUBNET:
            if not self.CIDR_RE.match(schema.target.value):
                raise RegexValidationError(
                    f"'{schema.target.value}' is not a valid CIDR notation subnet",
                    field="target.value"
                )
        elif schema.target.type in (TargetType.DOMAIN, TargetType.HOSTNAME):
            if not self.DOMAIN_RE.match(schema.target.value):
                raise RegexValidationError(
                    f"'{schema.target.value}' is not a valid domain or hostname",
                    field="target.value"
                )
        elif schema.target.type == TargetType.URL:
            if not self.URL_RE.match(schema.target.value):
                raise RegexValidationError(
                    f"'{schema.target.value}' is not a valid URL",
                    field="target.value"
                )

        # CHECK 2 — CVE ID formats
        for cve in schema.cve_ids:
            if not self.CVE_RE.match(cve):
                raise RegexValidationError(f"Invalid CVE format: {cve}", field="cve_ids")

        # CHECK 3 — Port bounds
        for port in schema.ports:
            if not (1 <= port <= 65535):
                raise RegexValidationError(f"Port {port} out of valid range", field="ports")

        # CHECK 4 — Shell metacharacter injection
        SHELL_META_RE = re.compile(r"[;&|$\\`!><]")
        if SHELL_META_RE.search(schema.target.value):
            raise RegexValidationError(
                "Shell metacharacters detected in target.value", field="target.value"
            )
        for mod in schema.modifiers:
            if SHELL_META_RE.search(mod):
                raise RegexValidationError(
                    f"Shell metacharacters detected in modifier: {mod}", field="modifiers"
                )

        self.logger.debug("regex_validated", target_type=schema.target.type.value)
        return schema
