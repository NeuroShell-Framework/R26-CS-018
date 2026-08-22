import ipaddress
from typing import List, Optional, Tuple, Union

from config.enforcement_policy import get_enforcement_policy
from config.settings import get_settings
from src.schemas.intent_schema import (
    IntentSchema, TargetType, NetworkValidationError
)
from src.validation.hallucination_taxonomy import HallucinationClass, ValidationFinding
from src.utils.logging_config import get_logger


IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


class NetworkArchitectureValidator:
    def __init__(self):
        self.logger = get_logger(__name__)
        self.settings = get_settings()
        self.last_findings: List[ValidationFinding] = []
        self.logger.info(
            "network_validator_initialized",
            engagement_scope=self.settings.engagement_scope,
            engagement_name=self.settings.engagement_name,
            mode=self.settings.engagement_mode,
        )

    @property
    def _scope_network(self) -> IPNetwork:
        try:
            return ipaddress.ip_network(
                self.settings.engagement_scope, strict=False
            )
        except ValueError as e:
            self.logger.error(
                "invalid_engagement_scope",
                scope=self.settings.engagement_scope,
                error=str(e),
            )
            return ipaddress.ip_network("10.0.0.0/8")

    def _parse_target(self, value: str) -> Union[IPAddress, IPNetwork]:
        try:
            if "/" in value:
                return ipaddress.ip_network(value, strict=False)
            return ipaddress.ip_address(value)
        except ValueError:
            raise NetworkValidationError(
                f"Invalid IP or subnet format: '{value}'",
                field="target.value",
                validation_type="format",
            )

    def _is_in_scope(
        self, address_str: str, target_type: TargetType
    ) -> Tuple[bool, str]:
        if target_type in (
            TargetType.DOMAIN, TargetType.URL,
            TargetType.HOSTNAME, TargetType.UNKNOWN,
        ):
            return True, ""

        if not address_str:
            return True, ""

        try:
            if target_type == TargetType.IP:
                addr = ipaddress.ip_address(address_str)
                in_scope = addr in self._scope_network
                if not in_scope:
                    return False, (
                        f"Target IP {address_str} is outside the declared "
                        f"engagement scope {self.settings.engagement_scope} "
                        f"({self.settings.engagement_name})"
                    )
                return True, ""

            elif target_type == TargetType.SUBNET:
                target_net = ipaddress.ip_network(address_str, strict=False)
                scope_net = self._scope_network
                if isinstance(target_net, ipaddress.IPv4Network) and isinstance(scope_net, ipaddress.IPv4Network):
                    in_scope = target_net.subnet_of(scope_net)
                elif isinstance(target_net, ipaddress.IPv6Network) and isinstance(scope_net, ipaddress.IPv6Network):
                    in_scope = target_net.subnet_of(scope_net)
                else:
                    in_scope = False

                if not in_scope:
                    return False, (
                        f"Target subnet {address_str} is not fully contained "
                        f"within engagement scope "
                        f"{self.settings.engagement_scope} "
                        f"({self.settings.engagement_name})"
                    )
                return True, ""

        except ValueError:
            return True, ""

        return True, ""

    def _check_cidr_sanity(
        self, address_str: str, target_type: TargetType
    ) -> Tuple[bool, str]:
        if target_type != TargetType.SUBNET:
            return True, ""

        try:
            net = ipaddress.ip_network(address_str, strict=False)
            prefix = net.prefixlen

            if prefix < self.settings.max_cidr_prefix:
                return False, (
                    f"CIDR prefix /{prefix} is wider than the maximum "
                    f"allowed /{self.settings.max_cidr_prefix} for this "
                    f"engagement. This would scan "
                    f"{net.num_addresses:,} addresses."
                )

            if isinstance(net, ipaddress.IPv4Network) and prefix == 32:
                return False, (
                    f"CIDR /32 ({address_str}) is a single host address. "
                    f"Use target type IP instead of SUBNET for host targets."
                )

            if isinstance(net, ipaddress.IPv6Network) and prefix < 64:
                return False, (
                    f"IPv6 subnet /{prefix} is too large. "
                    f"Minimum allowed prefix is /64."
                )

        except ValueError:
            pass

        return True, ""

    def _check_target_type_consistency(
        self, schema: IntentSchema
    ) -> Tuple[bool, str]:
        t = schema.target

        if t.type == TargetType.IP and "/" in t.value:
            return False, (
                f"Target type is IP but value '{t.value}' contains CIDR "
                f"notation. Did you mean target type SUBNET?"
            )

        if t.type == TargetType.SUBNET and "/" not in t.value:
            return False, (
                f"Target type is SUBNET but value '{t.value}' has no "
                f"prefix length. Specify as CIDR (e.g. {t.value}/24)."
            )

        if t.type == TargetType.UNKNOWN and t.value:
            return False, (
                f"Target type is UNKNOWN but a value '{t.value}' was "
                f"extracted. The target format could not be determined."
            )

        return True, ""

    def validate(
        self, schema: IntentSchema
    ) -> Tuple[IntentSchema, List[str]]:
        self.last_findings = []
        if self.settings.engagement_mode == "disabled":
            self.last_findings.append(
                ValidationFinding(
                    validator="network_validator",
                    passed=True,
                    hallucination_class=None,
                    detail="Network architecture validation disabled by configuration",
                    severity="warn",
                )
            )
            return schema, []

        warnings: List[str] = []
        policy = get_enforcement_policy(self.settings)
        if self.settings.engagement_mode == "warn":
            type_mismatch_sev = "warn"
            scope_sev = "warn"
        else:
            type_mismatch_sev = policy.get_severity(HallucinationClass.TARGET_TYPE_MISMATCH)
            scope_sev = policy.get_severity(HallucinationClass.OUT_OF_SCOPE_TARGET)

        # Step 1 — Type consistency
        consistent, msg = self._check_target_type_consistency(schema)
        if consistent:
            self.last_findings.append(
                ValidationFinding(
                    validator="network_validator",
                    passed=True,
                    hallucination_class=None,
                    detail=f"Target type '{schema.target.type.value}' is consistent with value '{schema.target.value}'",
                    severity="block",
                )
            )
        else:
            self.last_findings.append(
                ValidationFinding(
                    validator="network_validator",
                    passed=False,
                    hallucination_class=HallucinationClass.TARGET_TYPE_MISMATCH,
                    detail=msg,
                    severity=type_mismatch_sev,
                )
            )
            if type_mismatch_sev == "block":
                err = NetworkValidationError(msg, field="target.value", validation_type="type_consistency")
                err.findings = self.last_findings
                raise err
            warnings.append(f"ARCH_WARNING: {msg}")

        # Steps 2-4 for IP/SUBNET targets
        if schema.target.type in (TargetType.IP, TargetType.SUBNET):
            # Step 2 — Parse target format
            format_valid = True
            format_msg = ""
            try:
                self._parse_target(schema.target.value)
            except NetworkValidationError as e:
                format_valid = False
                format_msg = str(e)

            if format_valid:
                self.last_findings.append(
                    ValidationFinding(
                        validator="network_validator",
                        passed=True,
                        hallucination_class=None,
                        detail=f"Target address '{schema.target.value}' parsed valid format",
                        severity="block",
                    )
                )
            else:
                self.last_findings.append(
                    ValidationFinding(
                        validator="network_validator",
                        passed=False,
                        hallucination_class=HallucinationClass.TARGET_TYPE_MISMATCH,
                        detail=format_msg,
                        severity=type_mismatch_sev,
                    )
                )
                if type_mismatch_sev == "block":
                    err = NetworkValidationError(format_msg, field="target.value", validation_type="format")
                    err.findings = self.last_findings
                    raise err
                warnings.append(f"ARCH_WARNING: {format_msg}")
                return schema, warnings

            # Step 3 — Scope check
            in_scope, msg = self._is_in_scope(schema.target.value, schema.target.type)
            if in_scope:
                self.last_findings.append(
                    ValidationFinding(
                        validator="network_validator",
                        passed=True,
                        hallucination_class=None,
                        detail=f"Target '{schema.target.value}' is within engagement scope '{self.settings.engagement_scope}'",
                        severity=scope_sev,
                    )
                )
            else:
                self.last_findings.append(
                    ValidationFinding(
                        validator="network_validator",
                        passed=False,
                        hallucination_class=HallucinationClass.OUT_OF_SCOPE_TARGET,
                        detail=msg,
                        severity=scope_sev,
                    )
                )
                if scope_sev == "block":
                    err = NetworkValidationError(msg, field="target.value", validation_type="scope")
                    err.findings = self.last_findings
                    raise err
                warnings.append(f"SCOPE_VIOLATION: {msg}")

            # Step 4 — CIDR sanity (subnets only)
            if schema.target.type == TargetType.SUBNET:
                sane, msg = self._check_cidr_sanity(schema.target.value, schema.target.type)
                if sane:
                    self.last_findings.append(
                        ValidationFinding(
                            validator="network_validator",
                            passed=True,
                            hallucination_class=None,
                            detail=f"Subnet '{schema.target.value}' satisfies CIDR prefix sanity checks",
                            severity=scope_sev,
                        )
                    )
                else:
                    self.last_findings.append(
                        ValidationFinding(
                            validator="network_validator",
                            passed=False,
                            hallucination_class=HallucinationClass.OUT_OF_SCOPE_TARGET,
                            detail=msg,
                            severity=scope_sev,
                        )
                    )
                    if scope_sev == "block":
                        err = NetworkValidationError(msg, field="target.value", validation_type="cidr_sanity")
                        err.findings = self.last_findings
                        raise err
                    warnings.append(f"ARCH_WARNING: {msg}")

        self.logger.info(
            "network_architecture_validated",
            target=schema.target.value,
            target_type=schema.target.type.value,
            warnings=len(warnings),
            mode=self.settings.engagement_mode,
        )

        return schema, warnings
