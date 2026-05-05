import ipaddress
from typing import List, Optional, Tuple, Union

from config.settings import get_settings
from src.schemas.intent_schema import (
    IntentSchema, TargetType, NetworkValidationError
)
from src.utils.logging_config import get_logger


IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


class NetworkArchitectureValidator:
    def __init__(self):
        self.logger = get_logger(__name__)
        self.settings = get_settings()
        self._load_scope()
        self.logger.info(
            "network_validator_initialized",
            engagement_scope=self.settings.engagement_scope,
            engagement_name=self.settings.engagement_name,
            mode=self.settings.engagement_mode,
        )

    # ---------------------------------------------------------
    # Scope loading with safe fallback
    # ---------------------------------------------------------
    def _load_scope(self) -> None:
        try:
            self._scope_network: IPNetwork = ipaddress.ip_network(
                self.settings.engagement_scope, strict=False
            )
        except ValueError as e:
            self.logger.error(
                "invalid_engagement_scope",
                scope=self.settings.engagement_scope,
                error=str(e),
            )
            self._scope_network = ipaddress.ip_network("10.0.0.0/8")

    # ---------------------------------------------------------
    # Parse a target value to IPAddress or IPNetwork.
    # Only call for IP / SUBNET target types.
    # ---------------------------------------------------------
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

    # ---------------------------------------------------------
    # Scope containment check
    # ---------------------------------------------------------
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
                if not target_net.subnet_of(self._scope_network):
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

    # ---------------------------------------------------------
    # CIDR prefix sanity checks
    # ---------------------------------------------------------
    def _check_cidr_sanity(
        self, address_str: str, target_type: TargetType
    ) -> Tuple[bool, str]:
        if target_type != TargetType.SUBNET:
            return True, ""

        try:
            net = ipaddress.ip_network(address_str, strict=False)
            prefix = net.prefixlen

            # Prevent overly wide scans (small prefix = wide)
            if prefix < self.settings.max_cidr_prefix:
                return False, (
                    f"CIDR prefix /{prefix} is wider than the maximum "
                    f"allowed /{self.settings.max_cidr_prefix} for this "
                    f"engagement. This would scan "
                    f"{net.num_addresses:,} addresses."
                )

            # /32 is a single host — use IP type instead
            if isinstance(net, ipaddress.IPv4Network) and prefix == 32:
                return False, (
                    f"CIDR /32 ({address_str}) is a single host address. "
                    f"Use target type IP instead of SUBNET for host targets."
                )

            # IPv6 subnet must be at least /64
            if isinstance(net, ipaddress.IPv6Network) and prefix < 64:
                return False, (
                    f"IPv6 subnet /{prefix} is too large. "
                    f"Minimum allowed prefix is /64."
                )

        except ValueError:
            pass

        return True, ""

    # ---------------------------------------------------------
    # Type consistency — detect IP/SUBNET mismatches
    # ---------------------------------------------------------
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

    # ---------------------------------------------------------
    # Mode-aware violation handler
    # ---------------------------------------------------------
    def _handle(self, msg: str, vtype: str, warnings: List[str]) -> None:
        if self.settings.engagement_mode == "strict":
            raise NetworkValidationError(
                msg, field="target.value", validation_type=vtype
            )
        warnings.append(f"ARCH_WARNING: {msg}")

    # ---------------------------------------------------------
    # Main validation entry point
    # ---------------------------------------------------------
    def validate(
        self, schema: IntentSchema
    ) -> Tuple[IntentSchema, List[str]]:
        if self.settings.engagement_mode == "disabled":
            return schema, []

        warnings: List[str] = []

        # Step 1 — Type consistency (text-level)
        consistent, msg = self._check_target_type_consistency(schema)
        if not consistent:
            self._handle(msg, "type_consistency", warnings)

        # Steps 2-4 only apply to IP/SUBNET targets
        if schema.target.type in (TargetType.IP, TargetType.SUBNET):

            # Step 2 — Parse target to validate format
            try:
                parsed = self._parse_target(schema.target.value)
            except NetworkValidationError as e:
                self._handle(str(e), "format", warnings)
                return schema, warnings

            # Step 3 — Scope check
            in_scope, msg = self._is_in_scope(
                schema.target.value, schema.target.type
            )
            if not in_scope:
                if self.settings.engagement_mode == "strict":
                    raise NetworkValidationError(
                        msg, field="target.value", validation_type="scope"
                    )
                warnings.append(f"SCOPE_VIOLATION: {msg}")

            # Step 4 — CIDR sanity (subnets only)
            if schema.target.type == TargetType.SUBNET:
                sane, msg = self._check_cidr_sanity(
                    schema.target.value, schema.target.type
                )
                if not sane:
                    self._handle(msg, "cidr_sanity", warnings)

        self.logger.info(
            "network_architecture_validated",
            target=schema.target.value,
            target_type=schema.target.type.value,
            warnings=len(warnings),
            mode=self.settings.engagement_mode,
        )

        return schema, warnings
