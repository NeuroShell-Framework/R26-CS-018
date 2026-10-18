import re
import urllib.parse
import ipaddress
from typing import Tuple, List

BLOCKED_PATTERNS = [
    r"rm\s+-rf",
    r"mkfs",
    r"dd\s+if=",
    r":\(\)\{:\|:&\};:",
    r"chmod\s+777\s+/",
    r"> /dev/sd",
    r"wget.+\|\s*bash",
    r"curl.+\|\s*bash",
    r"nc\s+-e\s+/bin",
    r"bash\s+-i\s+>&",
]

ALLOWED_NETWORKS_V4 = [
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("127.0.0.0/8"),
]

ALLOWED_TOOLS = [
    "nmap", "nikto", "gobuster",
    "hydra", "metasploit", "whois",
    "dig", "curl", "wget"
]


class SafetyFilter:

    def validate(self, command: str, target: str) -> Tuple[bool, List[str]]:
        flags = []

        for pattern in BLOCKED_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                flags.append(f"BLOCKED: dangerous pattern detected: {pattern}")
                return False, flags

        if not self._is_allowed_target(target):
            flags.append(f"BLOCKED: target {target} is not RFC-1918 private range")
            return False, flags

        tool = command.split()[0] if command else ""
        if tool not in ALLOWED_TOOLS:
            flags.append(f"WARNING: tool '{tool}' not in approved list")

        return True, flags

    def _is_allowed_target(self, target: str) -> bool:
        if not target or not isinstance(target, str):
            return False

        raw_target = target.strip()
        if not raw_target:
            return False

        if raw_target.count('"') % 2 != 0 or raw_target.count("'") % 2 != 0:
            return False

        raw_target = raw_target.strip("\"'")

        # Explicit plain localhost check
        if raw_target.lower() in ["localhost", "127.0.0.1"]:
            return True

        # 1. Pure IPv4 single address check
        try:
            ip_obj = ipaddress.ip_address(raw_target)
            if ip_obj.version == 4:
                return any(ip_obj in net for net in ALLOWED_NETWORKS_V4)
            return False
        except ValueError:
            pass

        # 2. Perform URL & Host:Port checks BEFORE CIDR parsing
        is_url_or_hostport = (
            "://" in raw_target
            or raw_target.startswith("http://")
            or raw_target.startswith("https://")
            or "/" in raw_target
            or ":" in raw_target
        )

        is_cidr_syntax = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$", raw_target))

        if is_url_or_hostport and not is_cidr_syntax:
            try:
                url_to_parse = raw_target
                if not (url_to_parse.startswith("http://") or url_to_parse.startswith("https://")):
                    if "://" in url_to_parse:
                        scheme_part = url_to_parse.split("://")[0].lower()
                        if scheme_part not in ["http", "https"]:
                            return False
                    url_to_parse = f"http://{url_to_parse}"

                parsed = urllib.parse.urlsplit(url_to_parse)
                if parsed.scheme and parsed.scheme.lower() not in ["http", "https"]:
                    return False

                host = parsed.hostname
                if not host:
                    return False

                port = parsed.port  # urlsplit.port raises ValueError on malformed ports
                if port is not None and (port < 1 or port > 65535):
                    return False

            except ValueError:
                return False

            if host.lower() in ["localhost", "127.0.0.1"]:
                return True

            try:
                ip_obj = ipaddress.ip_address(host)
                if ip_obj.version == 4:
                    return any(ip_obj in net for net in ALLOWED_NETWORKS_V4)
                return False
            except ValueError:
                pass

            return False

        # 3. CIDR network parsing
        try:
            net_obj = ipaddress.ip_network(raw_target, strict=False)
            if net_obj.version == 4:
                return any(net_obj.subnet_of(net) for net in ALLOWED_NETWORKS_V4)
            return False
        except ValueError:
            pass

        return False


if __name__ == "__main__":
    sf = SafetyFilter()

    tests = [
        ("nmap -sS 192.168.1.1", "192.168.1.1"),
        ("rm -rf /", "192.168.1.1"),
        ("nmap -sS 8.8.8.8", "8.8.8.8"),
        ("nikto -h 10.0.0.1", "10.0.0.1"),
    ]

    for cmd, target in tests:
        passed, flags = sf.validate(cmd, target)
        print(f"\nCommand: {cmd}")
        print(f"Target:  {target}")
        print(f"Passed:  {passed}")
        print(f"Flags:   {flags}")