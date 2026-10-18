import re
import ipaddress
from src.schemas.models import RecoveryPlan, SafetyCheckResult

# Layer 2: Danger patterns â€” NEVER allow these in any corrected command
DANGER_PATTERNS = [
    r'rm\s+-rf',
    r'rm\s+-fr',
    r'mkfs\.',
    r'dd\s+if=',
    r'wget[^\n]+\|[^\n]+sh',
    r'curl[^\n]+\|[^\n]+bash',
    r'nc\s+-e\s+/bin',
    r'bash\s+-i\s+>&',
    r'>/etc/passwd',
    r'>/etc/shadow',
    r'cat\s+/etc/shadow',
    r'chmod\s+(-[a-zA-Z]+\s+)*(777|000|666)\s+/',
    r'chmod\s+-[a-zA-Z]*R[a-zA-Z]*\s+\S+\s+/\s*$',
    r':\(\)\{.*\}',        # fork bomb
    r'shred\s+',
    r'wipefs\s+',
]

COMPILED_DANGER = [re.compile(p, re.IGNORECASE) for p in DANGER_PATTERNS]

# Layer 3: Only RFC-1918 private IP ranges are in scope
PRIVATE_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
]


def _extract_targets(command: str) -> list:
    """Extract potential targets (IPs and hostnames) from a command."""
    # Match literal IPs
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', command)
    
    # Match domain-like strings (e.g., example.com, test.local, http://target)
    # Restricted to common TLDs to avoid matching filenames like 'common.txt'
    domains = re.findall(r'\b([a-zA-Z0-9.-]+\.(?:com|net|org|edu|gov|io|co|uk|local))\b', command, re.IGNORECASE)
    
    return ips + domains


def validate(corrected_command: str, plan: RecoveryPlan) -> SafetyCheckResult:

    # Layer 1: Basic sanity â€” command must not be empty
    if not corrected_command or not corrected_command.strip():
        return SafetyCheckResult(
            approved=False,
            reason='Corrected command is empty'
        )

    # Layer 2: Danger word check
    danger_found = []
    for pattern in COMPILED_DANGER:
        match = pattern.search(corrected_command)
        if match:
            danger_found.append(match.group())

    if danger_found:
        return SafetyCheckResult(
            approved=False,
            danger_words_found=danger_found,
            reason=f'Danger patterns detected: {danger_found}'
        )

    # Layer 3: Confidence threshold check
    if plan.confidence < 0.60:
        return SafetyCheckResult(
            approved=False,
            confidence_too_low=True,
            reason=f'Confidence {plan.confidence:.2f} is below 0.60 threshold'
        )

    # Layer 4: Scope check â€” all targets must be RFC-1918 IPs or localhost
    targets = _extract_targets(corrected_command)
    for target in targets:
        # Allow literal 'localhost'
        if target.lower() == 'localhost':
            continue
            
        try:
            ip = ipaddress.ip_address(target)
            if not any(ip in net for net in PRIVATE_NETWORKS):
                return SafetyCheckResult(
                    approved=False,
                    scope_violation=True,
                    reason=f'Public IP found in corrected command: {target}'
                )
        except ValueError:
            # If it's not a valid IP and not localhost, it's an unapproved hostname
            return SafetyCheckResult(
                approved=False,
                scope_violation=True,
                reason=f'Unapproved hostname found in corrected command (must use raw private IPs): {target}'
            )

    return SafetyCheckResult(approved=True, reason='All safety checks passed')
