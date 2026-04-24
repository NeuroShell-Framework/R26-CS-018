from typing import Dict, List, Set
from src.schemas.intent_schema import IntentType

ROLES_HIERARCHY = ["viewer", "analyst", "operator", "admin"]
# Higher index = more permissions
# viewer   : read-only, no active operations
# analyst  : passive recon, network scan only
# operator : all non-destructive operations
# admin    : all operations including exploitation

INTENT_ROLE_POLICY: Dict[IntentType, List[str]] = {
    IntentType.NETWORK_SCAN: ["analyst", "operator", "admin"],
    IntentType.VULNERABILITY_AUDIT: ["analyst", "operator", "admin"],
    IntentType.DIRECTORY_BRUTEFORCE: ["operator", "admin"],
    IntentType.SERVICE_ENUMERATION: ["analyst", "operator", "admin"],
    IntentType.EXPLOITATION: ["operator", "admin"],
    IntentType.PASSWORD_ATTACK: ["operator", "admin"],
    IntentType.PASSIVE_RECON: ["analyst", "operator", "admin"],
    IntentType.AMBIGUOUS: ["analyst", "operator", "admin"],
    IntentType.REJECTED: ["analyst", "operator", "admin"],
}

# Intents that require at least operator role
SENSITIVE_INTENTS: Set[IntentType] = {
    IntentType.EXPLOITATION,
    IntentType.PASSWORD_ATTACK,
    IntentType.DIRECTORY_BRUTEFORCE,
}

# Roles that can NEVER access sensitive intents (pre-inference fast-fail)
RESTRICTED_ROLES: Set[str] = {"viewer"}


def is_role_permitted(role: str, intent: IntentType) -> bool:
    """
    Returns True if the given role is permitted to invoke the given intent.
    Unknown roles are treated as viewer (most restrictive).
    """
    permitted_roles = INTENT_ROLE_POLICY.get(intent, [])
    return role in permitted_roles


def get_role_index(role: str) -> int:
    """
    Returns the hierarchy index of a role.
    Unknown roles return -1 (least privileged).
    """
    try:
        return ROLES_HIERARCHY.index(role)
    except ValueError:
        return -1


def get_permitted_intents(role: str) -> List[IntentType]:
    """
    Returns the list of IntentTypes permitted for a given role.
    """
    return [
        intent for intent, roles in INTENT_ROLE_POLICY.items()
        if role in roles
    ]
