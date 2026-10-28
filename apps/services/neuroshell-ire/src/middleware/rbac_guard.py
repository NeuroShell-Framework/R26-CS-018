from config.rbac_policy import (
    is_role_permitted, RESTRICTED_ROLES,
    SENSITIVE_INTENTS, get_permitted_intents
)
from config.feature_flags import get_feature_flags
from src.schemas.intent_schema import (
    IntentType, IREResponseV2, RBACError, ParseRequestV2
)
from src.utils.logging_config import get_logger


class RBACGuard:
    def __init__(self):
        self.logger = get_logger(__name__)
        self.flags = get_feature_flags()
        self.logger.info(
            "rbac_guard_initialized",
            extra={"enabled": self.flags.rbac}
        )

    def pre_inference_check(self, role: str) -> None:
        """
        Phase 1: Fast check BEFORE inference.
        Blocks roles in RESTRICTED_ROLES from accessing
        any sensitive intents at all.
        Raises RBACError immediately.
        """
        if not self.flags.rbac:
            return  # feature disabled — complete no-op

        if role in RESTRICTED_ROLES:
            self.logger.warning(
                "rbac_pre_inference_blocked",
                extra={"role": role, "reason": "restricted_role"}
            )
            raise RBACError(
                f"Role '{role}' is not permitted to use the IRE.",
                role=role,
                intent="ANY"
            )

    def post_inference_check(self, role: str, intent: IntentType) -> None:
        """
        Phase 2: Fine-grained check AFTER inference.
        Checks detected intent against the role policy table.
        Raises RBACError if not permitted.
        """
        if not self.flags.rbac:
            return  # feature disabled — complete no-op

        if not is_role_permitted(role, intent):
            permitted = get_permitted_intents(role)
            self.logger.warning(
                "rbac_post_inference_blocked",
                extra={
                    "role": role,
                    "intent": intent.value,
                    "permitted_intents": [i.value for i in permitted]
                }
            )
            raise RBACError(
                f"Role '{role}' is not permitted to invoke "
                f"'{intent.value}' intents. "
                f"Permitted intents for this role: "
                f"{[i.value for i in permitted]}",
                role=role,
                intent=intent.value
            )

        self.logger.debug(
            "rbac_check_passed",
            extra={"role": role, "intent": intent.value}
        )

    def get_role_summary(self, role: str) -> dict:
        """
        Returns a summary of what a role is permitted to do.
        Used by GET /admin/rbac/{role} endpoint (future).
        """
        return {
            "role": role,
            "permitted_intents": [
                i.value for i in get_permitted_intents(role)
            ],
            "rbac_enabled": self.flags.rbac,
        }
