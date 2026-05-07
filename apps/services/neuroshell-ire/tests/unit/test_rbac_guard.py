import pytest
from unittest.mock import patch
from src.middleware.rbac_guard import RBACGuard
from src.schemas.intent_schema import IntentType, RBACError


@pytest.fixture
def guard():
    return RBACGuard()


@pytest.fixture
def guard_disabled():
    with patch("src.middleware.rbac_guard.get_feature_flags") as mock:
        mock.return_value.rbac = False
        return RBACGuard()


class TestRBACGuardPreInferenceCheck:

    def test_viewer_role_raises_rbac_error(self, guard):
        """viewer role is blocked at pre-inference check."""
        with pytest.raises(RBACError) as exc_info:
            guard.pre_inference_check("viewer")
        assert exc_info.value.role == "viewer"

    def test_analyst_role_passes_pre_inference(self, guard):
        """analyst role passes pre-inference check without error."""
        guard.pre_inference_check("analyst")

    def test_operator_role_passes_pre_inference(self, guard):
        """operator role passes pre-inference check without error."""
        guard.pre_inference_check("operator")

    def test_admin_role_passes_pre_inference(self, guard):
        """admin role passes pre-inference check without error."""
        guard.pre_inference_check("admin")

    def test_unknown_role_passes_pre_inference(self, guard):
        """unknown roles are not in RESTRICTED_ROLES and pass pre-inference."""
        guard.pre_inference_check("some_random_role")

    def test_pre_inference_disabled_is_noop(self, guard_disabled):
        """pre-inference check is a no-op when RBAC feature flag is disabled."""
        guard_disabled.pre_inference_check("viewer")


class TestRBACGuardPostInferenceCheck:

    def test_analyst_network_scan_passes(self, guard):
        """analyst role is permitted for NETWORK_SCAN intent."""
        guard.post_inference_check("analyst", IntentType.NETWORK_SCAN)

    def test_analyst_exploitation_raises_rbac_error(self, guard):
        """analyst role is NOT permitted for EXPLOITATION intent."""
        with pytest.raises(RBACError) as exc_info:
            guard.post_inference_check("analyst", IntentType.EXPLOITATION)
        assert exc_info.value.role == "analyst"
        assert exc_info.value.denied_intent == "EXPLOITATION"

    def test_operator_exploitation_passes(self, guard):
        """operator role is permitted for EXPLOITATION intent."""
        guard.post_inference_check("operator", IntentType.EXPLOITATION)

    def test_operator_password_attack_passes(self, guard):
        """operator role is permitted for PASSWORD_ATTACK intent."""
        guard.post_inference_check("operator", IntentType.PASSWORD_ATTACK)

    def test_admin_all_intents_pass(self, guard):
        """admin role is permitted for all intents including exploitation."""
        for intent in IntentType:
            guard.post_inference_check("admin", intent)

    def test_viewer_exploitation_raises_rbac_error(self, guard):
        """viewer role is NOT permitted for EXPLOITATION intent."""
        with pytest.raises(RBACError) as exc_info:
            guard.post_inference_check("viewer", IntentType.EXPLOITATION)
        assert exc_info.value.denied_intent == "EXPLOITATION"

    def test_analyst_passive_recon_passes(self, guard):
        """analyst role is permitted for PASSIVE_RECON intent."""
        guard.post_inference_check("analyst", IntentType.PASSIVE_RECON)

    def test_analyst_directory_bruteforce_raises(self, guard):
        """analyst role is NOT permitted for DIRECTORY_BRUTEFORCE intent."""
        with pytest.raises(RBACError):
            guard.post_inference_check("analyst", IntentType.DIRECTORY_BRUTEFORCE)

    def test_operator_directory_bruteforce_passes(self, guard):
        """operator role is permitted for DIRECTORY_BRUTEFORCE intent."""
        guard.post_inference_check("operator", IntentType.DIRECTORY_BRUTEFORCE)

    def test_unknown_role_rejected_passes(self, guard):
        """unknown roles get denied for REJECTED intent since they have no mapping."""
        with pytest.raises(RBACError):
            guard.post_inference_check("unknown_user", IntentType.NETWORK_SCAN)

    def test_post_inference_disabled_is_noop(self, guard_disabled):
        """post-inference check is a no-op when RBAC feature flag is disabled."""
        guard_disabled.post_inference_check("viewer", IntentType.EXPLOITATION)


class TestRBACGuardGetRoleSummary:

    def test_analyst_summary_contains_network_scan(self, guard):
        """analyst role summary includes NETWORK_SCAN."""
        summary = guard.get_role_summary("analyst")
        assert summary["role"] == "analyst"
        assert "NETWORK_SCAN" in summary["permitted_intents"]

    def test_analyst_summary_excludes_exploitation(self, guard):
        """analyst role summary excludes EXPLOITATION."""
        summary = guard.get_role_summary("analyst")
        assert "EXPLOITATION" not in summary["permitted_intents"]

    def test_admin_summary_contains_exploitation(self, guard):
        """admin role summary includes EXPLOITATION."""
        summary = guard.get_role_summary("admin")
        assert "EXPLOITATION" in summary["permitted_intents"]

    def test_admin_summary_contains_all_intents(self, guard):
        """admin role summary includes all intents from the policy."""
        summary = guard.get_role_summary("admin")
        permitted = summary["permitted_intents"]
        assert "NETWORK_SCAN" in permitted
        assert "VULNERABILITY_AUDIT" in permitted
        assert "EXPLOITATION" in permitted
        assert "PASSWORD_ATTACK" in permitted
        assert "DIRECTORY_BRUTEFORCE" in permitted
        assert "SERVICE_ENUMERATION" in permitted
        assert "PASSIVE_RECON" in permitted

    def test_viewer_summary_excludes_all_active_intents(self, guard):
        """viewer role summary excludes all active operation intents."""
        summary = guard.get_role_summary("viewer")
        active = ["NETWORK_SCAN", "EXPLOITATION", "PASSWORD_ATTACK", "DIRECTORY_BRUTEFORCE"]
        for intent in active:
            assert intent not in summary["permitted_intents"]

    def test_rbac_enabled_flag_in_summary(self, guard):
        """role summary includes rbac_enabled boolean."""
        summary = guard.get_role_summary("operator")
        assert "rbac_enabled" in summary
        assert isinstance(summary["rbac_enabled"], bool)

    def test_unknown_role_returns_empty_intents(self, guard):
        """unknown role returns empty permitted_intents list."""
        summary = guard.get_role_summary("nonexistent_role")
        assert summary["role"] == "nonexistent_role"
        assert summary["permitted_intents"] == []
