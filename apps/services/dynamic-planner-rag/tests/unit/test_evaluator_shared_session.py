import sys
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest
from scripts.evaluate_component import run_evaluation


@pytest.mark.parametrize("inject_manager", [False, True])
def test_default_client_uses_shared_or_explicit_session_manager(inject_manager):
    target = "192.168.1.50"
    api_manager = MagicMock()
    explicit_manager = MagicMock()
    manager = explicit_manager if inject_manager else api_manager
    manager.get_last_target.return_value = target

    fake_api = ModuleType("src.api.main")
    fake_api.app = object()
    fake_api.API_KEY = "test-key"
    fake_api.session_mgr = api_manager

    client = MagicMock()
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {
        "status": "success",
        "tool": "nmap",
        "command": "nmap -sS " + target,
        "validation_passed": True,
    }

    def post(*args, **kwargs):
        # Recovery setup must seed the same selected manager before the request.
        assert manager.update_session.called
        return response

    client.post.side_effect = post
    validator = MagicMock()
    validator.evaluate.return_value = {
        "target_preserved": True,
        "semantically_correct": True,
        "details": [],
    }
    case = {
        "id": "BENCH-024",
        "name": "Shared fallback recovery",
        "category": "session_recovery",
        "expect_success": True,
        "expected_tool": "nmap",
        "expected_semantics": {"target_value": target},
        "body": {
            "session_id": "shared-recovery",
            "intent_contract": {
                "intent": "NETWORK_SCAN",
                "target": {"type": "IP", "value": "UNKNOWN"},
                "modifiers": ["stealth"],
            },
        },
    }

    with (
        patch.dict(sys.modules, {"src.api.main": fake_api}),
        patch("fastapi.testclient.TestClient", return_value=client),
        patch(
            "src.session.session_context_manager.SessionContextManager",
            side_effect=AssertionError("Unexpected separate session manager"),
        ),
    ):
        metrics = run_evaluation(
            benchmark_cases=[case],
            verbose=False,
            validator=validator,
            session_mgr=explicit_manager if inject_manager else None,
            headers={"x-api-key": "test-key"},
        )

    assert manager.update_session.called
    assert manager.clear_session.called
    assert client.post.call_count == 1
    assert metrics["benchmark_summary"]["infrastructure_failures"] == 0
    if inject_manager:
        api_manager.update_session.assert_not_called()
