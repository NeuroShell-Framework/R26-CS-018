import pytest
from src.session.session_context_manager import SessionContextManager

def test_session_manager_target_recovery():
    mgr = SessionContextManager()
    session_id = "test-recovery-001"

    # Initially no target
    assert mgr.get_last_target(session_id) is None

    # Update session with valid target
    mgr.update_session(session_id, "nmap -sS 192.168.1.10", "nmap", "192.168.1.10")
    assert mgr.get_last_target(session_id) == "192.168.1.10"

    # Update with UNKNOWN should not overwrite last valid target
    mgr.update_session(session_id, "gobuster dir -u UNKNOWN", "gobuster", "UNKNOWN")
    assert mgr.get_last_target(session_id) == "192.168.1.10"

    # Clear session
    mgr.clear_session(session_id)
    assert mgr.get_last_target(session_id) is None
