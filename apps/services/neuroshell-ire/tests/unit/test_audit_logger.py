# NeuroShell IRE — Unit Tests for Durable SQLite Audit Logger

import sqlite3
import pytest
from src.audit.audit_logger import AuditLogger, get_audit_logger


@pytest.fixture
def audit_logger():
    """Returns an in-memory AuditLogger instance for test isolation."""
    return AuditLogger(db_path=":memory:")


def test_audit_logger_initialization(audit_logger):
    """Schema is created with audit_log table."""
    with audit_logger._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_log';")
        assert cursor.fetchone() is not None


def test_audit_logger_privacy_assertion_raw_input_never_stored(audit_logger):
    """
    CRITICAL PRIVACY TEST:
    Raw command input text must NEVER appear anywhere in the database.
    Only its SHA-256 hash is recorded.
    """
    raw_command = "nmap -sS -p 445 --script vuln 192.168.1.100 SUPER_SECRET_TOKEN_98765"
    row_id = audit_logger.record_finding(
        raw_input=raw_command,
        intent_summary="NETWORK_SCAN on 192.168.1.100",
        hallucination_class="OUT_OF_SCOPE_TARGET",
        severity="block",
        enforcement_action="BLOCK",
        session_id="test-session-123",
    )

    # 1. Inspect the stored row
    row = audit_logger.get_escalation_by_id(row_id)
    assert row is not None
    assert row["raw_input_hash"] == audit_logger.hash_raw_input(raw_command)
    assert raw_command not in row["raw_input_hash"]

    # 2. Dump all text in the entire SQLite database and explicitly assert raw command is absent
    with audit_logger._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM audit_log WHERE id = ?;", (row_id,))
        record_values = [str(val) for val in cursor.fetchone()]
        combined_text = " ".join(record_values)
        assert raw_command not in combined_text
        assert "SUPER_SECRET_TOKEN_98765" not in combined_text


def test_record_finding_creates_row(audit_logger):
    """record_finding creates an audit row with correct metadata."""
    row_id = audit_logger.record_finding(
        raw_input="scan 10.0.0.1",
        intent_summary="NETWORK_SCAN on 10.0.0.1",
        hallucination_class="OUT_OF_SCOPE_TARGET",
        severity="warn",
        enforcement_action="WARN",
        session_id="sess-1",
    )
    assert row_id == 1
    row = audit_logger.get_escalation_by_id(1)
    assert row["hallucination_class"] == "OUT_OF_SCOPE_TARGET"
    assert row["severity"] == "warn"
    assert row["enforcement_action"] == "WARN"
    assert row["status"] == "recorded"


def test_escalation_queue_and_resolution(audit_logger):
    """Pending escalations are retrieved and resolved with approval/rejection notes."""
    # Insert pending escalation row
    row_id = audit_logger.record_finding(
        raw_input="exploit 10.0.0.1",
        intent_summary="EXPLOITATION on 10.0.0.1",
        hallucination_class="CONTRADICTORY_ACTION_TARGET",
        severity="escalate",
        enforcement_action="ESCALATE",
        session_id="sess-escalate",
        status="pending",
        cached_contract_json='{"intent": "EXPLOITATION", "target": "10.0.0.1"}',
    )

    pending = audit_logger.get_pending_escalations()
    assert len(pending) == 1
    assert pending[0]["id"] == row_id
    assert pending[0]["status"] == "pending"

    # Resolve with approve=True
    updated = audit_logger.resolve_escalation(
        audit_id=row_id,
        approve=True,
        note="Approved by security officer after authorization check",
        resolved_by="lead_auditor",
    )
    assert updated["status"] == "approved"
    assert updated["resolved_by"] == "lead_auditor"
    assert updated["resolved_at"] is not None
    assert "security officer" in updated["resolution_note"]

    # Verify pending queue is now empty
    pending_after = audit_logger.get_pending_escalations()
    assert len(pending_after) == 0


def test_get_audit_summary_counts(audit_logger):
    """get_audit_summary correctly aggregates finding counts."""
    audit_logger.record_finding("cmd1", "summary1", "FABRICATED_PARAMETER", "block", "BLOCK")
    audit_logger.record_finding("cmd2", "summary2", "FABRICATED_PARAMETER", "block", "BLOCK")
    audit_logger.record_finding("cmd3", "summary3", "UNGROUNDED_CONFIDENCE", "warn", "WARN")
    audit_logger.record_finding("cmd4", "summary4", "OUT_OF_SCOPE_TARGET", "escalate", "ESCALATE", status="pending")

    summary = audit_logger.get_audit_summary()
    assert summary["total_records"] == 4
    assert summary["by_hallucination_class"]["FABRICATED_PARAMETER"] == 2
    assert summary["by_hallucination_class"]["UNGROUNDED_CONFIDENCE"] == 1
    assert summary["by_hallucination_class"]["OUT_OF_SCOPE_TARGET"] == 1
    assert summary["by_enforcement_action"]["BLOCK"] == 2
    assert summary["by_enforcement_action"]["WARN"] == 1
    assert summary["by_enforcement_action"]["ESCALATE"] == 1
    assert summary["pending_escalation_count"] == 1
