# NeuroShell IRE — Durable SQLite Audit Logger & Escalation Queue
# Append-only audit logger enforcing raw input hashing and escalation review queue

import os
import sqlite3
import hashlib
from datetime import datetime
from typing import List, Dict, Any, Optional
from config.settings import get_settings, Settings
from src.utils.logging_config import get_logger


class AuditLogger:
    """
    Append-only audit log manager using SQLite.
    Stores validation findings, hallucination classifications, and escalation queue.
    Privacy Guarantee: Never stores raw user input commands; stores SHA-256 hash only.
    """

    def __init__(self, db_path: Optional[str] = None, settings: Optional[Settings] = None):
        self.logger = get_logger(__name__)
        self.settings = settings or get_settings()
        self.db_path = db_path or self.settings.audit_db_path
        self._mem_conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        if self.db_path == ":memory:":
            if self._mem_conn is None:
                self._mem_conn = sqlite3.connect(":memory:", check_same_thread=False)
                self._mem_conn.row_factory = sqlite3.Row
            return self._mem_conn

        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Initialise audit_log table schema."""
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    session_id TEXT,
                    raw_input_hash TEXT NOT NULL,
                    intent_summary TEXT NOT NULL,
                    hallucination_class TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    enforcement_action TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'recorded',
                    resolved_by TEXT,
                    resolved_at TEXT,
                    resolution_note TEXT,
                    cached_contract_json TEXT
                );
                """
            )
            conn.commit()

    @staticmethod
    def hash_raw_input(raw_input: str) -> str:
        """Compute SHA-256 digest of raw input string to ensure privacy."""
        if not raw_input:
            raw_input = ""
        return hashlib.sha256(raw_input.encode("utf-8")).hexdigest()

    def record_finding(
        self,
        raw_input: str,
        intent_summary: str,
        hallucination_class: str,
        severity: str,
        enforcement_action: str,
        session_id: Optional[str] = None,
        status: str = "recorded",
        cached_contract_json: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> int:
        """
        Write an append-only row to the audit log.
        Raw input string is hashed prior to storage.
        """
        raw_hash = self.hash_raw_input(raw_input)
        ts = timestamp or (datetime.utcnow().isoformat() + "Z")

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO audit_log (
                    timestamp, session_id, raw_input_hash, intent_summary,
                    hallucination_class, severity, enforcement_action, status,
                    cached_contract_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    ts,
                    session_id,
                    raw_hash,
                    intent_summary,
                    str(hallucination_class),
                    str(severity),
                    str(enforcement_action),
                    status,
                    cached_contract_json,
                ),
            )
            conn.commit()
            row_id = cursor.lastrowid
            self.logger.info(
                "audit_finding_logged",
                audit_id=row_id,
                hallucination_class=hallucination_class,
                enforcement_action=enforcement_action,
                status=status,
            )
            return row_id

    def get_pending_escalations(self) -> List[Dict[str, Any]]:
        """Retrieve all escalation audit records with pending review status."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM audit_log
                WHERE status = 'pending' OR (enforcement_action = 'ESCALATE' AND status NOT IN ('approved', 'rejected'))
                ORDER BY id ASC;
                """
            )
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def get_escalation_by_id(self, audit_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve a single audit log row by ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_log WHERE id = ?;", (audit_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def resolve_escalation(
        self,
        audit_id: int,
        approve: bool,
        note: str,
        resolved_by: str = "admin",
    ) -> Optional[Dict[str, Any]]:
        """
        Resolve a pending escalation.
        Updates status to 'approved' or 'rejected' and sets resolution timestamp and notes.
        """
        record = self.get_escalation_by_id(audit_id)
        if not record:
            return None

        new_status = "approved" if approve else "rejected"
        resolved_at = datetime.utcnow().isoformat() + "Z"

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE audit_log
                SET status = ?, resolved_by = ?, resolved_at = ?, resolution_note = ?
                WHERE id = ?;
                """,
                (new_status, resolved_by, resolved_at, note, audit_id),
            )
            conn.commit()

        updated_record = self.get_escalation_by_id(audit_id)
        self.logger.info(
            "escalation_resolved",
            audit_id=audit_id,
            status=new_status,
            resolved_by=resolved_by,
        )
        return updated_record

    def get_audit_summary(
        self, start_time: Optional[str] = None, end_time: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Aggregate count summary by hallucination_class and enforcement_action.
        Used for reporting and dashboard visualization.
        """
        query = "SELECT hallucination_class, enforcement_action, status FROM audit_log WHERE 1=1"
        params = []
        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time)
        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()

        by_hallucination: Dict[str, int] = {}
        by_enforcement: Dict[str, int] = {}
        pending_count = 0

        for row in rows:
            h_class = row["hallucination_class"]
            enf_action = row["enforcement_action"]
            st = row["status"]

            by_hallucination[h_class] = by_hallucination.get(h_class, 0) + 1
            by_enforcement[enf_action] = by_enforcement.get(enf_action, 0) + 1
            if st == "pending" or (enf_action == "ESCALATE" and st not in ("approved", "rejected")):
                pending_count += 1

        return {
            "total_records": len(rows),
            "by_hallucination_class": by_hallucination,
            "by_enforcement_action": by_enforcement,
            "pending_escalation_count": pending_count,
        }


_audit_logger_instance: Optional[AuditLogger] = None


def get_audit_logger(
    db_path: Optional[str] = None, settings: Optional[Settings] = None
) -> AuditLogger:
    global _audit_logger_instance
    if db_path is not None or settings is not None:
        return AuditLogger(db_path=db_path, settings=settings)
    if _audit_logger_instance is None:
        _audit_logger_instance = AuditLogger()
    return _audit_logger_instance
