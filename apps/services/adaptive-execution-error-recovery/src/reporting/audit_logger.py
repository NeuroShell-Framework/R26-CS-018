import sqlite3
import os
import json
import datetime
from dotenv import load_dotenv

load_dotenv()

DB_PATH = os.getenv('AUDIT_DB_PATH', './data/audit.db')

CREATE_SQL = '''
CREATE TABLE IF NOT EXISTS recovery_events (
    id                        INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id                TEXT NOT NULL,
    timestamp                 TEXT NOT NULL,
    attempt_number            INTEGER,
    original_command          TEXT,
    stderr                    TEXT,
    exit_code                 INTEGER,
    error_class               TEXT,
    classification_method     TEXT,
    classification_latency_ms REAL,
    strategy_applied          TEXT,
    corrected_command         TEXT,
    safety_approved           INTEGER,
    danger_words              TEXT,
    confidence                REAL,
    llm_reasoning             TEXT,
    outcome                   TEXT,
    total_latency_ms          REAL
);
CREATE INDEX IF NOT EXISTS idx_session ON recovery_events(session_id);
CREATE INDEX IF NOT EXISTS idx_error_class ON recovery_events(error_class);
PRAGMA journal_mode=WAL;
'''


def init_db(db_path: str = None):
    path = db_path or DB_PATH
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with sqlite3.connect(path) as conn:
        conn.executescript(CREATE_SQL)


def log_event(event: dict, db_path: str = None):
    """Append-only. Never updates or deletes existing rows."""
    path = db_path or DB_PATH
    with sqlite3.connect(path) as conn:
        conn.execute('''
            INSERT INTO recovery_events
            (session_id, timestamp, attempt_number, original_command, stderr,
             exit_code, error_class, classification_method, classification_latency_ms,
             strategy_applied, corrected_command, safety_approved, danger_words,
             confidence, llm_reasoning, outcome, total_latency_ms)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ''', (
            event.get('session_id'),
            datetime.datetime.now(datetime.timezone.utc).isoformat(),
            event.get('attempt_number'),
            event.get('original_command'),
            event.get('stderr', '')[:2000],
            event.get('exit_code'),
            event.get('error_class'),
            event.get('classification_method'),
            event.get('classification_latency_ms'),
            event.get('strategy_applied'),
            event.get('corrected_command'),
            1 if event.get('safety_approved') else 0,
            json.dumps(event.get('danger_words', [])),
            event.get('confidence'),
            event.get('llm_reasoning'),
            event.get('outcome'),
            event.get('total_latency_ms')
        ))
        conn.commit()


def query_session(session_id: str, db_path: str = None) -> list:
    """Return all events for a session, ordered by attempt."""
    path = db_path or DB_PATH
    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            'SELECT * FROM recovery_events WHERE session_id=? ORDER BY id',
            (session_id,)
        ).fetchall()
    return [dict(r) for r in rows]
