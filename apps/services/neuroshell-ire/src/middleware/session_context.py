import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from config.feature_flags import get_feature_flags
from src.schemas.intent_schema import IREResponse, IntentType, TargetType
from src.utils.logging_config import get_logger


@dataclass
class SessionTurn:
    """Represents one completed turn in a session."""
    turn_number: int
    command: str
    intent: str
    target_type: str
    target_value: str
    ports: List[int]
    cve_ids: List[str]
    confidence: float
    timestamp: float = field(default_factory=time.time)

    def to_context_line(self) -> str:
        """
        Produces a compact single-line context annotation.
        Example:
          [Turn 1] NETWORK_SCAN on SUBNET "192.168.1.0/24" ports=[22,80]
        """
        parts = [f"[Turn {self.turn_number}]", self.intent,
                 "on", self.target_type, f'"{self.target_value}"']
        if self.ports:
            parts.append(f"ports={self.ports}")
        if self.cve_ids:
            parts.append(f"cves={self.cve_ids}")
        return " ".join(str(p) for p in parts)


@dataclass
class Session:
    """Holds all turns for one session_id."""
    session_id: str
    turns: List[SessionTurn] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    last_active: float = field(default_factory=time.time)

    def add_turn(self, turn: SessionTurn) -> None:
        self.turns.append(turn)
        self.last_active = time.time()

    def get_recent_turns(self, max_turns: int) -> List[SessionTurn]:
        """Returns the last N turns, most recent last."""
        return self.turns[-max_turns:]

    def is_expired(self, ttl_seconds: float) -> bool:
        return (time.time() - self.last_active) > ttl_seconds

    @property
    def turn_count(self) -> int:
        return len(self.turns)

    def get_last_target(self) -> Optional[Tuple[str, str]]:
        """
        Returns (target_type, target_value) of the most recent
        successful turn, or None if no turns exist.
        """
        for turn in reversed(self.turns):
            if turn.target_value and turn.target_value != "":
                return (turn.target_type, turn.target_value)
        return None


class SessionContextStore:
    def __init__(self):
        self.logger = get_logger(__name__)
        self.flags = get_feature_flags()
        self._sessions: Dict[str, Session] = {}
        self._max_turns = self.flags.get_tuning("session_max_turns", 8)
        self._max_sessions = self.flags.get_tuning("session_max_sessions", 1024)
        self._ttl_seconds = self.flags.get_tuning("session_ttl_minutes", 30) * 60
        self.logger.info(
            "session_context_store_initialized",
            extra={"max_turns": self._max_turns, "ttl_seconds": self._ttl_seconds}
        )

    def _evict_expired(self) -> int:
        """Remove all sessions past TTL. Returns count evicted."""
        expired = [
            sid for sid, session in self._sessions.items()
            if session.is_expired(self._ttl_seconds)
        ]
        for sid in expired:
            del self._sessions[sid]
        if expired:
            self.logger.debug("sessions_evicted", extra={"count": len(expired)})
        return len(expired)

    def _get_or_create_session(self, session_id: str) -> Session:
        """
        Returns existing session or creates a new one.
        Evicts expired sessions before creating new ones.
        If at capacity, evict oldest by last_active.
        """
        if session_id in self._sessions:
            session = self._sessions[session_id]
            if session.is_expired(self._ttl_seconds):
                del self._sessions[session_id]
            else:
                return session

        self._evict_expired()

        if len(self._sessions) >= self._max_sessions:
            # Evict least recently used session
            oldest_id = min(
                self._sessions.keys(),
                key=lambda k: self._sessions[k].last_active
            )
            del self._sessions[oldest_id]
            self.logger.warning("session_lru_eviction", extra={"evicted": oldest_id})

        session = Session(session_id=session_id)
        self._sessions[session_id] = session
        return session

    def inject_context(self, command: str, session_id: Optional[str]) -> str:
        """
        Stage1 — called BEFORE input normalization.

        If session_context feature is disabled OR session_id is None:
          return command unchanged.

        Otherwise:
          1. Get recent turns for this session (up to max_turns)
          2. If no prior turns: return command unchanged
          3. Build context prefix:
               "Session context:\n"
               + one line per recent turn (turn.to_context_line())
               + "\nCurrent command: "
               + command
          4. Log debug: event="context_injected",
                        session_id=session_id,
                        turns_injected=N
          5. Return the prefixed string
        """
        if not self.flags.session_context or not session_id:
            return command

        session = self._get_or_create_session(session_id)
        recent = session.get_recent_turns(self._max_turns)

        if not recent:
            return command

        context_lines = [t.to_context_line() for t in recent]
        context_prefix = (
            "Session context:\n"
            + "\n".join(context_lines)
            + "\nCurrent command: "
        )
        enriched = context_prefix + command

        self.logger.debug(
            "context_injected",
            extra={"session_id": session_id, "turns_injected": len(recent)}
        )
        return enriched

    def update(self, session_id: Optional[str], command: str, response: IREResponse) -> None:
        """
        Stage 2 — called AFTER a successful pipeline parse.

        If session_context disabled OR session_id is None
        OR response.status != "success": return immediately.

        Otherwise:
          1. Get or create session
          2. Build SessionTurn from response fields
          3. Add to session
          4. Log debug: event="session_updated",
                        session_id=session_id,
                        turn=session.turn_count,
                        intent=response.intent.value
        """
        if not self.flags.session_context:
            return
        if not session_id or not response or response.status != "success":
            return

        session = self._get_or_create_session(session_id)

        turn = SessionTurn(
            turn_number=session.turn_count + 1,
            command=command,
            intent=response.intent.value if response.intent else "UNKNOWN",
            target_type=response.target.type.value if response.target else "UNKNOWN",
            target_value=response.target.value if response.target else "",
            ports=response.ports or [],
            cve_ids=response.cve_ids or [],
            confidence=response.confidence or 0.0,
        )

        session.add_turn(turn)

        self.logger.debug(
            "session_updated",
            extra={"session_id": session_id, "turn": session.turn_count, "intent": turn.intent}
        )

    def get_session_info(self, session_id: str) -> Optional[dict]:
        """Returns session metadata for API responses."""
        if session_id not in self._sessions:
            return None
        session = self._sessions[session_id]
        last_target = session.get_last_target()
        return {
            "session_id": session_id,
            "turn_count": session.turn_count,
            "last_target": last_target,
            "age_seconds": int(time.time() - session.created_at),
        }

    def clear_session(self, session_id: str) -> bool:
        """Clears a specific session. Returns True if it existed."""
        if session_id in self._sessions:
            del self._sessions[session_id]
            self.logger.info("session_cleared", extra={"session_id": session_id})
            return True
        return False

    def get_stats(self) -> dict:
        """Returns store-level statistics."""
        self._evict_expired()
        return {
            "active_sessions": len(self._sessions),
            "max_sessions": self._max_sessions,
            "ttl_seconds": self._ttl_seconds,
            "feature_enabled": self.flags.session_context,
        }
