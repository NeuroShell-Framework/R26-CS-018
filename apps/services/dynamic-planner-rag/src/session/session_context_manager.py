from __future__ import annotations

import json
import logging
import redis
from datetime import datetime
from dotenv import load_dotenv
import os

load_dotenv()

logger = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
SESSION_TTL = 3600

class SessionContextManager:

    def __init__(self):
        self.client = redis.from_url(REDIS_URL, socket_timeout=1.0, socket_connect_timeout=1.0)
        self._memory_fallback = {}
        print("SessionContextManager initialized")

    def get_session(self, session_id: str) -> dict:
        try:
            data = self.client.get(f"session:{session_id}")
            if data:
                return json.loads(data)
        except redis.RedisError as e:
            logger.warning(f"Redis unavailable in get_session ({e}). Returning fallback session.")
            if session_id in self._memory_fallback:
                return self._memory_fallback[session_id]

        return {
            "session_id"      : session_id,
            "targets_seen"    : [],
            "commands_run"    : [],
            "tools_used"      : [],
            "created_at"      : datetime.utcnow().isoformat(),
            "last_updated"    : datetime.utcnow().isoformat(),
        }

    def get_last_target(self, session_id: str) -> str | None:
        session = self.get_session(session_id)
        targets = session.get("targets_seen", [])
        valid_targets = [t for t in targets if t and t.upper() != "UNKNOWN"]
        return valid_targets[-1] if valid_targets else None

    def update_session(self, session_id: str, command: str, tool: str, target: str):
        session = self.get_session(session_id)
        
        if target and target.upper() != "UNKNOWN" and target not in session["targets_seen"]:
            session["targets_seen"].append(target)
        
        session["commands_run"].append(command)
        
        if tool not in session["tools_used"]:
            session["tools_used"].append(tool)
        
        session["last_updated"] = datetime.utcnow().isoformat()
        self._memory_fallback[session_id] = session

        try:
            self.client.setex(
                f"session:{session_id}",
                SESSION_TTL,
                json.dumps(session)
            )
        except redis.RedisError as e:
            logger.warning(f"Redis unavailable in update_session ({e}). Session state persisted in memory fallback.")

    def clear_session(self, session_id: str):
        self._memory_fallback.pop(session_id, None)
        try:
            self.client.delete(f"session:{session_id}")
        except redis.RedisError as e:
            logger.warning(f"Redis unavailable in clear_session ({e}). Key deletion bypassed.")





if __name__ == "__main__":
    mgr = SessionContextManager()

    mgr.update_session("test-123", "nmap -sS 192.168.1.1", "nmap", "192.168.1.1")
    mgr.update_session("test-123", "nikto -h 192.168.1.1", "nikto", "192.168.1.1")

    session = mgr.get_session("test-123")
    print(f"\nSession ID:    {session['session_id']}")
    print(f"Targets seen:  {session['targets_seen']}")
    print(f"Commands run:  {session['commands_run']}")
    print(f"Tools used:    {session['tools_used']}")

    mgr.clear_session("test-123")
    print("\nSession cleared!")