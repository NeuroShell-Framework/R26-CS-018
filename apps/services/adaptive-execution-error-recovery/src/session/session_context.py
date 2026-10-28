import json
import os
import redis
from dotenv import load_dotenv

load_dotenv()

REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379')
SESSION_TTL = 3600  # 1 hour


class SessionContext:

    def __init__(self):
        try:
            self.r = redis.from_url(REDIS_URL, decode_responses=True)
            self.r.ping()
            self.available = True
        except Exception:
            self.available = False
            print('WARNING: Redis unavailable — running stateless')

    def _key(self, session_id: str) -> str:
        return f'neuroshell:session:{session_id}'

    def get(self, session_id: str) -> dict:
        if not self.available:
            return {}
        try:
            raw = self.r.get(self._key(session_id))
            return json.loads(raw) if raw else {}
        except Exception:
            return {}

    def update(self, session_id: str, command: str, tool: str,
               target: str, strategy: str):
        if not self.available:
            return
        try:
            ctx = self.get(session_id)
            ctx.setdefault('commands_run', []).append(command)
            ctx.setdefault('tools_used', []).append(tool)
            if strategy:
                ctx.setdefault('prior_strategies', []).append(strategy)
            if target and target not in ctx.get('targets_seen', []):
                ctx.setdefault('targets_seen', []).append(target)
            self.r.setex(
                self._key(session_id),
                SESSION_TTL,
                json.dumps(ctx)
            )
        except Exception:
            pass

    def get_prior_strategies(self, session_id: str) -> list:
        return self.get(session_id).get('prior_strategies', [])

    def clear(self, session_id: str):
        if not self.available:
            return
        try:
            self.r.delete(self._key(session_id))
        except Exception:
            pass

    def exists(self, session_id: str) -> bool:
        if not self.available:
            return False
        try:
            return self.r.exists(self._key(session_id)) == 1
        except Exception:
            return False
