"""Persistent, disk-backed cache for full /execute chain flows.

Each entry stores the complete C1->C2->C3->C4 flow response for a given
natural-language command. The cache file survives service restarts, so an
identical user input short-circuits the whole chain (parse + plan + execution
+ analysis) on subsequent runs.

Storage layout:
    {
        "<sha256(normalized command)>": {
            "command": "...original input...",
            "flow": { ...full /execute content dict... },
            "created": "ISO-8601",
            "hit_count": int
        },
        ...
    }
"""

import hashlib
import json
import os
import re
import threading
import time
from copy import deepcopy
from pathlib import Path
from typing import Optional

SERVICE_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_CACHE_FILE = SERVICE_ROOT / "data" / "chain_cache.json"


def normalize_command(command: str) -> str:
    return re.sub(r"\s+", " ", command.strip().lower())


def command_key(command: str) -> str:
    return hashlib.sha256(normalize_command(command).encode("utf-8")).hexdigest()


class ChainCache:
    def __init__(
        self,
        path: Optional[Path] = None,
        max_entries: int = 200,
        version: str = "1.0.0",
    ):
        self.path = Path(path) if path else DEFAULT_CACHE_FILE
        self.max_entries = max_entries
        self.version = version
        self._lock = threading.Lock()
        self._data: dict = {}
        self._stats = {"hits": 0, "misses": 0, "loads": 0, "version": version}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8-sig"))
        except Exception:
            return
        entries = payload.get("entries") if isinstance(payload, dict) else payload
        if not isinstance(entries, dict):
            return
        entries = {k: v for k, v in entries.items() if isinstance(v, dict)}
        for k in list(entries.keys())[-self.max_entries:]:
            self._data[k] = entries[k]
        saved_stats = payload.get("stats") if isinstance(payload, dict) else {}
        if isinstance(saved_stats, dict):
            self._stats["hits"] = saved_stats.get("hits", 0)
            self._stats["misses"] = saved_stats.get("misses", 0)
        self._stats["loads"] += 1

    def _save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".json.tmp")
            payload = {
                "entries": self._data,
                "stats": self._stats,
                "saved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "version": self.version,
            }
            tmp.write_text(json.dumps(payload), encoding="utf-8")
            os.replace(tmp, self.path)
        except Exception:
            try:
                if tmp.exists():
                    tmp.unlink()
            except Exception:
                pass

    def lookup(self, command: str) -> Optional[dict]:
        key = command_key(command)
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                self._stats["misses"] += 1
                return None
            entry["hit_count"] = entry.get("hit_count", 0) + 1
            self._stats["hits"] += 1
            self._save()
            return deepcopy(entry)

    def store(self, command: str, flow_content: dict) -> dict:
        key = command_key(command)
        entry = {
            "command": command,
            "normalized": normalize_command(command),
            "flow": flow_content,
            "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "hit_count": 0,
            "key": key,
        }
        with self._lock:
            self._data[key] = entry
            if len(self._data) > self.max_entries:
                evict = min(
                    self._data,
                    key=lambda k: self._data[k].get("created", ""),
                )
                del self._data[evict]
            self._save()
        return entry

    def stats(self) -> dict:
        with self._lock:
            hits = self._stats.get("hits", 0)
            misses = self._stats.get("misses", 0)
            total = hits + misses
        return {
            "cache_file": str(self.path),
            "file_exists": self.path.exists(),
            "entries": len(self._data),
            "max_entries": self.max_entries,
            "hits": hits,
            "misses": misses,
            "total_lookups": total,
            "hit_rate": round(hits / total, 4) if total else 0.0,
            "key_sample": list(self._data.keys())[:5],
            "commands": [e.get("normalized") for e in list(self._data.values())[:20]],
        }

    def clear(self) -> bool:
        with self._lock:
            self._data = {}
            self._stats["hits"] = 0
            self._stats["misses"] = 0
            self._save()
        return True