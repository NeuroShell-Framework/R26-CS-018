# NeuroShell IRE — Alias Resolver
# Resolve aliases and jargon to canonical identifiers

import json
import re
from pathlib import Path
from typing import Dict
from src.utils.logging_config import get_logger


class AliasResolver:
    def __init__(self, alias_map_path: str = "data/alias_map.json"):
        self.logger = get_logger(__name__)
        self.alias_map = self.load_alias_map(alias_map_path)
        self._compiled_patterns = self._build_patterns()

    def load_alias_map(self, path: str) -> Dict[str, str]:
        raw = Path(path).read_text(encoding="utf-8")
        data = json.loads(raw)
        return {k: v for k, v in data.items() if not k.startswith("_")}

    def _build_patterns(self):
        sorted_keys = sorted(self.alias_map.keys(), key=len, reverse=True)
        patterns = []
        for key in sorted_keys:
            pattern = re.compile(r"\b" + re.escape(key) + r"\b", re.IGNORECASE)
            patterns.append((pattern, self.alias_map[key]))
        return patterns

    def enrich(self, text: str) -> str:
        if not text or not text.strip():
            return text

        matches_found = 0
        for pattern, replacement in self._compiled_patterns:
            match = pattern.search(text)
            if match:
                original = match.group(0)
                annotated = f"{replacement} (alias: {original})"
                text = pattern.sub(annotated, text, count=1)
                matches_found += 1

        self.logger.debug("alias_enriched", matches_found=matches_found)
        return text
