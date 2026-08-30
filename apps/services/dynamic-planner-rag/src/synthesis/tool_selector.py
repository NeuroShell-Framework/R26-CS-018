import os
import json

SUPPORTED_TOOLS = {"nmap", "nikto", "gobuster"}

# Resolve tool_map.json relative to this file's own location so the path is
# correct regardless of which directory uvicorn is launched from.
_DEFAULT_TOOL_MAP = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "data", "tool_map.json"
)

class ToolSelector:
    def __init__(self, tool_map_path: str = None):
        if tool_map_path is None:
            tool_map_path = _DEFAULT_TOOL_MAP
        with open(tool_map_path, "r") as f:
            self.tool_map = json.load(f)

    def select(self, intent, tool_hint=None, top_retrieval_source=None):

        # Priority 1 → C1 tool hint
        if tool_hint and tool_hint.lower() in SUPPORTED_TOOLS:
            return tool_hint.lower()

        # Priority 2 → retrieval source
        if top_retrieval_source and top_retrieval_source.lower() in SUPPORTED_TOOLS:
            return top_retrieval_source.lower()

        # Priority 3 → fallback mapping
        fallback_tools = self.tool_map.get(intent, [])

        if fallback_tools:
            return fallback_tools[0]

        return None