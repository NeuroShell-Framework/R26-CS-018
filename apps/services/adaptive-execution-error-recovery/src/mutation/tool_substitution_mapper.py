import json


class ToolSubstitutionMapper:

    def __init__(self, map_path='taxonomy/tool_substitution_map.json'):
        with open(map_path) as f:
            self.substitution_map = json.load(f)

    def get_substitute(
        self, tool: str, intent_ref: str, already_tried: list
    ):
        intent_map = self.substitution_map.get(intent_ref, {})
        substitutes = intent_map.get(tool.lower(), [])
        for substitute in substitutes:
            if substitute not in already_tried:
                return substitute
        return None
