# NeuroShell IRE --- JSON Parser
# Parse and extract JSON from LLM responses

import json
import re
from src.schemas.intent_schema import JSONParseError
from src.utils.logging_config import get_logger


class JSONParser:
    def __init__(self):
        self.logger = get_logger(__name__)

    def parse(self, raw_text: str) -> dict:
        if not raw_text or not raw_text.strip():
            raise JSONParseError('Model returned empty output')

        text = raw_text.strip()

        # Strip Gemma thinking blocks
        text = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL)
        text = text.replace('<|think|>', '')

        # Strip markdown code fences
        text = re.sub(r'```json\s*', '', text)
        text = re.sub(r'```\s*', '', text)

        # Find JSON object boundary
        first_brace = text.find('{')
        last_brace = text.rfind('}')
        if first_brace == -1 or last_brace == -1:
            raise JSONParseError('No JSON object found in model output')

        json_str = text[first_brace : last_brace + 1]

        try:
            result = json.loads(json_str)
        except json.JSONDecodeError as e:
            raise JSONParseError(
                f'JSON decode failed: {e.msg} at line {e.lineno} col {e.colno}'
            )

        if not isinstance(result, dict):
            raise JSONParseError('Model output parsed to non-object JSON type')

        self.logger.debug('json_parsed', keys=list(result.keys()))
        return result
