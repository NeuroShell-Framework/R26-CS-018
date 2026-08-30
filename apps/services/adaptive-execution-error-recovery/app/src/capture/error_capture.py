import re
from src.schemas.models import RawExecutionResult, ErrorContext

INJECTION_PATTERNS = [
    r'ignore previous instructions',
    r'disregard the above',
    r'forget (?:all )?(?:previous |prior )?instructions',
    r'<\|im_start\|>',
    r'<\|im_end\|>',
    r'\[/?INST\]',
    r'\[/?SYSTEM\]',
    r'<\|system\|>',
    r'<\|user\|>',
    r'<\|assistant\|>',
    r'</s>',
]


def _strip_injections(text: str) -> str:
    for pattern in INJECTION_PATTERNS:
        text = re.sub(pattern, '[REDACTED]', text, flags=re.IGNORECASE)
    return text


def _extract_tool_name(command: str) -> str:
    parts = command.strip().split()
    if not parts:
        return 'unknown'
    tool = parts[0]
    if tool == 'sudo' and len(parts) > 1:
        return parts[1]
    if '&&' in command:
        after = command.split('&&')[-1].strip().split()
        if after:
            return after[0]
    return tool


def build_error_context(
    raw: RawExecutionResult,
    session_id: str,
    intent_ref: str,
    attempt_number: int,
    prior_strategies: list,
    silent_failure: bool = False
) -> ErrorContext:
    clean_stderr = _strip_injections(raw.stderr[:2000])
    clean_stdout = raw.stdout[:500]
    tool = _extract_tool_name(raw.command)

    return ErrorContext(
        session_id=session_id,
        command=raw.command,
        stdout=clean_stdout,
        stderr=clean_stderr,
        exit_code=raw.exit_code,
        tool=tool,
        intent_ref=intent_ref,
        attempt_number=attempt_number,
        prior_strategies=prior_strategies,
        silent_failure=silent_failure
    )
