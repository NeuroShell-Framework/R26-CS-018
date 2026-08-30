from __future__ import annotations

import json
import os
import re
import ollama
from dotenv import load_dotenv
from src.schemas.models import ErrorContext, RecoveryPlan

load_dotenv()

OLLAMA_MODEL = os.getenv('OLLAMA_MODEL', 'qwen2.5-coder:latest')

SYSTEM_PROMPT = '''You are a cybersecurity error recovery expert for Kali Linux penetration testing tools.
Analyze the failed command and produce a JSON recovery plan.
Output ONLY valid JSON. No markdown. No explanation. No code fences.

JSON Schema:
{
  "error_class": one of [TOOL_NOT_INSTALLED, PERMISSION_DENIED, NETWORK_UNREACHABLE, WRONG_SYNTAX, RESOURCE_EXHAUSTION, AUTH_FAILURE, TIMEOUT, VERSION_MISMATCH, UNKNOWN],
  "root_cause": "string explaining exact cause (10-500 chars)",
  "strategy": one of [INSTALL_TOOL, ADD_SUDO, ADJUST_PARAMETERS, TOOL_SUBSTITUTION, FIX_SYNTAX, ADJUST_TIMEOUT, FIX_AUTH, VERSION_DOWNGRADE, ESCALATE],
  "corrected_command": "the fixed executable command (no markdown)",
  "confidence": float between 0.0 and 1.0,
  "reasoning": "step by step reasoning for this diagnosis"
}

Rules:
1. corrected_command must be a real Kali Linux bash command
2. Never use public IP addresses in corrected_command
3. If you cannot determine a safe fix, set strategy=ESCALATE and confidence<0.5
4. corrected_command must differ from the original failed command
5. Output raw JSON only — absolutely no markdown, no backticks, no explanation'''


def call_llm_reasoner(ctx: ErrorContext):
    user_message = f'''Failed Command: {ctx.command}
Tool: {ctx.tool}
Exit Code: {ctx.exit_code}
Intent: {ctx.intent_ref}
Attempt Number: {ctx.attempt_number}
Prior Strategies Tried: {ctx.prior_strategies}
Silent Failure: {ctx.silent_failure}

STDERR (error output):
{ctx.stderr[:1500]}

STDOUT (partial output before failure):
{ctx.stdout[:300]}'''

    try:
        response = ollama.chat(
            model=OLLAMA_MODEL,
            messages=[
                {'role': 'system', 'content': SYSTEM_PROMPT},
                {'role': 'user',   'content': user_message}
            ],
            options={'temperature': 0.1},
            format='json',
            keep_alive='30m'
        )
        raw = response['message']['content']
        raw = re.sub(r'```json|```', '', raw).strip()
        data = json.loads(raw)
        return RecoveryPlan(**data)
    except (json.JSONDecodeError, Exception) as e:
        print(f'LLM reasoner failed: {e}')
        return None


# ── Focused command corrector (lightweight fallback) ──────────

CORRECTOR_PROMPT = '''You are a Kali Linux command correction expert.
Given a failed command, its error output, and the error class, produce ONLY the corrected command.
Output ONLY the corrected bash command as a single line of raw text.
No markdown. No explanation. No code fences. No JSON. Just the fixed command.

Rules:
1. The corrected command must be a real, executable Kali Linux bash command.
2. Never use public IP addresses.
3. The corrected command MUST differ from the original failed command.
4. If you cannot determine a safe fix, output exactly: ESCALATE'''


def generate_corrected_command(ctx: ErrorContext, error_class: str) -> str | None:
    """
    Ask the LLM to produce ONLY a corrected command (no full recovery plan).
    Returns the corrected command string, or None if it cannot fix.
    """
    user_message = f'''Failed Command: {ctx.command}
Tool: {ctx.tool}
Error Class: {error_class}
Exit Code: {ctx.exit_code}
Intent: {ctx.intent_ref}

STDERR:
{ctx.stderr[:1500]}

STDOUT:
{ctx.stdout[:300]}

Output ONLY the corrected command:'''

    try:
        response = ollama.chat(
            model=OLLAMA_MODEL,
            messages=[
                {'role': 'system', 'content': CORRECTOR_PROMPT},
                {'role': 'user',   'content': user_message}
            ],
            options={'temperature': 0.05, 'num_predict': 100},
            keep_alive='30m'
        )
        corrected = response['message']['content'].strip()
        # Clean any accidental markdown
        corrected = re.sub(r'^```\w*\n?', '', corrected)
        corrected = re.sub(r'\n?```$', '', corrected).strip()

        if not corrected or corrected == 'ESCALATE':
            return None
        # Must differ from original
        if corrected.lower() == ctx.command.lower():
            return None
        return corrected
    except Exception as e:
        print(f'LLM command corrector failed: {e}')
        return None
