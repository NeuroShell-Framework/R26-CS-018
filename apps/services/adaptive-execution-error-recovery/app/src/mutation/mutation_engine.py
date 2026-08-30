from __future__ import annotations

import re
from src.schemas.models import RecoveryPlan, ErrorContext
from src.mutation.tool_substitution_mapper import ToolSubstitutionMapper
from src.mutation.dataset_corrector import DatasetCorrector

# Only these tools may be auto-installed via apt-get.
# NOTE: rustscan is NOT in the Kali apt repos (GitHub-release only), so it must
# never be offered here — an install attempt would waste an attempt and fail.
KALI_PACKAGE_WHITELIST = {
    'nmap', 'gobuster', 'nikto', 'ffuf', 'dirb', 'hydra', 'sqlmap',
    'whatweb', 'masscan', 'medusa', 'ncrack',
    'wfuzz', 'crackmapexec', 'enum4linux', 'netcat', 'curl', 'wget'
}

# Known-good wordlist paths available in the neuroshell-kali image.
# NOTE (modern Kali layout): dirb/dirbuster ship wordlists under
# /usr/share/{dirb,dirbuster}/wordlists, NOT the legacy /usr/share/wordlists/*
# that older guides reference — keep this list in sync with the image.
VALID_WORDLIST_PATHS = [
    '/usr/share/dirb/wordlists/common.txt',
    '/usr/share/dirb/wordlists/big.txt',
    '/usr/share/dirb/wordlists/small.txt',
    '/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt',
    '/usr/share/seclists/Discovery/Web-Content/common.txt',
]

# Default wordlist for directory bruteforcing
DEFAULT_WORDLIST = '/usr/share/dirb/wordlists/common.txt'

_TARGET_URL    = re.compile(r'https?://[^\s]+')
_TARGET_IPCIDR = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b')


def _extract_target(command: str):
    """Return the scan target (URL preferred, else IPv4/CIDR) from a command, or None."""
    m = _TARGET_URL.search(command)
    if m:
        return m.group(0)
    m = _TARGET_IPCIDR.search(command)
    if m:
        return m.group(0)
    return None


def _preserve_original_target(corrected: str, original: str):
    """
    Re-inject the user's original target into a dataset/LLM correction so a syntax
    fix never silently redirects the scan to a different host. Returns the
    retargeted command, or None if the user's target cannot be identified
    (fail safe: the caller must then reject the correction).
    """
    user_target = _extract_target(original)
    if not user_target:
        return None
    ds_target = _extract_target(corrected)
    if ds_target is None:
        return f'{corrected} {user_target}'
    if ds_target != user_target:
        return corrected.replace(ds_target, user_target, 1)
    return corrected


def _fix_wordlist_path(command: str) -> str:
    """Replace non-existent wordlist paths with a known-good default."""
    # Match -w <path> patterns
    match = re.search(r'-w\s+(\S+)', command)
    if match:
        path = match.group(1)
        # If it's a suspicious/non-standard path, replace with default
        if path in VALID_WORDLIST_PATHS:
            return command
        # Replace bad wordlist path with default
        return command[:match.start(1)] + DEFAULT_WORDLIST + command[match.end(1):]
    return command


def _sanitize_dataset_correction(corrected: str, original_cmd: str, tool: str) -> str | None:
    """Validate and sanitize a dataset correction before using it."""
    if not corrected or not corrected.strip():
        return None

    # Reject corrections that are just tool names or very short
    if len(corrected.strip()) < 5:
        return None

    # Hard blocklist: reject listener/interactive patterns that hang indefinitely
    if re.search(r'\b(nc|netcat|ncat)\b\s+.*-l', corrected) or re.search(r'\s-(lvnp|lvp|lp)\b', corrected):
        return None

    # Fix wordlist paths in gobuster/dirb/ffuf corrections
    if tool.lower() in ('gobuster', 'dirb', 'ffuf', 'wfuzz'):
        corrected = _fix_wordlist_path(corrected)

    return corrected


class MutationEngine:

    def __init__(self, dataset_corrector: DatasetCorrector | None = None):
        self.substitution_mapper = ToolSubstitutionMapper()
        self.dataset_corrector = dataset_corrector

    def apply_mutation(
        self, plan: RecoveryPlan, ctx: ErrorContext
    ) -> tuple[str | None, str]:
        """
        Apply a mutation strategy to produce a corrected command.

        Returns:
            (corrected_command, correction_source)
            corrected_command is None if no mutation could be applied.
            correction_source is one of: 'rule-based', 'dataset', 'llm', ''
        """
        strategy = plan.strategy
        cmd = ctx.command

        if strategy == 'INSTALL_TOOL':
            tool = ctx.tool.lower()
            if tool not in KALI_PACKAGE_WHITELIST:
                return None, ''
            # Don't re-install if command already contains apt-get install for this tool
            if f'apt-get install' in cmd and tool in cmd:
                return None, ''
            # Docker containers run as root — never use sudo with apt-get
            corrected = f'apt-get update -qq --fix-missing && apt-get install -y --fix-missing {tool} && {cmd}'
            return corrected, 'rule-based'

        elif strategy == 'ADD_SUDO':
            # Inside Docker containers we are already root — sudo is not available
            if cmd.startswith('sudo '):
                return cmd[5:], 'rule-based'
            # Also handle sudo embedded after && chains
            if ' sudo ' in cmd:
                return cmd.replace(' sudo ', ' ', 1), 'rule-based'
            return None, ''

        elif strategy == 'ADJUST_PARAMETERS':
            mutated = re.sub(r'-t\s*\d+', '-t 10', cmd)
            mutated = re.sub(r'-T[45]', '-T2', mutated)
            mutated = re.sub(r'--timeout\s*\d+', '--timeout 30', mutated)
            if mutated != cmd:
                return mutated, 'rule-based'
            # Rule-based didn't change anything — try dataset
            ds_result = self._try_dataset_correction(ctx, plan.error_class)
            if ds_result:
                return ds_result, 'dataset'
            # Fallback to LLM
            llm_result = self._try_llm_correction(ctx, plan.error_class)
            if llm_result:
                return llm_result, 'llm'
            return None, ''

        elif strategy == 'TOOL_SUBSTITUTION':
            substitute = self.substitution_mapper.get_substitute(
                ctx.tool, ctx.intent_ref, ctx.prior_strategies
            )
            if not substitute:
                return None, ''
            return cmd.replace(ctx.tool, substitute, 1), 'rule-based'

        elif strategy in ('FIX_SYNTAX', 'ADJUST_TIMEOUT', 'FIX_AUTH', 'VERSION_DOWNGRADE'):
            # Check if stderr indicates a missing wordlist/file — fix path directly
            if re.search(r'(wordlist|file)\s+.*does\s+not\s+exist', ctx.stderr, re.IGNORECASE):
                fixed = _fix_wordlist_path(cmd)
                if fixed != cmd:
                    return fixed, 'rule-based'

            # If the plan already has a different corrected command (from LLM reasoner),
            # use it directly
            if (plan.corrected_command
                    and plan.corrected_command.strip().lower() != cmd.strip().lower()):
                sanitized = _sanitize_dataset_correction(plan.corrected_command, cmd, ctx.tool)
                if sanitized:
                    retargeted = _preserve_original_target(sanitized, cmd)
                    if retargeted is not None:
                        return retargeted, 'llm'
                    # else fall through to dataset/LLM correction below

            # Otherwise, try dataset correction first
            ds_result = self._try_dataset_correction(ctx, plan.error_class)
            if ds_result:
                return ds_result, 'dataset'

            # Then try LLM correction as fallback
            llm_result = self._try_llm_correction(ctx, plan.error_class)
            if llm_result:
                return llm_result, 'llm'

            return None, ''

        return None, ''

    def _try_dataset_correction(self, ctx: ErrorContext, error_class: str) -> str | None:
        """Attempt to find a corrected command from the dataset."""
        if not self.dataset_corrector or not self.dataset_corrector.is_loaded:
            return None
        result = self.dataset_corrector.lookup_correction(
            tool=ctx.tool,
            error_class=error_class,
            original_command=ctx.command,
            stderr=ctx.stderr,
        )
        if result:
            corrected = result['correct_command']
            # PRESERVE USER TARGET: never silently redirect the scan to the dataset's host
            retargeted = _preserve_original_target(corrected, ctx.command)
            if retargeted is None:
                print(f'[AEERE] Dataset correction rejected (cannot preserve user target): {corrected}')
                return None
            corrected = retargeted
            # Sanitize the dataset correction
            sanitized = _sanitize_dataset_correction(corrected, ctx.command, ctx.tool)
            if sanitized:
                print(f'[AEERE] Dataset correction found (score={result["match_score"]}): {sanitized}')
                return sanitized
            else:
                print(f'[AEERE] Dataset correction rejected (bad quality): {corrected}')
        return None

    def _try_llm_correction(self, ctx: ErrorContext, error_class: str) -> str | None:
        """Attempt to generate a corrected command via the LLM."""
        try:
            from src.classification.llm_causal_reasoner import generate_corrected_command
            corrected = generate_corrected_command(ctx, error_class)
            if corrected:
                sanitized = _sanitize_dataset_correction(corrected, ctx.command, ctx.tool)
                if sanitized:
                    print(f'[AEERE] LLM correction generated: {sanitized}')
                    return sanitized
        except Exception as e:
            print(f'[AEERE] LLM correction failed: {e}')
        return None
