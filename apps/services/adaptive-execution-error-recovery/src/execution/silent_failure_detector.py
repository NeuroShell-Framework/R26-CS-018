# Tools that MUST produce stdout output to be considered successful
TOOLS_REQUIRING_OUTPUT = {
    'nmap', 'nikto', 'ffuf', 'dirb',
    'hydra', 'sqlmap', 'whatweb', 'masscan'
}

# Version/help commands never count as silent failures
VERSION_KEYWORDS = ['--version', '-version', 'version', '--help', '-help', '--h', '-h']

# Patterns in stderr that indicate the tool silently ignored an error.
# Some tools (e.g. nikto) exit 0 on invalid flags but signal the real
# problem only via stderr.  If any of these appear we treat exit-0 as
# a silent failure so the recovery engine gets a chance to fix the command.
STDERR_ERROR_PATTERNS = [
    'unknown option',
    'invalid option',
    'unrecognized option',
    'requires an argument',
    'requires a value',
    'unknown argument',
]

def is_silent_failure(tool: str, stdout: str, exit_code: int,
                      command: str = '', stderr: str = '') -> bool:
    if exit_code != 0:
        return False
    if tool.lower() not in TOOLS_REQUIRING_OUTPUT:
        return False

    # --- Stderr error patterns take priority over the version/help keyword skip.
    # Some tools (e.g. nikto) reuse flags like '-h' for "host", not "help".
    # If stderr contains a real error signal we must honour it regardless of
    # whether the command string happens to contain a version/help keyword.
    stderr_lower = stderr.lower()
    if any(pattern in stderr_lower for pattern in STDERR_ERROR_PATTERNS):
        return True

    if any(kw in command.lower() for kw in VERSION_KEYWORDS):
        return False

    # Original check: suspiciously short stdout
    if len(stdout.strip()) < 10:
        return True

    return False