import sys
sys.path.insert(0, '.')
from src.execution.command_runner import CommandRunner
r = CommandRunner()
result = r.execute(
    'apt-get update -qq --fix-missing && apt-get install -y --fix-missing gobuster && gobuster dir -u http://192.168.1.10 -w /common.txt',
    timeout=120
)
print(f'EXIT_CODE={result.exit_code}')
print(f'TIMED_OUT={result.timed_out}')
stderr = result.stderr.strip()
print(f'STDERR_LEN={len(stderr)}')
print(f'STDERR_START={stderr[:200]}')
if 'Failed to fetch' in stderr:
    print('HAS_FAILED_TO_FETCH=True')
else:
    print('HAS_FAILED_TO_FETCH=False')
if 'Operation not permitted' in stderr:
    print('HAS_PERM_ISSUE=True')
else:
    print('HAS_PERM_ISSUE=False')
if 'Unable to locate package' in stderr:
    print('HAS_UNABLE_LOCATE=True')
else:
    print('HAS_UNABLE_LOCATE=False')
