import pandas as pd
import re
from collections import Counter

ERROR_TYPE_MAP = {
    'package_not_found':     'TOOL_NOT_INSTALLED',
    'permission_error':      'PERMISSION_DENIED',
    'network_error':         'NETWORK_UNREACHABLE',
    'file_not_found':        'WRONG_SYNTAX',
    'port_conflict':         'RESOURCE_EXHAUSTION',
    'service_error':         'VERSION_MISMATCH',
    'syntax_error':          'WRONG_SYNTAX',
    'dependency_error':      'TOOL_NOT_INSTALLED',
    'command_not_found':     'TOOL_NOT_INSTALLED',
    'password)':             'AUTH_FAILURE',
    'authentication_error':  'AUTH_FAILURE',
}

def load_dataset(csv_path: str) -> list[dict]:
    df = pd.read_csv(csv_path)
    scenarios = []
    for _, row in df.iterrows():
        try:
            cmd_str = str(row.iloc[0])
            command_match = re.search(r'"command":"([^"]+)"', cmd_str)
            error_msg = str(row.iloc[1]).replace('error_message:', '').strip().strip('"')
            error_type = str(row.iloc[2]).replace('error_type:', '').strip().strip('"')
            root_cause = str(row.iloc[3]).replace('root_cause:', '').strip().strip('"')
            remediation = str(row.iloc[4]).replace('remediation_steps:', '').strip().strip('"')
            correct_cmd = str(row.iloc[5]).replace('correct_command:', '').strip().strip('"')
            tool = str(row.iloc[6]).replace('tool:', '').strip().strip('"')
            difficulty = str(row.iloc[7]).replace('difficulty:', '').strip().strip('"').rstrip('}')
            
            scenarios.append({
                'command': command_match.group(1) if command_match else '',
                'error_message': error_msg,
                'error_class': ERROR_TYPE_MAP.get(error_type, 'UNKNOWN'),
                'error_type': error_type,
                'root_cause': root_cause,
                'remediation_steps': remediation,
                'correct_command': correct_cmd,
                'tool': tool,
                'difficulty': difficulty
            })
        except Exception:
            continue
    return scenarios

if __name__ == '__main__':
    scenarios = load_dataset('kali_data/kali_linux_error.csv')
    print(f'Total loaded: {len(scenarios)}')
    classes = Counter(s['error_class'] for s in scenarios)
    print('Distribution:')
    for cls, count in classes.most_common():
        print(f'  {cls}: {count}')
