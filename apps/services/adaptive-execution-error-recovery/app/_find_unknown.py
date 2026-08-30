import pandas as pd
from collections import Counter

df = pd.read_csv('datasets/kali_linux_error.csv')

m = {
    'package_not_found': 'TOOL_NOT_INSTALLED',
    'permission_error': 'PERMISSION_DENIED',
    'network_error': 'NETWORK_UNREACHABLE',
    'file_not_found': 'WRONG_SYNTAX',
    'port_conflict': 'RESOURCE_EXHAUSTION',
    'service_error': 'VERSION_MISMATCH',
}

unknown = []
for _, r in df.iterrows():
    try:
        et = str(r.iloc[2]).replace('error_type:', '').strip().strip('"')
        if et not in m:
            unknown.append(et)
    except:
        pass

print('Unknown error types found:')
for t, c in Counter(unknown).most_common():
    print(f'  {t}: {c}')
