import json
from collections import Counter

path = r'd:\Research\Data set\kali_linux_error.csv'
# try loading as the project loads it
import sys
sys.path.insert(0, '.')
try:
    from kali_data.dataset_loader import load_dataset
    rows = load_dataset('kali_data/kali_linux_error.csv')
    print('Loaded via project loader:', len(rows), 'rows')
    key = 'error_type' if rows and 'error_type' in rows[0] else None
    if not key and rows:
        print('Available keys:', list(rows[0].keys()))
    if key:
        c = Counter(r.get('error_type','') for r in rows)
        print()
        print('error_type distribution:')
        for k, v in c.most_common():
            print('  ' + str(k).ljust(28) + str(v))
except Exception as e:
    print('Loader failed:', repr(e))
