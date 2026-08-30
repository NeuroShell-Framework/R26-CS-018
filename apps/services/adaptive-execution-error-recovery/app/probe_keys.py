import sys
sys.path.insert(0, '.')
from kali_data.dataset_loader import load_dataset

rows = load_dataset('kali_data/kali_linux_error.csv')
print('Total rows:', len(rows))
print()
print('Keys in first row:', list(rows[0].keys()))
print()
print('First 3 full rows:')
for r in rows[:3]:
    print('-' * 50)
    for k, v in r.items():
        print('  ' + str(k) + ' = ' + repr(v)[:80])
