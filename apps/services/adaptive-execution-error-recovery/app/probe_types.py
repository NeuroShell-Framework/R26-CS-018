import sys
sys.path.insert(0, '.')
from kali_data.dataset_loader import load_dataset

rows = load_dataset('kali_data/kali_linux_error.csv')

targets = ['service_error', 'port_conflict', 'dependency_error', 'file_not_found']
for t in targets:
    print('=' * 60)
    print('error_type:', t)
    print('=' * 60)
    shown = 0
    for r in rows:
        if r.get('error_type') == t:
            em = r.get('error_message', '')
            print('  cmd   :', r.get('command', '')[:70])
            print('  stderr:', em[:90])
            print()
            shown += 1
            if shown >= 4:
                break
