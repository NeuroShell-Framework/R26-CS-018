import collections
from src.mutation.dataset_corrector import DatasetCorrector
from kali_data.dataset_loader import load_dataset
from src.capture.error_capture import _extract_tool_name

def check_mismatches():
    scenarios = load_dataset('kali_data/kali_linux_error.csv')
    mismatches = 0
    for s in scenarios:
        command = s.get('command', '').strip()
        if not command: continue
        derived = _extract_tool_name(command).lower()
        actual = _extract_tool_name(command).lower()
        if derived != actual:
            mismatches += 1
    print(f"Post-fix derived vs actual mismatches: {mismatches}")

def check_keys():
    c = DatasetCorrector()
    scenarios = load_dataset('kali_data/kali_linux_error.csv')
    c.load_from_scenarios(scenarios)
    
    total = sum(len(v) for v in c._index.values())
    keys = len(c._index)
    avg = total / keys if keys else 0
    print(f"Total keys: {keys}, Average entries per key: {avg:.2f}")

def check_lookup():
    c = DatasetCorrector()
    scenarios = load_dataset('kali_data/kali_linux_error.csv')
    c.load_from_scenarios(scenarios)
    print("\nLookup Result:")
    result = c.lookup_correction('nikto', 'WRONG_SYNTAX', 'nikto --invalid-option-xyz -h 192.168.1.10', stderr='Unknown option: invalid-option-xyz')
    print('Result:', result)

print("--- Output 1 ---")
check_mismatches()

print("\n--- Output 2 ---")
check_keys()

print("\n--- Output 3 ---")
check_lookup()
