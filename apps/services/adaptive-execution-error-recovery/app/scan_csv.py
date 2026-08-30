import os
from kali_data.dataset_loader import load_dataset

def scan():
    mismatches = {}
    
    # Load dataset using existing parser
    scenarios = load_dataset('kali_data/kali_linux_error.csv')
    
    for s in scenarios:
        labeled_tool = s.get('tool', '').strip().lower()
        command = s.get('command', '').strip()
        
        if not labeled_tool or not command:
            continue
            
        parts = command.split()
        if not parts:
            continue
            
        actual_tool = parts[0].lower()
        if actual_tool == 'sudo' and len(parts) > 1:
            actual_tool = parts[1].lower()
        elif '&&' in command:
            after = command.split('&&')[-1].strip().split()
            if after:
                actual_tool = after[0].lower()
                
        if labeled_tool != actual_tool:
            pair = (labeled_tool, actual_tool)
            mismatches[pair] = mismatches.get(pair, 0) + 1

    print(f"Total rows scanned: {len(scenarios)}")
    mismatched_total = sum(mismatches.values())
    print(f"Total mismatched rows: {mismatched_total}\n")
    print("Mismatches (Labeled Tool -> Actual Tool in Command):")
    for pair, count in sorted(mismatches.items(), key=lambda x: x[1], reverse=True):
        print(f"  {pair[0]:<15} -> {pair[1]:<15}: {count}")

if __name__ == "__main__":
    scan()
