import re
import json


class RegexClassifier:

    def __init__(self, taxonomy_path='taxonomy/error_taxonomy.json'):
        with open(taxonomy_path) as f:
            taxonomy = json.load(f)
        self.compiled = {}
        self.taxonomy = taxonomy['error_classes']
        for cls, data in self.taxonomy.items():
            self.compiled[cls] = [re.compile(p, re.IGNORECASE) for p in data['patterns']]

    def enrich_from_dataset(self, scenarios: list[dict]):
        from collections import defaultdict
        dataset_patterns = defaultdict(set)

        for s in scenarios:
            error_class = s.get('error_class', 'UNKNOWN')
            if error_class == 'UNKNOWN':
                continue
            msg = s.get('error_message', '')
            if msg and len(msg) > 5 and msg != 'nan':
                words = msg.lower().split()
                for word in words:
                    clean = re.sub(r'[^a-z0-9]', '', word)
                    if len(clean) > 4:
                        dataset_patterns[error_class].add(clean)

        for cls, words in dataset_patterns.items():
            if cls in self.compiled:
                for word in list(words)[:10]:
                    try:
                        pattern = re.compile(word, re.IGNORECASE)
                        self.compiled[cls].append(pattern)
                    except:
                        continue

        total = sum(len(v) for v in dataset_patterns.values())
        print(f'Classifier enriched with {total} dataset patterns')

    def classify(self, stderr: str, exit_code: int) -> tuple:
        # ── Priority overrides — check specific patterns BEFORE exit code shortcuts ──

        # "sudo: command not found" in Docker → PERMISSION_DENIED, not TOOL_NOT_INSTALLED
        if exit_code == 127 and re.search(r'sudo:\s*(command\s+not\s+found|not\s+found)', stderr, re.IGNORECASE):
            return 'PERMISSION_DENIED', 0.95

        # Wordlist / file path not found → WRONG_SYNTAX (bad arguments), not TOOL_NOT_INSTALLED
        if re.search(r'(wordlist|file)\s+.*does\s+not\s+exist', stderr, re.IGNORECASE):
            return 'WRONG_SYNTAX', 0.90
        if re.search(r'no\s+such\s+file.*wordlist|wordlist.*no\s+such\s+file', stderr, re.IGNORECASE):
            return 'WRONG_SYNTAX', 0.90

        # Generic exit code 127 → tool not installed
        if exit_code == 127:
            return 'TOOL_NOT_INSTALLED', 0.99

        # ── Standard pattern matching ──
        matches = {}
        for cls, patterns in self.compiled.items():
            count = sum(1 for p in patterns if p.search(stderr))
            if count > 0:
                matches[cls] = count / len(patterns)
        if not matches:
            return None, 0.0
        best = max(matches, key=matches.get)
        confidence = min(0.95, 0.60 + matches[best] * 0.35)
        return best, confidence
