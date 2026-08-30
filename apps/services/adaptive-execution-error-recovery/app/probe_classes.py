import sys
sys.path.insert(0, '.')
from src.classification.regex_classifier import RegexClassifier

clf = RegexClassifier()

probes = [
    ('TOOL_NOT_INSTALLED', 'bash: gobuster: command not found', 127),
    ('PERMISSION_DENIED',  'Permission denied: cannot open output file', 1),
    ('NETWORK_UNREACHABLE','No route to host', 1),
    ('WRONG_SYNTAX',       'Invalid option -- z', 1),
    ('RESOURCE_EXHAUSTION','Cannot allocate memory', 1),
    ('AUTH_FAILURE',       'Authentication failed for user admin', 1),
    ('TIMEOUT',            'Operation timed out after 30 seconds', 1),
    ('VERSION_MISMATCH',   'deprecated flag removed in version 3', 1),
]

header = 'EXPECTED'.ljust(22) + 'GOT'.ljust(22) + 'CONF'.ljust(8) + 'MATCH'
print(header)
print('-' * 60)
correct = 0
for expected, stderr, code in probes:
    got, conf = clf.classify(stderr, code)
    if got == expected:
        correct += 1
        match = 'OK'
    else:
        match = 'XX  <-- MISMATCH'
    row = expected.ljust(22) + str(got).ljust(22) + (str(round(conf, 2))).ljust(8) + match
    print(row)
print('-' * 60)
print('Regex classifier: ' + str(correct) + '/8 classes correctly identified')
