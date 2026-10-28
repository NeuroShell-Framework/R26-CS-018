import json
import sys
sys.path.insert(0, '.')
from src.classification.regex_classifier import RegexClassifier
try:
    from src.classification.embedding_classifier import EmbeddingClassifier
    embed_clf = EmbeddingClassifier()
    HAS_EMBED = True
except Exception as e:
    print('Embedding classifier unavailable:', e)
    HAS_EMBED = False

regex_clf = RegexClassifier()

SAMPLES = {}
SAMPLES["TOOL_NOT_INSTALLED"] = [("bash: gobuster: command not found",127),("nmap: command not found",127),("bash: nikto: command not found",127),("sqlmap: command not found",127),("No such file or directory: ffuf",127),("hydra: command not found",127),("bash: masscan: command not found",127),("command not found: dirb",127),("bash: whatweb: command not found",127),("wfuzz: command not found",127)]
SAMPLES["PERMISSION_DENIED"] = [("Permission denied: cannot open output file",1),("Operation not permitted",1),("nmap: Permission denied, are you root?",1),("EACCES: permission denied",1),("You must be root to run this scan",1),("Permission denied writing to /var/log",1),("bind: Operation not permitted",1),("Cannot open /dev/bpf0: Permission denied",1),("Permission denied cannot create raw socket",1),("access denied: must be root",1)]
SAMPLES["NETWORK_UNREACHABLE"] = [("No route to host",1),("Connection refused",1),("Network is unreachable",1),("EHOSTUNREACH: host unreachable",1),("Host is down",1),("connect to 10.0.0.5 failed: No route to host",1),("Connection refused by remote host",1),("Failed to connect: Network unreachable",1),("nmap: no route to host 10.1.1.1",1),("curl: (7) Failed to connect: Connection refused",1)]
SAMPLES["WRONG_SYNTAX"] = [("Invalid option -- z",1),("unrecognized argument: --foo",1),("usage: nmap [Scan Type]",1),("invalid flag provided",1),("unknown flag: --bad",1),("Invalid option: --script-args",1),("Error: unknown shorthand flag q",1),("nmap: unrecognized option --xyz",1),("gobuster: unknown flag --totally-invalid",1),("usage: hydra [options] target",1)]
SAMPLES["RESOURCE_EXHAUSTION"] = [("Cannot allocate memory",1),("Too many open files",1),("out of memory",1),("ENOMEM: not enough memory",1),("fork: Cannot allocate memory",1),("Killed (out of memory)",137),("socket: Too many open files",1),("Out of memory: Kill process 1234",1),("cannot fork: Resource temporarily unavailable",1),("memory allocation of 8388608 bytes failed",1)]
SAMPLES["AUTH_FAILURE"] = [("Authentication failed",1),("Permission denied (publickey)",1),("Invalid credentials",1),("Access denied for user",1),("Login incorrect",1),("Authentication failure for admin",1),("Permission denied (publickey,password)",1),("ssh: authentication failed",1),("hydra: invalid credentials supplied",1),("530 Login authentication failed",1)]
SAMPLES["TIMEOUT"] = [("Operation timed out",1),("ETIMEDOUT: connection timed out",1),("Read timeout exceeded",1),("timed out after 30 seconds",1),("connection timeout",1),("nmap: host timeout reached",1),("curl: (28) Operation timed out",28),("request timed out",1),("Timeout occurred during the request",1),("connect: Connection timed out",1)]
SAMPLES["VERSION_MISMATCH"] = [("Unrecognized option in this version",1),("deprecated flag removed in version 3",1),("requires gobuster version 3.6 or higher",1),("unknown option --v2",1),("this option is deprecated",1),("feature requires version 2.0+",1),("--old-flag: deprecated use --new-flag",1),("Unrecognized option --legacy",1),("nmap: --datadir deprecated in this build",1),("requires newer version of the tool",1)]

CLASSES = list(SAMPLES.keys())

def classify(stderr, code):
    cls, conf = regex_clf.classify(stderr, code)
    if cls is None and HAS_EMBED:
        cls, conf = embed_clf.classify(stderr)
    return cls

records = []
per_class = {c: {"tp":0,"fp":0,"fn":0,"total":0} for c in CLASSES}

for true_cls, samples in SAMPLES.items():
    for stderr, code in samples:
        pred = classify(stderr, code)
        per_class[true_cls]["total"] += 1
        if pred == true_cls:
            per_class[true_cls]["tp"] += 1
        else:
            per_class[true_cls]["fn"] += 1
            if pred in per_class:
                per_class[pred]["fp"] += 1
        records.append({"true": true_cls, "pred": pred, "stderr": stderr})

print("CLASS".ljust(22) + "PREC".ljust(8) + "RECALL".ljust(8) + "F1".ljust(8) + "N")
print("-" * 54)
f1s = []
total_correct = 0
total_n = 0
for c in CLASSES:
    d = per_class[c]
    tp, fp, fn = d["tp"], d["fp"], d["fn"]
    prec = tp/(tp+fp) if (tp+fp) else 0.0
    rec  = tp/(tp+fn) if (tp+fn) else 0.0
    f1   = 2*prec*rec/(prec+rec) if (prec+rec) else 0.0
    f1s.append(f1)
    total_correct += tp
    total_n += d["total"]
    print(c.ljust(22) + str(round(prec,2)).ljust(8) + str(round(rec,2)).ljust(8) + str(round(f1,2)).ljust(8) + str(d["total"]))

macro_f1 = sum(f1s)/len(f1s)
accuracy = total_correct/total_n
print("-" * 54)
print("Overall accuracy : " + str(round(accuracy*100,1)) + "%  (" + str(total_correct) + "/" + str(total_n) + ")")
print("Macro F1-Score   : " + str(round(macro_f1,3)) + "  (" + str(round(macro_f1*100,1)) + "%)")
print("Proposal target  : F1 > 90%")
print("Result           : " + ("MET" if macro_f1 > 0.90 else "BELOW TARGET"))

with open("benchmark_f1_results.json","w") as f:
    json.dump({"per_class": per_class, "macro_f1": macro_f1, "accuracy": accuracy, "records": records}, f, indent=2)
print()
print("Full results written to benchmark_f1_results.json")
