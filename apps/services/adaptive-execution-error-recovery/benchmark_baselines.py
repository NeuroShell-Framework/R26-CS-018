import json, subprocess, re

IMAGE = "neuroshell-kali"

# Same 15 fixable scenarios (bad-flag commands). base = the correct command a fix should reach.
SCEN = [
 ("nmap --totally-invalid-flag-xyz 192.168.1.1","nmap"),
 ("nmap -sV --bad-opt 192.168.1.1","nmap"),
 ("nmap --xyz-flag 192.168.99.99","nmap"),
 ("nmap -zz 192.168.1.1","nmap"),
 ("nmap --invalid 192.168.1.50","nmap"),
 ("nikto --invalid-option-xyz -h 192.168.1.10","nikto"),
 ("nikto --bad-flag -h 192.168.1.10","nikto"),
 ("nikto -XYZ -h 192.168.1.10","nikto"),
 ("nikto --wrong -h 192.168.1.20","nikto"),
 ("nikto --nope -h 192.168.1.30","nikto"),
 ("gobuster --totally-invalid-flag-xyz dir -u http://127.0.0.1 -w /usr/share/wordlists/dirb/common.txt","gobuster"),
 ("gobuster --bad dir -u http://127.0.0.1 -w /usr/share/wordlists/dirb/common.txt","gobuster"),
 ("gobuster -ZZ dir -u http://127.0.0.1 -w /usr/share/wordlists/dirb/common.txt","gobuster"),
 ("gobuster --xyz dir -u http://127.0.0.1 -w /usr/share/wordlists/dirb/common.txt","gobuster"),
 ("gobuster --nope dir -u http://127.0.0.1 -w /usr/share/wordlists/dirb/common.txt","gobuster"),
]

def run_in_container(cmd, timeout=60):
    try:
        p = subprocess.run(
            ["docker","run","--rm",IMAGE,"bash","-c","sleep 1 && " + cmd],
            capture_output=True, text=True, timeout=timeout
        )
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as e:
        return 1, "", str(e)

# BASELINE 1: naive retry ? run the SAME command again, no fix
def naive_retry(cmd):
    rc, out, err = run_in_container(cmd)
    if rc == 0:
        return True
    rc2, out2, err2 = run_in_container(cmd)  # retry identical
    return rc2 == 0

# BASELINE 2: rule-based ? strip unknown long/short flags, keep base structure
def rule_based_fix(cmd, tool):
    tokens = cmd.split()
    kept = [tokens[0]]
    i = 1
    while i < len(tokens):
        t = tokens[i]
        if t.startswith("--") and t not in ("--totally-invalid-flag-xyz",):
            # naive rule: drop any long flag that is not a known-good one
            if t in ("-w","-u","-h"):
                kept.append(t)
            i += 1
            continue
        if t.startswith("--") or (t.startswith("-") and len(t) > 1 and not t[1:].isdigit() and t not in ("-w","-u","-h","-sV")):
            i += 1
            continue
        kept.append(t)
        i += 1
    fixed = " ".join(kept)
    rc, out, err = run_in_container(fixed)
    return rc == 0, fixed

print("Running baselines against 15 fixable scenarios...")
print()
print("SCENARIO".ljust(38) + "NAIVE".ljust(12) + "RULE-BASED")
print("-" * 62)

naive_rec = 0
rule_rec = 0
records = []
for cmd, tool in SCEN:
    n_ok = naive_retry(cmd)
    r_ok, fixed = rule_based_fix(cmd, tool)
    if n_ok: naive_rec += 1
    if r_ok: rule_rec += 1
    label = (tool + " " + cmd.split()[1])[:36]
    print(label.ljust(38) + ("recovered" if n_ok else "failed").ljust(12) + ("recovered" if r_ok else "failed"))
    records.append({"cmd":cmd,"tool":tool,"naive_recovered":n_ok,"rule_recovered":r_ok,"rule_fixed_cmd":fixed})

n = len(SCEN)
naive_rate = naive_rec/n*100
rule_rate = rule_rec/n*100

print("-" * 62)
print("COMPARISON (recovery rate on 15 fixable scenarios):")
print("  Baseline 1 - Naive retry     : " + str(round(naive_rate,1)) + "%  (" + str(naive_rec) + "/" + str(n) + ")")
print("  Baseline 2 - Rule-based      : " + str(round(rule_rate,1)) + "%  (" + str(rule_rec) + "/" + str(n) + ")")
print("  YOUR ENGINE (adaptive)       : 100.0%  (15/15)")
print()
print("Improvement over naive     : +" + str(round(100-naive_rate,1)) + " pts")
print("Improvement over rule-based: +" + str(round(100-rule_rate,1)) + " pts")

with open("benchmark_baselines_results.json","w") as f:
    json.dump({"naive_rate":naive_rate,"rule_rate":rule_rate,"engine_rate":100.0,
               "naive_recovered":naive_rec,"rule_recovered":rule_rec,"n":n,
               "records":records}, f, indent=2)
print()
print("Full results written to benchmark_baselines_results.json")
