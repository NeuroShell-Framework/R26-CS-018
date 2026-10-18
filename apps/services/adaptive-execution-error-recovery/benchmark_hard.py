import json, subprocess, urllib.request

IMAGE = "neuroshell-kali"
API = "http://localhost:8003/execute"

SCEN = [
 ("masscan -p80 192.168.1.1","masscan","NETWORK_SCAN","tool_not_installed"),
 ("wpscan --url http://127.0.0.1","wpscan","VULNERABILITY_AUDIT","tool_not_installed"),
 ("dirsearch -u http://127.0.0.1","dirsearch","DIRECTORY_BRUTEFORCE","tool_not_installed"),
 ("gobuster dir -u http://127.0.0.1 -w /wrong/nonexistent/path.txt","gobuster","DIRECTORY_BRUTEFORCE","bad_wordlist_path"),
 ("gobuster dir -u http://127.0.0.1 -w /also/missing/list.txt","gobuster","DIRECTORY_BRUTEFORCE","bad_wordlist_path"),
 ("gobuster dir -u http://127.0.0.1 -w /tmp/does-not-exist.txt","gobuster","DIRECTORY_BRUTEFORCE","bad_wordlist_path"),
]

def run_in_container(cmd, timeout=90):
    try:
        p = subprocess.run(["docker","run","--rm",IMAGE,"bash","-c","sleep 1 && " + cmd], capture_output=True, text=True, timeout=timeout)
        return p.returncode
    except Exception:
        return 1

def rule_based_fix(cmd, tool):
    tokens = cmd.split()
    kept = [tokens[0]]
    i = 1
    while i < len(tokens):
        t = tokens[i]
        if t.startswith("-") and len(t) > 1 and not t[1:].isdigit() and t not in ("-w","-u","-h","-sV"):
            i += 1
            continue
        kept.append(t)
        i += 1
    return run_in_container(" ".join(kept)) == 0

def engine_recover(cmd, tool, intent, sid):
    body = json.dumps({"command":cmd,"tool":tool,"session_id":sid,"intent_ref":intent,"estimated_duration":"short"}).encode()
    req = urllib.request.Request(API, data=body, headers={"Content-Type":"application/json"})
    try:
        with urllib.request.urlopen(req, timeout=200) as resp:
            r = json.loads(resp.read().decode())
        return r.get("status") in ("recovered","success")
    except Exception:
        return False

print("HARDER scenarios: rule-based flag-stripping should fail, engine should recover")
print()
print("SCENARIO".ljust(40) + "TYPE".ljust(22) + "RULE".ljust(10) + "ENGINE")
print("-" * 82)
rule_rec = 0
eng_rec = 0
records = []
for cmd, tool, intent, htype in SCEN:
    r_ok = rule_based_fix(cmd, tool)
    e_ok = engine_recover(cmd, tool, intent, "hard-" + tool)
    if r_ok: rule_rec += 1
    if e_ok: eng_rec += 1
    label = (tool + " " + htype)[:38]
    print(label.ljust(40) + htype.ljust(22) + ("recovered" if r_ok else "failed").ljust(10) + ("recovered" if e_ok else "failed"))
    records.append({"cmd":cmd,"tool":tool,"type":htype,"rule_recovered":r_ok,"engine_recovered":e_ok})

n = len(SCEN)
rule_rate = rule_rec/n*100
eng_rate = eng_rec/n*100
print("-" * 82)
print("HARDER SCENARIO COMPARISON (" + str(n) + " scenarios):")
print("  Rule-based baseline : " + str(round(rule_rate,1)) + "%  (" + str(rule_rec) + "/" + str(n) + ")")
print("  YOUR ENGINE         : " + str(round(eng_rate,1)) + "%  (" + str(eng_rec) + "/" + str(n) + ")")
print("  Engine advantage    : +" + str(round(eng_rate-rule_rate,1)) + " pts")

with open("benchmark_hard_results.json","w") as f:
    json.dump({"rule_rate":rule_rate,"engine_rate":eng_rate,"n":n,
               "rule_recovered":rule_rec,"engine_recovered":eng_rec,"records":records}, f, indent=2)
print()
print("Full results written to benchmark_hard_results.json")
