import json, urllib.request

API = "http://localhost:8003/execute"

# Fixable WRONG_SYNTAX scenarios. gobuster now targets reachable 127.0.0.1 (in-container nginx).
SCEN = [
 ("nmap --totally-invalid-flag-xyz 192.168.1.1","nmap","NETWORK_SCAN",True),
 ("nmap -sV --bad-opt 192.168.1.1","nmap","NETWORK_SCAN",True),
 ("nmap --xyz-flag 192.168.99.99","nmap","NETWORK_SCAN",True),
 ("nmap -zz 192.168.1.1","nmap","NETWORK_SCAN",True),
 ("nmap --invalid 192.168.1.50","nmap","NETWORK_SCAN",True),
 ("nikto --invalid-option-xyz -h 192.168.1.10","nikto","VULNERABILITY_AUDIT",True),
 ("nikto --bad-flag -h 192.168.1.10","nikto","VULNERABILITY_AUDIT",True),
 ("nikto -XYZ -h 192.168.1.10","nikto","VULNERABILITY_AUDIT",True),
 ("nikto --wrong -h 192.168.1.20","nikto","VULNERABILITY_AUDIT",True),
 ("nikto --nope -h 192.168.1.30","nikto","VULNERABILITY_AUDIT",True),
 ("gobuster --totally-invalid-flag-xyz dir -u http://127.0.0.1 -w /usr/share/wordlists/dirb/common.txt","gobuster","DIRECTORY_BRUTEFORCE",True),
 ("gobuster --bad dir -u http://127.0.0.1 -w /usr/share/wordlists/dirb/common.txt","gobuster","DIRECTORY_BRUTEFORCE",True),
 ("gobuster -ZZ dir -u http://127.0.0.1 -w /usr/share/wordlists/dirb/common.txt","gobuster","DIRECTORY_BRUTEFORCE",True),
 ("gobuster --xyz dir -u http://127.0.0.1 -w /usr/share/wordlists/dirb/common.txt","gobuster","DIRECTORY_BRUTEFORCE",True),
 ("gobuster --nope dir -u http://127.0.0.1 -w /usr/share/wordlists/dirb/common.txt","gobuster","DIRECTORY_BRUTEFORCE",True),
]

def call(cmd, tool, intent, sid):
    body = json.dumps({"command":cmd,"tool":tool,"session_id":sid,"intent_ref":intent,"estimated_duration":"short"}).encode()
    req = urllib.request.Request(API, data=body, headers={"Content-Type":"application/json"})
    with urllib.request.urlopen(req, timeout=200) as resp:
        return json.loads(resp.read().decode())

results = []
print("SCENARIO".ljust(40) + "STATUS".ljust(12) + "ATTEMPTS".ljust(10) + "LATENCY(ms)")
print("-" * 74)
for i, (cmd, tool, intent, fixable) in enumerate(SCEN):
    sid = "rec2-" + str(i+1)
    try:
        r = call(cmd, tool, intent, sid)
        status = r.get("status","?")
        latency = r.get("latency_ms",0)
        rlog = r.get("recovery_log",[])
        fr = r.get("failure_report") or {}
        attempts = fr.get("attempts", len(rlog) if rlog else 1)
    except Exception as e:
        status, latency, attempts, r = "ERROR:"+type(e).__name__, 0, 0, {"error":str(e)}
    label = (tool + " " + cmd.split()[1])[:38]
    print(label.ljust(40) + str(status).ljust(12) + str(attempts).ljust(10) + str(latency))
    results.append({"cmd":cmd,"tool":tool,"fixable":fixable,"status":status,"latency_ms":latency,"attempts":attempts,"full":r})

fixable = [x for x in results if x["fixable"] and not str(x["status"]).startswith("ERROR")]
recovered = [x for x in fixable if x["status"] in ("recovered","success")]
n_fix = len(fixable)
n_rec = len(recovered)
recovery_rate = (n_rec/n_fix*100) if n_fix else 0.0

lats = [x["latency_ms"] for x in results if not str(x["status"]).startswith("ERROR") and x["latency_ms"]>0]
avg_lat = sum(lats)/len(lats) if lats else 0
rec_lats = [x["latency_ms"] for x in recovered if x["latency_ms"]>0]
avg_rec_lat = sum(rec_lats)/len(rec_lats) if rec_lats else 0
att = [x["attempts"] for x in recovered if x["attempts"]>0]
mean_att = sum(att)/len(att) if att else 0

print("-" * 74)
print("Fixable scenarios       : " + str(n_fix))
print("Recovered               : " + str(n_rec))
print("RECOVERY RATE           : " + str(round(recovery_rate,1)) + "%   (target >= 80%)  " + ("MET" if recovery_rate>=80 else "BELOW"))
print("Avg latency (all)       : " + str(round(avg_lat)) + " ms")
print("Avg latency (recovered) : " + str(round(avg_rec_lat)) + " ms")
print("Mean attempts-to-success: " + str(round(mean_att,2)))

with open("benchmark_recovery_results.json","w") as f:
    json.dump({"recovery_rate":recovery_rate,"n_fixable":n_fix,"n_recovered":n_rec,
               "avg_latency_ms":avg_lat,"avg_recovered_latency_ms":avg_rec_lat,
               "mean_attempts":mean_att,"results":results}, f, indent=2)
print()
print("Full results written to benchmark_recovery_results.json")
