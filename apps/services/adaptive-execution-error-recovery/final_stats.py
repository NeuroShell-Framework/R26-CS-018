# Real medians + session-level fix rate from recovery_events.
import sqlite3, glob, os, statistics as st
db = (glob.glob("audit.db") + glob.glob("**/audit.db", recursive=True) + glob.glob("**/*.db", recursive=True))[0]
con = sqlite3.connect(db)
T = "recovery_events"

def med(q):
    vals = [r[0] for r in con.execute(q) if r[0] is not None]
    return st.median(vals) if vals else None

print("=== END-TO-END latency (ms): MEDIAN is the fair number ===")
print("  overall median :", round(med(f"SELECT total_latency_ms FROM {T}") or 0, 1))
print("  non-llm median :", round(med(f"SELECT total_latency_ms FROM {T} WHERE classification_method!='llm' OR classification_method IS NULL") or 0, 1))
print("  llm-only median:", round(med(f"SELECT total_latency_ms FROM {T} WHERE classification_method='llm'") or 0, 1))

print("\n=== CLASSIFICATION latency (ms): median per method ===")
for m in ("regex","llm"):
    print(f"  {m:6s} median:", round(med(f"SELECT classification_latency_ms FROM {T} WHERE classification_method='{m}'") or 0, 4))

print("\n=== % of errors among CLASSIFIED events (excluding None) ===")
rows = dict(con.execute(f"SELECT classification_method, COUNT(*) FROM {T} WHERE classification_method IS NOT NULL GROUP BY classification_method"))
tot = sum(rows.values())
for m,c in rows.items():
    print(f"  {str(m):6s}: {c:4d}  ({100*c/tot:.1f}%)")

print("\n=== SESSION-LEVEL FIX RATE (Table 8) ===")
sessions = [r[0] for r in con.execute(f"SELECT DISTINCT session_id FROM {T}")]
recovered = 0
for s in sessions:
    outs = [r[0] for r in con.execute(f"SELECT outcome FROM {T} WHERE session_id=?", (s,))]
    if any(o in ("recovered","success") for o in outs):
        recovered += 1
print(f"  total sessions (scenarios): {len(sessions)}")
print(f"  sessions recovered        : {recovered}")
print(f"  FIX RATE                  : {100*recovered/len(sessions):.1f}%" if sessions else "n/a")

print("\n=== SAFETY gate activity (real, from normal runs) ===")
tot = con.execute(f"SELECT COUNT(*) FROM {T}").fetchone()[0]
blk = con.execute(f"SELECT COUNT(*) FROM {T} WHERE safety_approved=0").fetchone()[0]
print(f"  total events: {tot} | allowed: {tot-blk} | blocked: {blk}")
print(f"  blocked low-confidence (<0.70): {con.execute(f'SELECT COUNT(*) FROM {T} WHERE safety_approved=0 AND confidence<0.7').fetchone()[0]}")
