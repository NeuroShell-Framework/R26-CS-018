# Inspects recovery_events to pull real fix-rate and error-type numbers.
import sqlite3, glob, os
db = (glob.glob("audit.db") + glob.glob("**/audit.db", recursive=True) + glob.glob("**/*.db", recursive=True))[0]
print("DB:", os.path.abspath(db), "\n")
con = sqlite3.connect(db)

cols = [c[1] for c in con.execute("PRAGMA table_info(recovery_events)")]
print("Columns in recovery_events:", cols, "\n")

n = con.execute("SELECT COUNT(*) FROM recovery_events").fetchone()[0]
print("Total rows:", n, "\n")

# show 3 sample rows so we can see the shape
print("--- 3 sample rows ---")
for row in con.execute("SELECT * FROM recovery_events LIMIT 3"):
    print(row)
print()

# try common breakdowns if the columns exist
def col(*names):
    for x in names:
        for c in cols:
            if c.lower() == x: return c
    return None

succ = col("success","is_success","recovered","fixed","resolved")
etype = col("error_type","error_class","class","type")
strat = col("strategy","fix_strategy","mutation","action")

if succ:
    print(f"--- {succ} breakdown (fix rate) ---")
    for row in con.execute(f"SELECT {succ}, COUNT(*) FROM recovery_events GROUP BY {succ}"):
        print("  ", row)
    print()
if etype:
    print(f"--- {etype} breakdown ---")
    for row in con.execute(f"SELECT {etype}, COUNT(*) FROM recovery_events GROUP BY {etype} ORDER BY COUNT(*) DESC"):
        print("  ", row)
    print()
if strat:
    print(f"--- {strat} breakdown ---")
    for row in con.execute(f"SELECT {strat}, COUNT(*) FROM recovery_events GROUP BY {strat}"):
        print("  ", row)
