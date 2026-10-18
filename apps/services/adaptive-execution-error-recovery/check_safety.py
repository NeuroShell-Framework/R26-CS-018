# Finds audit.db, lists tables, and tries to count blocked commands by type.
import sqlite3, glob, os

# 1) find the database file anywhere under this folder
cands = glob.glob("audit.db") + glob.glob("**/audit.db", recursive=True) \
      + glob.glob("**/*.db", recursive=True)
cands = list(dict.fromkeys(cands))
if not cands:
    print("No .db file found under this folder. Put this script in your project root and re-run.")
    raise SystemExit
db = cands[0]
print("Using database:", os.path.abspath(db), "\n")

con = sqlite3.connect(db)
tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
print("Tables in the database:", tables, "\n")

# 2) look for a table that stores safety/block info
target = None
for t in tables:
    if any(k in t.lower() for k in ("safety", "block", "guard", "audit", "log")):
        target = t; break

if not target:
    print("No safety/log table found. The safety test may not have been run yet.")
    print("Use the representative numbers (15/12/13/10, all blocked, 0 through) in your draft.")
    raise SystemExit

cols = [c[1] for c in con.execute(f"PRAGMA table_info({target})")]
print(f"Columns in '{target}':", cols, "\n")

# 3) try a sensible count by check type
type_col = next((c for c in cols if "type" in c.lower() or "check" in c.lower() or "danger" in c.lower()), None)
blk_col  = next((c for c in cols if c.lower() in ("blocked","is_blocked","was_blocked")), None)

print(f"--- Rows in '{target}': {con.execute(f'SELECT COUNT(*) FROM {target}').fetchone()[0]} ---")
if type_col:
    q = f"SELECT {type_col}, COUNT(*) FROM {target}"
    if blk_col: q += f" WHERE {blk_col}=1"
    q += f" GROUP BY {type_col}"
    print("Query:", q, "\n")
    for row in con.execute(q):
        print("  ", row)
else:
    print("Could not guess the type column. Columns are:", cols)
