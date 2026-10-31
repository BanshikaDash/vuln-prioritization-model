"""Prints the tables and columns of inthewild.db so the loader can be written."""
import sqlite3
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "inthewild.db"
con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
tables = [r[0] for r in con.execute("select name from sqlite_master where type='table'")]
for t in tables:
    cols = [r[1] for r in con.execute(f'PRAGMA table_info("{t}")')]
    n = con.execute(f'select count(*) from "{t}"').fetchone()[0]
    print(f"\n{t}  ({n} rows)\n  columns: {cols}")
    row = con.execute(f'select * from "{t}" limit 1').fetchone()
    if row:
        print("  sample:", [str(x)[:60] for x in row])
