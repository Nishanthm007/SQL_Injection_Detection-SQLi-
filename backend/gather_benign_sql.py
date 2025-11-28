import glob
import re
import os

OUTPUT_PATH = "data/benign_queries_raw.txt"
os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
sql_queries = set()

# 1. Scrape .sql files from your local repos (expand paths as needed)
for sqlfile in glob.glob("../../**/*.sql", recursive=True):
    with open(sqlfile, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            # crude filter: keep lines likely to be queries
            if re.match(r"(?i)^(select|insert|update|delete)\s", line):
                sql_queries.add(line)

# 2. (Optional) Add known benign test queries by appending lines manually
# sql_queries.add("SELECT id FROM users WHERE id = 1;")

# 3. Write to output file
with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    for q in sql_queries:
        f.write(q + "\n")

print(f"Wrote {len(sql_queries)} queries to {OUTPUT_PATH}")
