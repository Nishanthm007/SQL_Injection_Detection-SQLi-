#!/usr/bin/env python3
"""
Generate a synthetic labeled SQL test dataset for evaluation.

Outputs:
    backend/test_dataset.csv

Usage (from project root or backend folder):
    cd Major-Project(SQLi)/backend
    python scripts/generate_test_dataset.py
"""
import random
import csv
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "test_dataset.csv"
SEED = 12345
TOTAL = 5000
MALICIOUS = TOTAL // 2
BENIGN = TOTAL - MALICIOUS

random.seed(SEED)

# helper pools
names = ["alice", "bob", "charlie", "dave", "eve", "mallory", "trent"]
tables = ["users", "orders", "products", "sessions", "customers", "logs", "accounts", "payments"]
cols = ["id", "name", "email", "price", "total", "created_at", "status", "role", "credit_card"]
nums = list(range(1, 500))

def tautology_variants():
    templates = [
        "1 OR 1=1",
        "1 OR 1=1; --",
        "' OR '1'='1",
        "\" OR \"1\"=\"1\"",
        "' OR 'a'='a",
        "admin' OR '1'='1' --",
        "1' OR 1=1#"
    ]
    t = random.choice(templates)
    return t

def union_variants():
    payloads = [
        "' UNION SELECT username, password FROM users --",
        "' UNION ALL SELECT 1,2,3 --",
        "' UNION SELECT null,version(),null --",
        "' UNION SELECT email,credit_card FROM customers --",
        "' UNION SELECT name, (SELECT group_concat(name) FROM sqlite_master) --"
    ]
    return random.choice(payloads)

def comment_variants():
    templates = [
        f"admin'/*test*/--",
        f"1 OR 1=1; /* bypass */",
        "SELECT * FROM users WHERE id = 1 -- comment",
        "SELECT 1; --"
    ]
    return random.choice(templates)

def stacked_variants():
    templates = [
        "1; DROP TABLE users;",
        "0; DELETE FROM logs; --",
        "42; UPDATE users SET role='admin' WHERE id=1;",
        "1; INSERT INTO admin_accounts (user) VALUES ('pwn');"
    ]
    return random.choice(templates)

def time_based_variants():
    templates = [
        "1' AND SLEEP(5) --",
        "1 AND BENCHMARK(1000000,MD5(1)) --",
        "WAITFOR DELAY '0:0:5'",
        "IF(1=1, SLEEP(3), 0)"
    ]
    return random.choice(templates)

def error_based_variants():
    templates = [
        "1 OR updatexml(1,concat(0x7e,version(),0x7e),1)",
        "1 OR extractvalue(1,concat(0x7e,user(),0x7e))",
        "' OR (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT user()), FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x) a) --"
    ]
    return random.choice(templates)

def obfuscated_variants():
    templates = [
        "1 oR   1 =    1",
        "1/**/OR/**/1/**/=/**/1",
        "'/**/OR/**/'x'='x",
        "''' OR ''''='"
    ]
    return random.choice(templates)

def blind_variants():
    templates = [
        "' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a' --",
        "' AND ASCII(SUBSTRING((SELECT @@version),1,1))>0 --"
    ]
    return random.choice(templates)

def random_malicious():
    pick = random.random()
    if pick < 0.18:
        return tautology_variants()
    elif pick < 0.36:
        return union_variants()
    elif pick < 0.54:
        return comment_variants()
    elif pick < 0.68:
        return stacked_variants()
    elif pick < 0.82:
        return time_based_variants()
    elif pick < 0.92:
        return error_based_variants()
    else:
        return obfuscated_variants()

# Benign templates
def benign_simple_select():
    t = random.choice(tables)
    c = random.sample(cols, k=min(2, len(cols)))
    q = f"SELECT {', '.join(c)} FROM {t} WHERE id = {random.choice(nums)};"
    return q

def benign_like():
    t = random.choice(tables)
    col = random.choice(cols)
    w = random.choice(["widget", "service", "alpha", "toy", "book"])
    return f"SELECT * FROM {t} WHERE {col} LIKE '%{w}%';"

def benign_insert():
    t = random.choice(tables)
    if t in ("orders", "payments"):
        return f"INSERT INTO {t} (id, total) VALUES ({random.choice(nums)}, {random.choice([9.99, 19.95, 49.00, 99.95])});"
    else:
        name = random.choice(names)
        return f"INSERT INTO {t} (name) VALUES ('{name}');"

def benign_update():
    t = random.choice(tables)
    col = random.choice(cols)
    return f"UPDATE {t} SET {col} = {random.choice([0,1,2,3,10,'NULL'])} WHERE id = {random.choice(nums)};"

def benign_delete():
    t = random.choice(tables)
    return f"DELETE FROM {t} WHERE updated_at < '2024-01-01';"

def benign_join():
    return "SELECT u.id, o.order_id FROM users u JOIN orders o ON u.id=o.user_id WHERE o.total > 50;"

def benign_aggregate():
    return "SELECT status, COUNT(*) FROM orders GROUP BY status ORDER BY COUNT(*) DESC;"

def benign_complex():
    t = random.choice(tables)
    return f"SELECT {', '.join(random.sample(cols,2))} FROM {t} WHERE {random.choice(cols)} > {random.choice(nums)} ORDER BY created_at DESC LIMIT 10;"

benign_generators = [
    benign_simple_select,
    benign_like,
    benign_insert,
    benign_update,
    benign_delete,
    benign_join,
    benign_aggregate,
    benign_complex
]

# Build dataset
rows = []

# Malicious examples
for i in range(MALICIOUS):
    q = random_malicious()
    # small randomization: sometimes embed in a longer SELECT context to look realistic
    if random.random() < 0.25:
        t = random.choice(tables)
        q = f"SELECT * FROM {t} WHERE {q}"
    rows.append((q, 1))

# Benign examples
for i in range(BENIGN):
    gen = random.choice(benign_generators)
    q = gen()
    rows.append((q, 0))

# Shuffle final dataset
random.shuffle(rows)

# Write to CSV
OUT.parent.mkdir(parents=True, exist_ok=True)
with OUT.open("w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["query", "label"])
    for q, lab in rows:
        writer.writerow([q, lab])

# Summary
mal = sum(1 for _, l in rows if l == 1)
ben = sum(1 for _, l in rows if l == 0)
print(f"Wrote {len(rows)} rows to: {OUT.resolve()}")
print(f"Malicious: {mal}, Benign: {ben}")
print("Sample rows:")
for i in range(10):
    print(i+1, rows[i])
