"""Debug rule matching"""
import re

test_query = "SELECT * FROM users WHERE id=1 OR 1=1--"
print(f"Test query: {test_query}\n")

# Test different patterns
patterns = [
    ("Original Rule 1", r"(?i)(['\"]|^)\s*OR\s+['\"]*\d+\s*=\s*\d+['\"]*"),
    ("Simpler: OR digit=digit", r"(?i)\bOR\s+\d+\s*=\s*\d+"),
    ("Even simpler: OR 1=1", r"(?i)OR\s+1\s*=\s*1"),
]

for name, pattern in patterns:
    print(f"{name}:")
    print(f"  Pattern: {pattern}")
    match = re.search(pattern, test_query, re.IGNORECASE)
    if match:
        print(f"  ✓ MATCHED: '{match.group()}'")
    else:
        print(f"  ✗ No match")
    print()
