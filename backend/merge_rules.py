"""Merge simplified rules with existing detailed rules"""
import json
from pathlib import Path

# Load existing rules
rules_dir = Path(__file__).parent.parent / "rules"
existing_path = rules_dir / "rules_machine.json"

print(f"Loading existing rules from: {existing_path}")
with open(existing_path, 'r') as f:
    existing_data = json.load(f)
    existing_rules = existing_data.get('rules', [])

print(f"  Loaded {len(existing_rules)} existing rules")

# Create 10 high-priority simple rules (will be checked first)
simple_rules = [
    {
        "rule_id": "SIMPLE-001",
        "name": "OR Tautology (digit=digit)",
        "category": "Tautology-Simple",
        "description": "Catches OR 1=1, OR 2=2, etc.",
        "regex": r"(?i)\bOR\s+\d+\s*=\s*\d+",
        "confidence": 0.95,
        "priority": 10,
        "enabled": True,
        "notes": "Simple catch-all for numeric tautologies"
    },
    {
        "rule_id": "SIMPLE-002",
        "name": "OR String Equality",
        "category": "Tautology-Simple",
        "regex": r"(?i)\bOR\s+['\"][^'\"]{1,30}['\"]\s*=\s*['\"][^'\"]{1,30}['\"]",
        "confidence": 0.90,
        "priority": 9,
        "enabled": True
    },
    {
        "rule_id": "SIMPLE-003",
        "name": "UNION SELECT",
        "category": "Union-Simple",
        "regex": r"(?i)\bUNION\s+(ALL\s+)?SELECT\b",
        "confidence": 0.98,
        "priority": 10,
        "enabled": True
    },
    {
        "rule_id": "SIMPLE-004",
        "name": "SQL Comments",
        "category": "Comment-Simple",
        "regex": r"(--|#|/\*)",
        "confidence": 0.70,
        "priority": 7,
        "enabled": True
    },
    {
        "rule_id": "SIMPLE-005",
        "name": "Stacked Query (DROP/DELETE/etc)",
        "category": "Stacked-Simple",
        "regex": r"(?i);\s*(DROP|DELETE|UPDATE|INSERT|ALTER|CREATE|TRUNCATE)\b",
        "confidence": 0.95,
        "priority": 10,
        "enabled": True
    },
    {
        "rule_id": "SIMPLE-006",
        "name": "SQL Functions (CONCAT, CHAR, etc)",
        "category": "Function-Simple",
        "regex": r"(?i)\b(CONCAT|CHAR|ASCII|SUBSTRING|LOAD_FILE|BENCHMARK)\s*\(",
        "confidence": 0.80,
        "priority": 8,
        "enabled": True
    },
    {
        "rule_id": "SIMPLE-007",
        "name": "Time-Based (SLEEP, WAITFOR)",
        "category": "Time-Simple",
        "regex": r"(?i)\b(SLEEP|WAITFOR|DELAY|BENCHMARK)\s*\(",
        "confidence": 0.92,
        "priority": 9,
        "enabled": True
    },
    {
        "rule_id": "SIMPLE-008",
        "name": "Boolean Conditions (AND/OR with comparison)",
        "category": "Boolean-Simple",
        "regex": r"(?i)\b(AND|OR)\s+\d+\s*[<>!=]+\s*\d+",
        "confidence": 0.75,
        "priority": 7,
        "enabled": True
    },
    {
        "rule_id": "SIMPLE-009",
        "name": "Information Schema",
        "category": "Info-Simple",
        "regex": r"(?i)\bINFORMATION_SCHEMA\b",
        "confidence": 0.90,
        "priority": 9,
        "enabled": True
    },
    {
        "rule_id": "SIMPLE-010",
        "name": "Hex/Char Encoding",
        "category": "Encoding-Simple",
        "regex": r"(?i)(0x[0-9a-f]+|CHAR\(|CHR\()",
        "confidence": 0.75,
        "priority": 7,
        "enabled": True
    }
]

# Merge: Simple rules first (checked first), then detailed rules
merged_rules = {
    "version": "1.3.0-merged",
    "created_date": "2025-11-24",
    "total_rules": len(simple_rules) + len(existing_rules),
    "description": "Merged: 10 simple catch-all rules + 74 detailed rules",
    "rules": simple_rules + existing_rules
}

# Save merged rules
output_path = rules_dir / "rules_merged.json"
with open(output_path, 'w') as f:
    json.dump(merged_rules, f, indent=2)

print(f"\n✓ Created merged rules file: {output_path}")
print(f"  Total rules: {merged_rules['total_rules']}")
print(f"    - Simple catch-all: {len(simple_rules)}")
print(f"    - Detailed rules: {len(existing_rules)}")
print(f"\nMerged rules will be checked in order:")
print(f"  1. Simple rules (priority 7-10) - fast pattern matching")
print(f"  2. Detailed rules (your original 74) - comprehensive coverage")
