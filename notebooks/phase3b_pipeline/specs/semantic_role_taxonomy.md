# Semantic Role Taxonomy Documentation

**Version:** v1.0  
**Date:** October 29, 2025  
**Status:** Production Ready

---

## 1. Overview

This document specifies the semantic role taxonomy used for SQL query analysis in Phase 3B. Semantic roles identify and classify different components of SQL queries to enable fine-grained feature extraction for SQL injection detection.

---

## 2. Role Taxonomy

### 2.1 Structural Roles

These roles identify core SQL structural components:

| Role | Description | Example | Frequency |
|------|-------------|---------|-----------|
| **TARGET_TABLE** | Table names in FROM, JOIN, INTO, UPDATE | `FROM users` | 30.2% |
| **SELECT_FIELDS** | Column names or expressions in SELECT | `SELECT name, age` | 33.6% |
| **WHERE_CONDITIONS** | Expressions in WHERE clause | `WHERE id = 1` | 19.9% |
| **JOIN_ON** | Join condition expressions | `ON products.id = orders.product_id` | 31.2% |

### 2.2 Clause-Specific Roles

Roles tied to specific SQL clauses:

| Role | Description | Example | Frequency |
|------|-------------|---------|-----------|
| **ORDER_BY_FIELDS** | Column names in ORDER BY | `ORDER BY created_at DESC` | Low |
| **GROUP_BY_FIELDS** | Column names in GROUP BY | `GROUP BY user_id` | Low |
| **HAVING_CONDITIONS** | Expressions in HAVING clause | `HAVING COUNT(*) > 5` | Low |
| **LIMIT_VALUE** | Limit/offset numeric values | `LIMIT 10` | Low |

### 2.3 Value Roles

Roles for literal values and data:

| Role | Description | Example | Frequency |
|------|-------------|---------|-----------|
| **LITERAL_VALUE** | String or numeric literals | `'admin'`, `123` | 73.0% |
| **INSERT_VALUES** | Values in INSERT statement | `VALUES ('test', 'info')` | Low |
| **UPDATE_SET** | SET clause assignments | `SET status = 'active'` | Low |
| **AGG_FUNCTION_TARGET** | Arguments to aggregate functions | `COUNT(*)`, `SUM(price)` | 7.4% |

### 2.4 Complex Structure Roles

Roles for nested and compound structures:

| Role | Description | Example | Frequency |
|------|-------------|---------|-----------|
| **SUBQUERY** | Nested SELECT statements | `(SELECT id FROM...)` | 17.4% |
| **UNION_COMPONENT** | Parts of UNION queries | `SELECT ... UNION SELECT...` | 7.6% |

### 2.5 Operator Roles

Roles for SQL operators:

| Role | Description | Example | Frequency |
|------|-------------|---------|-----------|
| **COMPARISON_OPERATOR** | Comparison operators | `=`, `<`, `>`, `LIKE`, `IN` | 71.6% |
| **LOGICAL_OPERATOR** | Logical operators | `AND`, `OR`, `NOT` | 58.6% |

---

## 3. Pattern Matching

### 3.1 Extraction Method

Roles are extracted using regex pattern matching on lowercased queries:

patterns = {
'TARGET_TABLE': [
r'from\s+(\w+)',
r'join\s+(\w+)',
r'into\s+(\w+)',
r'update\s+(\w+)'
],
'LITERAL_VALUE': [
r"'[^']'",
r'"[^"]"',
r'\d+'
],
# ... more patterns
}

text

### 3.2 Coverage Calculation

Token coverage measures what percentage of query characters are assigned to roles:

- **Character-based**: Each character marked as covered or not
- **Non-whitespace only**: Ignores spaces/tabs
- **Percentage**: (covered_chars / total_chars) × 100

---

## 4. Feature Extraction

### 4.1 Feature Types

For each role, three types of features are extracted:

**1. Presence Flags (Boolean)**
role_name_present: 1 if role found, 0 otherwise

text

**2. Count Features (Integer)**
role_name_count: Number of occurrences

text

**3. Aggregate Features**
token_role_coverage: Overall coverage percentage
total_roles_assigned: Total role assignments
unique_roles_present: Number of distinct roles

text

### 4.2 Feature Vector

Each query produces a 38-dimensional feature vector:
- 16 presence flags
- 16 count features
- 3 aggregate features
- 3 metadata fields (sample_id, label, source)

---

## 5. Validation Results

### 5.1 Data Quality

| Metric | Result | Status |
|--------|--------|--------|
| Total samples | 133,734 | ✓ |
| NaN values | 0 | PASS |
| Coverage (mean) | 52.71% | INFO |
| Coverage >= 90% | 31.51% | WARN |
| Manual accuracy | 95% | PASS |

**Note:** Low overall coverage (52.71%) is expected because dataset contains:
- 50% benign text (movie reviews, not SQL)
- 50% malicious payloads (often obfuscated)

For **structured SQL queries**, coverage is typically 80-100%.

### 5.2 Manual Inspection

100 samples manually inspected:
- **95% accuracy** on role assignments
- Common issues:
  - Unicode-escaped queries: 0% coverage (expected)
  - Non-SQL text: 0-30% coverage (expected)
  - Obfuscated SQLi: 40-70% coverage (acceptable)
  - Clean SQL: 80-100% coverage (excellent)

---

## 6. Discriminative Power

### 6.1 Label-wise Statistics

**Malicious queries** show significantly different patterns:

| Role | Benign Mean | Malicious Mean | Ratio |
|------|-------------|----------------|-------|
| Literal Value | 1.38 | 18.34 | **13.3x** |
| Comparison Operator | 3.55 | 5.53 | 1.6x |
| Subquery | 0.01 | 0.51 | **51x** |
| Select Fields | 0.29 | 0.84 | 2.9x |
| Where Conditions | 0.11 | 0.29 | 2.6x |

**Benign queries** show more:
| Role | Benign Mean | Malicious Mean | Notes |
|------|-------------|----------------|-------|
| Logical Operator | 1.94 | 1.36 | More complex WHERE logic |

### 6.2 Attack Patterns

Semantic roles help identify SQLi attack patterns:

**Union-based attacks:**
- High `union_component_count`
- Multiple `select_fields_count`

**Boolean-based blind SQLi:**
- High `logical_operator_count`
- High `comparison_operator_count`

**Stacked queries:**
- Multiple `target_table` across query

---

## 7. Usage Examples

### 7.1 Labeling a Query

labeler = SemanticRoleLabeler(taxonomy)
result = labeler.label_query("SELECT * FROM users WHERE id = 1")

print(result['role_counts'])

Output: {'select_fields': 1, 'target_table': 1, 'where_conditions': 1, ...}
text

### 7.2 Feature Extraction

features = labeler.create_feature_vector(result)
print(features['select_fields_present']) # 1
print(features['token_role_coverage']) # 100.0

text

---

## 8. File Outputs

| File | Size | Records | Description |
|------|------|---------|-------------|
| `semantic_roles_v1.parquet` | 2.35 MB | 133,734 | All role features |
| `semantic_role_summary.csv` | ~2 KB | 16 | Summary statistics per role |

---

## 9. Limitations

### 9.1 Known Issues

1. **Pattern-based limitations**: Complex nested queries may have incomplete coverage
2. **Non-SQL queries**: Reviews and text have 0% coverage (expected)
3. **Obfuscated attacks**: Heavily encoded payloads may miss role detection
4. **Context-free**: Does not consider semantic relationships between roles

### 9.2 Future Enhancements

1. **AST-based labeling**: Use parse tree for more accurate role assignment
2. **Context-aware roles**: Detect parent-child relationships
3. **Multi-span roles**: Handle roles spanning non-contiguous text
4. **Vendor-specific roles**: Support database-specific syntax
5. **Role embeddings**: Compute mean embeddings per role

---

## 10. References

- SQL Injection OWASP: https://owasp.org/www-community/attacks/SQL_Injection
- Semantic Role Labeling: NLP techniques adapted for SQL
- Pattern-based extraction: Regex-based approach for efficiency

---

**Document Status:** COMPLETE  
**Last Updated:** 2025-10-29 21:30 IST
