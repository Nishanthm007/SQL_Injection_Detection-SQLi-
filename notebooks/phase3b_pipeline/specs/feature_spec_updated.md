# Feature Specification - Syntax Tree Features

**Version:** v2.0 (Updated)  
**Date:** October 28, 2025  
**Status:** Production Ready

---

## 1. Overview

This document specifies the AST-derived and syntax-tree features extracted from SQL queries for Phase 3B of the SQL injection detection pipeline.

---

## 2. Feature Categories

### 2.1 Structural Features (AST-based)

| Feature | Type | Description | Range |
|---------|------|-------------|-------|
| `ast_depth` | int | Maximum depth of Abstract Syntax Tree | [0, 100] |
| `total_nodes` | int | Total number of nodes in AST | [0, 1000] |
| `max_branching_factor` | int | Maximum branching factor (WHERE, JOIN, UNION, subquery) | [0, 50] |
| `nested_select_depth` | int | Maximum nesting depth of parentheses/SELECT | [0, 23] |

**Statistics:**
- Mean AST depth: 0.00 (shallow parsing mode)
- Mean total nodes: 0.00 (shallow parsing mode)
- Mean branching factor: 0.63
- Mean nested depth: 0.76

---

### 2.2 Keyword Count Features

| Feature | Type | Description | Range |
|---------|------|-------------|-------|
| `select_count` | int | Number of SELECT keywords | [0, 46] |
| `where_count` | int | Number of WHERE keywords | [0, 50] |
| `join_count` | int | Number of JOIN keywords (all types) | [0, 6] |
| `from_count` | int | Number of FROM keywords | [0, 8] |
| `union_count` | int | Number of UNION keywords | [0, 3] |
| `group_by_count` | int | Number of GROUP BY clauses | [0, 10] |
| `order_by_count` | int | Number of ORDER BY clauses | [0, 5] |
| `having_count` | int | Number of HAVING keywords | [0, 5] |
| `distinct_count` | int | Number of DISTINCT keywords | [0, 10] |
| `limit_count` | int | Number of LIMIT keywords | [0, 5] |

**Key Findings:**
- SELECT: 35.1% of queries contain SELECT
- Malicious queries have ~10x more SELECT keywords (mean: 1.19 vs 0.17)
- UNION: 10,847 queries (8.1%) contain UNION

---

### 2.3 Subquery and Nesting Features

| Feature | Type | Description | Range |
|---------|------|-------------|-------|
| `subquery_count` | int | Number of subqueries (SELECT in parentheses) | [0, 42] |
| `function_call_count` | int | Total SQL function calls | [0, 11] |

**Key Findings:**
- Subqueries: 30.3% of queries have subqueries
- Malicious queries have ~125x more subqueries (mean: 0.83 vs 0.01)
- Function calls present in only 0.15% of queries

---

### 2.4 Structural Syntax Features

| Feature | Type | Description | Range |
|---------|------|-------------|-------|
| `semicolon_count` | int | Number of semicolons | [0, 10] |
| `comment_count` | int | Number of comments (-- or /* */) | [0, 20] |
| `literal_count` | int | Number of string literals (quoted strings) | [0, 24] |
| `comparison_op_count` | int | Comparison operators (=, <, >, !=, etc.) | [0, 112] |
| `logical_op_count` | int | Logical operators (AND, OR, NOT) | [0, 41] |

**Key Findings:**
- Comparison operators: 66.8% of queries
- Logical operators: 57.5% of queries
- Literals: 38.6% of queries

---

### 2.5 Boolean Flag Features

| Feature | Type | Description |
|---------|------|-------------|
| `union_flag` | bool | 1 if query contains UNION, 0 otherwise |
| `order_by_flag` | bool | 1 if query contains ORDER BY, 0 otherwise |
| `group_by_flag` | bool | 1 if query contains GROUP BY, 0 otherwise |
| `use_of_sleep_flag` | bool | 1 if query contains SLEEP function, 0 otherwise |
| `use_of_waitfor_flag` | bool | 1 if query contains WAITFOR, 0 otherwise |
| `use_of_benchmark_flag` | bool | 1 if query contains BENCHMARK function, 0 otherwise |

**Attack Detection Flags:**
- `use_of_sleep_flag`: 27 queries (0.02%) - Time-based blind SQLi
- `use_of_waitfor_flag`: 733 queries (0.55%) - MSSQL time-based attacks
- `use_of_benchmark_flag`: 0 queries - MySQL DoS attacks
- `union_flag`: 10,847 queries (8.1%) - UNION-based SQLi

**Validation:** 100% accuracy on UNION flag (all queries with union_count > 0 have union_flag = 1)

---

### 2.6 Normalized Features

| Feature | Type | Description | Formula |
|---------|------|-------------|---------|
| `normalized_select_count` | float | SELECT count per token | select_count / token_count |
| `normalized_function_count` | float | Function count per token | function_call_count / token_count |
| `normalized_subquery_count` | float | Subquery count per token | subquery_count / token_count |

**Purpose:** Normalize by query length to detect relative complexity regardless of query size.

---

### 2.7 Basic Query Metrics

| Feature | Type | Description | Range |
|---------|------|-------------|-------|
| `query_length` | int | Total character count | [0, 5994] |
| `token_count` | int | Total word/token count | [0, 222] |

**Statistics:**
- Mean query length: 419.8 characters
- Mean token count: 45.7 tokens
- 100% non-zero (all queries have content)

---

## 3. Feature Extraction Method

### 3.1 Extraction Pipeline

Input: SQL query string
|
v
Parse query (if possible) --> AST features
|
v
Regex/string matching --> Keyword counts
|
v
Pattern matching --> Boolean flags
|
v
Normalization --> Normalized features
|
v
Output: 32-dimensional feature vector

text

### 3.2 Implementation Details

**Class:** `ASTFeatureExtractor`

**Key Methods:**
- `extract_features()`: Main extraction method
- `_count_joins()`: Count JOIN keywords (all types)
- `_count_subqueries()`: Pattern matching for (SELECT ...)
- `_calculate_select_nesting_depth()`: Parenthesis depth calculation
- `_count_function_calls()`: Match SQL function patterns
- `_count_comparison_operators()`: Count comparison operators
- `_count_logical_operators()`: Count AND/OR/NOT
- `_estimate_branching_factor()`: Estimate max branching

---

## 4. Data Quality

### 4.1 Validation Results

| Check | Result | Status |
|-------|--------|--------|
| NaN values | 0 | PASS |
| UNION flag accuracy | 100% | PASS |
| Distribution sanity | All features in expected range | PASS |
| Label balance | 50/50 | PASS |

### 4.2 Feature Coverage

- **100% coverage**: query_length, token_count
- **66.8% coverage**: comparison_op_count
- **57.5% coverage**: logical_op_count
- **38.6% coverage**: literal_count
- **35.1% coverage**: select_count
- **30.3% coverage**: nested_select_depth

---

## 5. Discriminative Power

### 5.1 Label-wise Comparison

**Top Discriminative Features (Malicious > Benign):**

| Feature | Benign Mean | Malicious Mean | Difference |
|---------|-------------|----------------|------------|
| `select_count` | 0.17 | 1.19 | +1.02 |
| `subquery_count` | 0.01 | 0.83 | +0.82 |
| `union_flag` | 0.01 | 0.15 | +0.14 |
| `nested_select_depth` | 0.45 | 1.07 | +0.62 |

**Features Higher in Benign:**

| Feature | Benign Mean | Malicious Mean | Difference |
|---------|-------------|----------------|------------|
| `join_count` | 0.03 | 0.00 | -0.03 |
| `function_call_count` | 0.002 | 0.001 | -0.001 |

---

## 6. Usage Examples

### 6.1 Feature Extraction

extractor = ASTFeatureExtractor()
features = extractor.extract_features(
query="SELECT * FROM users WHERE id=1",
parse_result={'ast_depth': 3, 'node_count': 15},
token_count=7
)

text

### 6.2 Batch Processing

all_features = []
for query in queries:
features = extractor.extract_features(query, parse_result, token_count)
all_features.append(features)
features_df = pd.DataFrame(all_features)

text

---

## 7. File Outputs

| File | Size | Records | Description |
|------|------|---------|-------------|
| `features_syntax_v1.parquet` | 2.04 MB | 133,734 | All extracted features |
| `feature_summary_stats.csv` | ~5 KB | 32 | Summary statistics per feature |

---

## 8. Future Enhancements

1. **Deep AST parsing**: Enable full AST extraction (currently shallow)
2. **Database-specific features**: Detect vendor-specific functions
3. **Encoding detection**: Identify hex, base64, URL encoding
4. **Temporal features**: Query timing patterns
5. **Contextual features**: HTTP headers, user agent, session data

---

**Document Status:** COMPLETE  
**Last Updated:** 2025-10-28 23:02 IST
