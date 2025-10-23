# Feature Engineering Specification

**Version:** v1.0  
**Date:** October 22, 2025  
**Phase:** 3B - Robust Text Processing Pipeline  
**Owner:** ML Engineering & Feature Team

---

## 1. Overview

This specification defines all features extracted from SQL queries for injection detection. Features are organized into three categories: Syntax-Tree (AST-derived), Semantic Role, and Statistical Anomaly features.

**Total Feature Count:** 45+ features

---

## 2. Syntax-Tree Features (AST-Derived)

Extracted from parsed Abstract Syntax Trees using SQLGlot parser.

### 2.1 Tree Structure Features

| Feature Name | Type | Description | Range |
|--------------|------|-------------|-------|
| `ast_depth` | int | Maximum depth of AST tree | 0-50 |
| `ast_max_branching` | int | Maximum children per node | 0-100 |
| `ast_total_nodes` | int | Total number of nodes in AST | 0-1000 |
| `ast_leaf_nodes` | int | Number of leaf nodes | 0-500 |

### 2.2 Statement Type Features

| Feature Name | Type | Description |
|--------------|------|-------------|
| `has_select` | bool | Contains SELECT statement |
| `has_insert` | bool | Contains INSERT statement |
| `has_update` | bool | Contains UPDATE statement |
| `has_delete` | bool | Contains DELETE statement |
| `has_drop` | bool | Contains DROP statement |
| `has_create` | bool | Contains CREATE statement |
| `has_exec` | bool | Contains EXEC/EXECUTE statement |

### 2.3 Clause Count Features

| Feature Name | Type | Description | Range |
|--------------|------|-------------|-------|
| `select_count` | int | Number of SELECT clauses | 0-20 |
| `where_count` | int | Number of WHERE clauses | 0-10 |
| `join_count` | int | Number of JOIN clauses | 0-10 |
| `union_count` | int | Number of UNION operators | 0-10 |
| `subquery_count` | int | Number of subqueries | 0-15 |
| `orderby_count` | int | Number of ORDER BY clauses | 0-5 |
| `groupby_count` | int | Number of GROUP BY clauses | 0-5 |
| `having_count` | int | Number of HAVING clauses | 0-5 |

### 2.4 Function Features

| Feature Name | Type | Description |
|--------------|------|-------------|
| `function_count` | int | Total function calls |
| `has_sleep` | bool | Contains SLEEP function |
| `has_benchmark` | bool | Contains BENCHMARK function |
| `has_load_file` | bool | Contains LOAD_FILE function |
| `has_concat` | bool | Contains CONCAT/string functions |
| `has_char` | bool | Contains CHAR function |
| `agg_function_count` | int | Aggregate functions (COUNT, SUM, etc.) |

### 2.5 Literal Features

| Feature Name | Type | Description | Range |
|--------------|------|-------------|-------|
| `string_literal_count` | int | Number of string literals | 0-50 |
| `numeric_literal_count` | int | Number of numeric literals | 0-50 |
| `hex_literal_count` | int | Number of hex literals (0x...) | 0-20 |
| `null_literal_count` | int | Number of NULL literals | 0-10 |

### 2.6 Structural Features

| Feature Name | Type | Description |
|--------------|------|-------------|
| `semicolon_count` | int | Statement terminators (stacked queries) |
| `comment_count` | int | Number of comments (-- or /* */) |
| `nested_depth` | int | Maximum nesting depth (subqueries, parens) |
| `parenthesis_pairs` | int | Number of balanced parenthesis pairs |

---

## 3. Semantic Role Features

Extracted by identifying the semantic role of tokens in the query.

### 3.1 Role Definitions

| Role Name | Description | Examples |
|-----------|-------------|----------|
| `TARGET_TABLE` | Table being queried/modified | users, orders, products |
| `SELECT_FIELDS` | Columns in SELECT clause | id, name, email, * |
| `WHERE_CONDITIONS` | Conditions in WHERE clause | id = 1, name LIKE '%test%' |
| `JOIN_CLAUSE` | JOIN specifications | INNER JOIN, LEFT JOIN ON |
| `SUBQUERY_TARGET` | Subquery statements | (SELECT...) |
| `AGG_FUNCTION` | Aggregation functions | COUNT, SUM, AVG |
| `CONDITION_OPERATOR` | Comparison operators | =, <, >, LIKE, IN |
| `LITERAL_VALUE` | Constant values | 'admin', 123, 0xFF |

### 3.2 Role Features

For each role, extract three features:

| Feature Pattern | Type | Description |
|-----------------|------|-------------|
| `role_{name}_present` | bool | Role exists in query |
| `role_{name}_count` | int | Number of tokens with this role |
| `role_{name}_diversity` | float | Unique tokens / total tokens |

**Example:**
- `role_target_table_present` = True
- `role_target_table_count` = 2
- `role_target_table_diversity` = 0.5 (2 unique / 4 total mentions)

---

## 4. Statistical Anomaly Features

Detect unusual patterns in query text that may indicate obfuscation or injection.

### 4.1 Entropy and Complexity

| Feature Name | Type | Calculation | Range |
|--------------|------|-------------|-------|
| `shannon_entropy` | float | -Σ(p(c) * log2(p(c))) | 0.0-8.0 |
| `normalized_entropy` | float | shannon_entropy / log2(vocab_size) | 0.0-1.0 |
| `compression_ratio` | float | len(compressed) / len(original) | 0.0-1.0 |

### 4.2 Character Distribution

| Feature Name | Type | Description | Range |
|--------------|------|-------------|-------|
| `non_alnum_ratio` | float | Non-alphanumeric chars / total | 0.0-1.0 |
| `digit_ratio` | float | Digit chars / total | 0.0-1.0 |
| `uppercase_ratio` | float | Uppercase chars / total | 0.0-1.0 |
| `whitespace_ratio` | float | Whitespace chars / total | 0.0-1.0 |
| `special_char_ratio` | float | Special chars (!, @, #) / total | 0.0-1.0 |

### 4.3 Encoding Detection

| Feature Name | Type | Pattern | Example |
|--------------|------|---------|---------|
| `has_url_encoding` | bool | %[0-9A-F]{2} | %27, %20 |
| `url_encoding_count` | int | Count of URL-encoded chars | 0-50 |
| `has_hex_encoding` | bool | 0x[0-9A-F]+ or \x[0-9A-F]{2} | 0x41, \x27 |
| `hex_encoding_count` | int | Count of hex-encoded values | 0-20 |
| `has_unicode_escape` | bool | \u[0-9A-F]{4} | \u0027 |
| `has_base64_pattern` | bool | [A-Za-z0-9+/]{20,}={0,2} | base64-like strings |

### 4.4 N-gram Deviation

Measure how much the query deviates from typical SQL patterns.

| Feature Name | Type | Description |
|--------------|------|-------------|
| `char_trigram_deviation` | float | KL divergence from benign corpus |
| `word_bigram_deviation` | float | KL divergence from benign corpus |
| `rare_char_trigram_count` | int | Trigrams appearing <0.1% in corpus |

### 4.5 Length-Based Features

| Feature Name | Type | Description | Range |
|--------------|------|-------------|-------|
| `query_char_length` | int | Total characters | 1-6000 |
| `query_word_length` | int | Total tokens | 1-250 |
| `avg_word_length` | float | Mean characters per word | 1.0-20.0 |
| `max_word_length` | int | Longest word in query | 1-200 |
| `repeated_char_max` | int | Longest sequence of same char | 1-5000 |

---

## 5. Feature Normalization

### 5.1 Scaling Strategy

| Feature Type | Scaling Method | Range |
|--------------|----------------|-------|
| Count features | Log1p transform | [0, log(max)] |
| Ratio features | Min-max scaling | [0, 1] |
| Boolean features | No scaling | {0, 1} |
| Entropy features | Standard scaling | z-score |

### 5.2 Outlier Handling

- Cap values at 99th percentile
- Flag extreme outliers with additional feature
- Log original value before capping

---

## 6. Feature Completeness

### 6.1 Missing Value Handling

| Scenario | Strategy |
|----------|----------|
| Parse failure | Set AST features to 0, flag `parse_failed=True` |
| Empty query | Set all counts to 0, flag `empty_query=True` |
| Encoding error | Use fallback values, flag `encoding_error=True` |

### 6.2 Feature Validation

- No NaN values allowed
- All features within expected range
- Consistency checks (e.g., select_count <= ast_total_nodes)

---

## 7. Output Format

### 7.1 Feature Table Schema

{
'sample_id': 'train_00001',

text
# AST features (20+)
'ast_depth': 5,
'ast_max_branching': 3,
'select_count': 1,
'where_count': 1,
'union_count': 0,
'has_sleep': False,
...

# Semantic role features (24)
'role_target_table_present': True,
'role_target_table_count': 1,
'role_where_conditions_count': 2,
...

# Statistical features (30+)
'shannon_entropy': 4.23,
'non_alnum_ratio': 0.15,
'has_url_encoding': False,
'char_trigram_deviation': 1.45,
...

# Metadata
'parse_failed': False,
'empty_query': False,
'feature_version': 'v1.0'
}

text

### 7.2 Output Files

phase3b_pipeline/data/features/
├── train_features_v1.parquet
├── val_features_v1.parquet
├── test_features_v1.parquet
├── feature_stats_v1.json # Min/max/mean/std per feature
└── feature_correlation_v1.csv # Feature correlation matrix

text

---

## 8. Performance Requirements

- Feature extraction: <50ms per query
- Batch processing (1000 queries): <30 seconds
- Memory usage: <4GB for full training set

---

## 9. Validation Metrics

### 9.1 Acceptance Criteria

- Feature completeness: 100% (no missing values after imputation)
- Feature variance: All features have std > 0.01
- Correlation threshold: No pair with |r| > 0.95 (remove redundant features)
- Parse-derived feature accuracy: >95% match manual labels (sample validation)

---

## 10. Version History

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| v1.0 | 2025-10-22 | Initial specification | Phase 3B Team |

---

**Document Status:** APPROVED  
**Next Review Date:** 2025-11-22
