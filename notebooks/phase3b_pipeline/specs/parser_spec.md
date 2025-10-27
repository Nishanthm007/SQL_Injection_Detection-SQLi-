# SQL Parser Specification

**Version:** v1.0  
**Date:** October 22, 2025  
**Phase:** 3B - Robust Text Processing Pipeline  
**Owner:** Backend Engineering & Security Team

---

## 1. Overview

This specification defines the SQL parsing strategy for extracting Abstract Syntax Trees (AST) and structural information from SQL queries. The parser must handle both valid SQL and malformed injection attempts robustly.

---

## 2. Parser Selection

### 2.1 Primary Parser: SQLGlot

**Library:** `sqlglot` v27.28.1+  
**Repository:** https://github.com/tobymao/sqlglot  
**License:** MIT

**Justification:**
- **Robustness:** Tolerates malformed SQL with configurable error levels
- **Dialect Support:** 31+ SQL dialects (MySQL, PostgreSQL, SQLite, etc.)
- **AST Richness:** 100+ node types with full expression trees
- **Performance:** 1-10ms per query (pure Python)
- **Active Development:** 8.4K+ GitHub stars, used in production by Apache Superset, Dagster
- **Error Recovery:** Continues parsing with warnings instead of failing

### 2.2 Fallback Strategy

When SQLGlot fails to produce a complete AST:

**Step 1:** Set `parse_failed=True` flag  
**Step 2:** Extract tokens using regex heuristics  
**Step 3:** Identify basic components:
- SQL keywords (SELECT, WHERE, FROM, etc.)
- Operators (=, <, >, AND, OR, etc.)
- String literals (quoted content)
- Comments (-- and /* */)
- Identifiers (alphanumeric sequences)

**Step 4:** Store partial results with error information

---

## 3. Parsing Configuration

### 3.1 Error Handling Modes

PARSE_MODES = {
'strict': {
'error_level': 'raise',
'description': 'Use for validation only'
},
'tolerant': {
'error_level': 'warn',
'description': 'Default mode for production'
},
'silent': {
'error_level': 'ignore',
'description': 'Use for batch processing'
}
}

text

**Default Mode:** `tolerant`

### 3.2 Parser Options

PARSER_OPTIONS = {
'read': None,
'error_level': None,
'max_errors': 10,
'normalize': True
}

text

---

## 4. AST Output Format

### 4.1 JSON Structure

{
"sample_id": "train_00001",
"parse_success": true,
"parse_time_ms": 2.34,
"dialect": "generic",
"ast_root_type": "Select",
"sql_normalized": "SELECT * FROM users WHERE id = 1",
"tokens": ["SELECT", "*", "FROM", "users", "WHERE", "id", "=", "1"],
"errors": [],
"warnings": []
}

text

---

## 5. Normalization Rules

- **Keywords:** Uppercase (SELECT, WHERE)
- **Identifiers:** Lowercase (users, user_id)
- **Whitespace:** Single spaces, normalized line endings
- **Quotes:** Single quotes for strings, double for identifiers

---

## 6. Error Handling

### 6.1 Error Categories

| Error Type | Handling | Flag |
|------------|----------|------|
| Syntax Error | Log, continue with partial parse | `syntax_error=True` |
| Unexpected Token | Skip token, continue | `unexpected_token=True` |
| Incomplete Query | Mark incomplete, extract parseable | `incomplete=True` |
| Timeout | Abort after 5s, use fallback | `timeout=True` |

---

## 7. Fallback Heuristics

### 7.1 Suspicious Pattern Detection

SUSPICIOUS_PATTERNS = {
'sleep_function': r'SLEEP\s*$$',
'union_injection': r'UNION\s+(ALL\s+)?SELECT',
'comment_injection': r'--|#|/',
'stacked_queries': r';\sSELECT|;\sDROP',
'tautology': r"OR\s+'?1'?\s=\s*'?1",
'hex_encoding': r'0x[0-9a-fA-F]+',
}

text

---

## 8. Performance Requirements

| Operation | Target | Maximum |
|-----------|--------|---------|
| Simple parse | <1ms | 5ms |
| Complex parse | <5ms | 20ms |
| Batch (1000) | <10s | 30s |

**Timeout:** 5 seconds per query

---

## 9. Output Files

phase3b_pipeline/data/parsed/
├── train_ast_v1.jsonl
├── val_ast_v1.jsonl
├── test_ast_v1.jsonl
├── train_parse_errors_v1.csv
└── parsing_stats_v1.json

text

---

## 10. Validation Metrics

### Acceptance Criteria

- Full parse success: >85%
- Partial parse: >95%
- Timeout rate: <0.1%
- Average parse time: <5ms

---

## 11. Version History

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| v1.0 | 2025-10-22 | Initial specification | Phase 3B Team |

---

**Document Status:** APPROVED  
**Next Review Date:** 2025-11-22
