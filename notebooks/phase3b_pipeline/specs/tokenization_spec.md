# Tokenization Specification

**Version:** v1.0  
**Date:** October 22, 2025  
**Phase:** 3B - Robust Text Processing Pipeline  
**Owner:** Data Engineering & NLP Team

---

## 1. Overview

This specification defines the tokenization strategies for SQL injection detection. Two parallel tokenization approaches are implemented:
1. **Character-level tokenization** - for fine-grained pattern detection
2. **Word-level tokenization** - for semantic and structural understanding

---

## 2. Character-Level Tokenization

### 2.1 Purpose
Capture fine-grained obfuscation patterns including:
- Hex encoding (0x41)
- URL encoding (%27)
- Unicode manipulation
- Character substitutions
- Whitespace manipulation

### 2.2 Configuration

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Vocabulary Size | 260 tokens | 256 ASCII chars + 4 special tokens |
| Max Sequence Length | 1024 characters | Based on 95th percentile (961) + buffer |
| Truncation Strategy | Right (tail) | Preserve query beginning with SQL keywords |
| Padding Strategy | Left | Preserve recent context for sequential models |
| Padding Token | <PAD> (ID: 0) | Standard practice |
| Unknown Token | <UNK> (ID: 1) | For non-ASCII characters |
| Start Token | <START> (ID: 2) | Sequence beginning marker |
| End Token | <END> (ID: 3) | Sequence termination marker |

### 2.3 Special Tokens

CHAR_SPECIAL_TOKENS = {
'<PAD>': 0, # Padding token
'<UNK>': 1, # Unknown/non-ASCII characters
'<START>': 2, # Sequence start
'<END>': 3 # Sequence end
}

text

### 2.4 Character Mapping
- ASCII characters (32-126): Direct mapping to ASCII code
- Control characters (0-31, 127-255): Map to <UNK>
- Special preserve: \n (10), \t (9), \r (13)
- Non-ASCII (>127): Map to <UNK> with logging

### 2.5 Noise Injection (Training Only)

**Character Dropout:**
- Probability: 10%
- Applied to: Training set only
- Random seed: Deterministic per experiment
- Purpose: Regularization and robustness to typos

**Implementation:**
if is_training and random.random() < 0.10:
char = '<UNK>'

text

### 2.6 Output Format

{
'sample_id': 'train_00001',
'char_tokens': [83, 69, 76, 69, 67, 84, ...], # ASCII codes
'char_length': 412,
'original_length': 412,
'truncated': False,
'unk_count': 3,
'noise_applied': True # Training only
}

text

---

## 3. Word-Level Tokenization (SQL-Aware)

### 3.1 Purpose
Preserve SQL syntax and semantics for:
- Transformer-based models
- Structural feature extraction
- Semantic role labeling
- Parse tree generation

### 3.2 Configuration

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Max Sequence Length | 150 tokens | Based on 95th percentile (146) + buffer |
| Truncation Strategy | Right (tail) | Preserve query structure at beginning |
| Padding Strategy | Right | Standard for BERT-style models |
| Case Normalization | Keywords uppercase, identifiers lowercase | Consistent parsing |
| Subword Strategy | WordPiece (200 merges) | Handle OOV identifiers |

### 3.3 Token Classes

#### 3.3.1 SQL Keywords
**Examples:** SELECT, FROM, WHERE, JOIN, UNION, ORDER BY, GROUP BY, HAVING, INSERT, UPDATE, DELETE, DROP, CREATE, ALTER, EXEC, EXECUTE

**Handling:**
- Case-insensitive matching
- Normalize to UPPERCASE
- Treat multi-word keywords as single token (e.g., "ORDER BY")

#### 3.3.2 Operators
**Examples:** =, !=, <>, <, >, <=, >=, AND, OR, NOT, LIKE, IN, BETWEEN, IS NULL

**Handling:**
- Preserve as-is
- Multi-character operators as single token

#### 3.3.3 Identifiers (Tables, Columns, Aliases)
**Examples:** users, user_id, t1, customer_name

**Handling:**
- Normalize to lowercase
- Subword tokenization for OOV
- Track identifier frequency

#### 3.3.4 Literals - Dual Mode

**Mode 1: Masked (Structure Focus)**
'admin' -> <STR_LIT>
123 -> <NUM_LIT>
0xDEADBEEF -> <HEX_LIT>

text

**Mode 2: Raw (Payload Focus)**
' OR '1'='1' -> [', 'OR', ', '1', '=', '1']
Keep original for injection pattern detection

text

#### 3.3.5 Comments
**Examples:** --, /* */, #

**Handling:**
- Option 1: Replace with <COMMENT> token
- Option 2: Preserve content (configurable)
- Track comment positions

#### 3.3.6 Punctuation
**Examples:** ; , ( ) . [ ] { }

**Handling:**
- Each punctuation as separate token
- Structural markers for parsing

### 3.4 Special Tokens

WORD_SPECIAL_TOKENS = {
'<PAD>': 0, # Padding
'<UNK>': 1, # Unknown token
'<CLS>': 2, # Classification token (BERT-style)
'<SEP>': 3, # Separator for multi-statement
'<MASK>': 4, # Masked language modeling
'<STR_LIT>': 5, # String literal placeholder
'<NUM_LIT>': 6, # Numeric literal placeholder
'<HEX_LIT>': 7, # Hexadecimal literal placeholder
'<COMMENT>': 8 # Comment placeholder
}

text

### 3.5 Vocabulary Construction

**Base Vocabulary (Fixed):**
- 500 SQL keywords and operators
- Special tokens (9 tokens)

**Dynamic Vocabulary (From Training Data):**
- Top 50,000 identifiers by frequency
- Subword units (WordPiece with 200 merges)

**Total Vocabulary Size:** ~50,509 tokens

### 3.6 Whitespace Normalization

- Collapse multiple spaces to single space
- Preserve newlines within string literals
- Remove leading/trailing whitespace
- Normalize tabs to spaces

### 3.7 Output Format - Dual Mode

**Masked Mode:**
{
'sample_id': 'train_00001',
'tokens': ['SELECT', '<STR_LIT>', 'FROM', 'users', 'WHERE', 'id', '=', '<NUM_LIT>'],
'token_ids': ,​
'token_length': 8,
'mode': 'masked'
}

text

**Raw Mode:**
{
'sample_id': 'train_00001',
'tokens': ['SELECT', "'admin'", 'FROM', 'users', 'WHERE', 'id', '=', '1'],
'token_ids': ,​
'token_length': 8,
'literal_positions': ,​
'mode': 'raw'
}

text

---

## 4. Edge Case Handling

### 4.1 Empty Queries
- Flag as `empty_query=True`
- Pad to max length with <PAD>
- Include in dataset with special attention in loss function

### 4.2 Non-ASCII Characters
- Character-level: Map to <UNK>, log frequency
- Word-level: Preserve if within identifier, else <UNK>

### 4.3 Null Bytes
- Replace with <UNK>
- Flag sample for security review
- Log occurrence

### 4.4 Extremely Long Queries (>max_length)
- Truncate according to strategy
- Set `truncated=True` flag
- Log original length

### 4.5 Malformed Encoding
- Best-effort decode with UTF-8
- Fallback to latin-1
- Ultimate fallback: byte-level processing

---

## 5. Validation Metrics

### 5.1 Tokenization Quality Metrics
- Coverage: % of queries fully tokenized without <UNK>
- Truncation rate: % of queries exceeding max length
- <UNK> frequency: Average <UNK> tokens per query
- Vocabulary utilization: % of vocab tokens used

### 5.2 Acceptance Criteria
- Character-level <UNK> rate: <2%
- Word-level <UNK> rate: <5%
- Truncation rate: <10%
- Vocabulary coverage: >95%

---

## 6. Implementation Requirements

### 6.1 Performance
- Throughput: >1000 queries/second (single core)
- Memory: <2GB for vocabulary and tokenizer state
- Batch processing: Support batch sizes up to 512

### 6.2 Reproducibility
- Deterministic tokenization (same input = same output)
- Seed management for noise injection
- Version tracking for vocabulary updates

### 6.3 Output Files
phase3b_pipeline/data/tokenized/
├── train_char_tokenized.parquet
├── train_word_tokenized_masked.parquet
├── train_word_tokenized_raw.parquet
├── val_char_tokenized.parquet
├── val_word_tokenized_masked.parquet
├── val_word_tokenized_raw.parquet
├── test_char_tokenized.parquet
├── test_word_tokenized_masked.parquet
├── test_word_tokenized_raw.parquet
├── char_vocab.json
└── word_vocab.json

text

---

## 7. Version History

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| v1.0 | 2025-10-22 | Initial specification | Phase 3B Team |

---

**Document Status:** APPROVED  
**Next Review Date:** 2025-11-22
