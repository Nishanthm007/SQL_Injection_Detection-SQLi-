# Phase 3C: Evaluation Objectives

**Document Version:** v1.0  
**Date:** November 2, 2025  
**Project:** SQL Injection Detection - Evaluation Dataset Construction  
**Phase:** 3C (Days 1-12)

---

## 1. Definition of "Novel" in Context

### 1.1 Novel Attack Payloads Must Exhibit

#### Completely New Payload Templates
- Attack patterns NOT present in Phase 3B training corpus (133,734 samples)
- Similarity threshold enforcement: max_cosine_similarity < 0.85 against all training/augmentation samples
- Verification method: Use Phase 3B Word2Vec embeddings for semantic similarity computation
- Examples: CVE-based exploits published post-2024, honeypot captures from 2025

#### New Database Functions/Extensions
- Vendor-specific functions not in training data:
  - PostgreSQL: pg_sleep(), pg_read_file(), COPY TO PROGRAM
  - MySQL: SLEEP(), BENCHMARK(), LOAD_FILE(), INTO OUTFILE
  - MSSQL: WAITFOR DELAY, xp_cmdshell, extended stored procedures
  - Oracle: DBMS_PIPE.RECEIVE_MESSAGE, UTL_HTTP, external procedures
  - SQLite: load_extension()
- Advanced exploitation techniques:
  - Out-of-band (DNS/HTTP exfiltration via LOAD_FILE, INTO OUTFILE)
  - Second-order injection (stored payload exploitation)
  - Stored procedure abuse
  - Transaction manipulation attacks

#### New Encodings/Obfuscations
- Transformation chains NOT used in augmentation pipeline:
  - Multi-stage encoding: Base64 → URL → Hex
  - UTF-8 overlong sequences
  - Unicode normalization exploits (NFKC/NFKD attacks)
  - Double encoding variations
  - Mixed encoding within single payload
- Composite obfuscations combining ≥3 transformation types

#### New Attack Flows
- Time-based blind SQLi with novel timing functions
- Boolean-based blind with unconventional conditional logic
- Union-based with column count inference via error messages
- Stacked queries with transaction manipulation
- Error-based with vendor-specific error message exploitation
- Polyglot payloads (valid syntax in multiple SQL dialects)

---

## 2. Evaluation Dataset Objectives

### 2.1 Novel Attack Test Set

**Primary Objective:** Measure model generalization to unseen attack patterns

**What It Measures:**
- Detection capability on zero-day SQLi exploits
- Generalization beyond training distribution
- Resistance to concept drift (attacks evolve over time)

**Success Criteria:**
- Recall (Malicious) ≥ 0.85 (catch 85%+ of truly novel attacks)
- Precision (Malicious) ≥ 0.90 (limit false alarms on novel patterns)
- F1-Score ≥ 0.87 (balanced performance)
- Novelty Enforcement: 100% samples pass similarity filter (< 0.85 threshold)
- Sample Size: ≥ 1,500 samples

**Use Case:**
Validates system can detect emerging attack techniques not represented in training data.

---

### 2.2 Adversarial Evaluation Suite

**Primary Objective:** Measure robustness to adversarial obfuscation and evasion attempts

**What It Measures:**
- Resilience against WAF bypass techniques
- Performance degradation under encoding/obfuscation
- Robustness across transformation difficulty levels

**Success Criteria:**
- Per-category recall ≥ 0.80 across all transformation types
- Hard-difficulty recall ≥ 0.75 (sophisticated evasion resistance)
- Easy-difficulty recall ≥ 0.95 (simple obfuscations handled reliably)
- Robustness matrix populated: recall by transformation type × difficulty level
- Coverage: All 8+ transformation categories represented
- Hard case volume: ≥ 200 samples per major category

**Transformation Categories:**
1. URL Encoding (single, double)
2. Hex Encoding (inline, concatenated)
3. Base64 Encoding (single, nested)
4. Comment Insertion (inline, block comments)
5. Case Manipulation (alternating, randomized)
6. String Concatenation (CONCAT, + operator, CHAR() function)
7. Whitespace Manipulation (tabs, newlines, multiple spaces)
8. Composite Transformations (≥3 chained transforms)

**Use Case:**
Validates system resists attacker evasion techniques and maintains detection performance.

---

### 2.3 Production Benign Complex Queries

**Primary Objective:** Measure false positive rate on realistic legitimate queries

**What It Measures:**
- Production operational viability
- Specificity on complex benign patterns
- Realistic false alarm burden

**Success Criteria:**
- False Positive Rate (FPR) ≤ 0.05 (5% or less)
- Precision (Benign Class) ≥ 0.95
- Specificity ≥ 0.95
- Top-100 flagged benigns manually reviewed and categorized
- Diversity: ≥ 5 SQL dialects, ≥ 3 ORM frameworks
- Sample Size: ≥ 5,000 complex benign queries

**Query Complexity Types:**
- Long analytic queries (multi-table JOINs, CTEs, window functions)
- Multi-statement transactional queries (BEGIN/COMMIT blocks)
- ORM-generated queries (Django, SQLAlchemy, Hibernate)
- Parameterized prepared statements
- Vendor-specific syntax (Oracle ROWNUM, MySQL LIMIT, MSSQL TOP)
- BI tool queries (Tableau, Power BI patterns)

**Use Case:**
Validates system won't disrupt normal operations with excessive false alarms.

---

### 2.4 Cross-Domain Test Set

**Primary Objective:** Measure domain transfer and generalization beyond SQL

**What It Measures:**
- Transfer learning capability to adjacent query languages
- False positive avoidance on SQL-like non-SQL traffic
- Domain-specific failure mode identification

**Success Criteria:**
- Per-domain F1-score ≥ 0.75
- Domain coverage: ≥ 6 distinct domains
- Per-domain sample size: ≥ 300 samples
- Label quality: High confidence ≥ 95% samples

**Domain Coverage (Target):**
1. NoSQL JSON queries (MongoDB aggregation pipelines, document filters)
2. GraphQL queries (nested selection sets, fragments, aliases)
3. SPARQL queries (RDF triple patterns, FILTER clauses)
4. Analytics SQL (BI tools, data warehouse patterns)
5. API query strings (REST parameter injection attempts)
6. Telemetry logs (SQL-like substrings in log entries)

**Use Case:**
Validates system can detect injection attacks in adjacent query languages.

---

## 3. Evaluation Metrics Framework

### 3.1 Basic Metrics (Per Dataset)

**Accuracy:** (TP + TN) / (TP + TN + FP + FN) - Target: ≥ 0.99

**Precision:** TP / (TP + FP) - Target: ≥ 0.92

**Recall:** TP / (TP + FN) - Target: ≥ 0.88

**F1-Score:** 2 × (Precision × Recall) / (Precision + Recall) - Target: ≥ 0.90

**False Positive Rate:** FP / (FP + TN) - Target: ≤ 0.05

**Specificity:** TN / (TN + FP) - Target: ≥ 0.95

### 3.2 Advanced Metrics

- Per-Class Metrics (separate precision/recall for malicious and benign)
- Macro/Micro Averaging
- Per-Category Recall (by attack type)
- Per-Transformation Recall (by adversarial transformation)
- Robustness Score (weighted average across adversarial categories)

### 3.3 Performance Metrics

- Latency: < 1 ms per query
- Throughput: ≥ 1000 qps
- Memory Usage: < 500 MB

---

## 4. Hybrid System Configuration

### 4.1 Evaluation Runs

**Run 1: Rule-Based Only** - Baseline: 84% accuracy

**Run 2: CNN Only** - Target: ≥ 95% accuracy

**Run 3: Hybrid (Rule-First)** - Target: ≥ 99% accuracy

**Run 4: Hybrid (Ensemble)** - Target: ≥ 99% accuracy

**Run 5: Human Review Integration** - Low-confidence routing

---

## 5. Dataset Construction Constraints

### 5.1 Novelty Enforcement
- Similarity threshold: max_cosine_similarity < 0.85
- Method: Phase 3B Word2Vec embeddings
- Log: similarity_check_log.csv

### 5.2 Holdout Rules
- Zero overlap with training/validation/augmentation
- Cross-evaluation set deduplication
- Full provenance tracking

### 5.3 Label Quality Requirements
- High confidence labels: ≥ 95%
- Inter-annotator agreement: Cohen's kappa ≥ 0.7
- Minimum 2 annotators per sample subset

### 5.4 Diversity Requirements
- Attack type balance: No category > 40%
- Transformation coverage: All 8+ categories
- SQL dialect diversity: ≥ 5 dialects
- Domain diversity: ≥ 6 domains

---

## 6. Deliverables Checklist

- [ ] novel_attack_testset_v1.jsonl
- [ ] adversarial_eval_suite_v1.zip
- [ ] production_benign_complex_v1.parquet
- [ ] cross_domain_testset_v1.jsonl
- [ ] eval_manifest_v1.csv
- [ ] evaluation_plan_v1.pdf
- [ ] triage_queue.csv
- [ ] similarity_check_log.csv
- [ ] evaluation_readme.md

---

**Status:** DRAFT - Awaiting Stakeholder Sign-Off  
**Target Approval:** November 2, 2025
