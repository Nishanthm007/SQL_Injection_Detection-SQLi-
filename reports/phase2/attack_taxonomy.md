# SQL Injection Attack Taxonomy
**Version:** 1.0  
**Date:** 2025-10-17  
**Phase:** Phase 2 - Rule Engine Development

## Overview
This document defines the 6 primary SQL injection attack categories, their characteristics, and detection requirements.

## Attack Categories

### TAU: Tautology-Based Injection

**Severity:** HIGH  
**Description:** Exploits always-true conditions to bypass authentication or retrieve all records

**Technical Details:**  
Injects conditions like 'OR 1=1', 'OR 'a'='a' that always evaluate to TRUE

**Typical Targets:**
- Login forms
- Search filters
- WHERE clauses

**Detection Strategy:** Pattern matching for tautology expressions

**Example Attacks:**
``````
``````
``````
``````
``````

**Keywords:** OR, AND, =, 1=1, true, false

**False Positive Risks:**
- Legitimate queries with OR conditions
- Mathematical expressions in data

---

### UNI: UNION-Based Injection

**Severity:** CRITICAL  
**Description:** Uses UNION operator to combine malicious query with legitimate one

**Technical Details:**  
Appends UNION SELECT to retrieve data from other tables

**Typical Targets:**
- Data retrieval endpoints
- SELECT statements
- API queries

**Detection Strategy:** Detect UNION keyword with SELECT/FROM patterns

**Example Attacks:**
``````
``````
``````
``````
``````

**Keywords:** UNION, UNION ALL, SELECT, FROM, NULL

**False Positive Risks:**
- Legitimate complex queries using UNION
- Stored procedures with UNION

---

### CMT: Comment-Based Injection

**Severity:** HIGH  
**Description:** Uses SQL comments to truncate queries and bypass validation

**Technical Details:**  
Injects -- or /* */ or # to comment out remaining query parts

**Typical Targets:**
- Login forms
- Input validation
- Query string parameters

**Detection Strategy:** Detect SQL comment sequences

**Example Attacks:**
``````
``````
``````
``````
``````

**Keywords:** --, /*, */, #

**False Positive Risks:**
- URLs with -- in parameters
- Email addresses or data containing #
- Mathematical operations (e.g., 5--3)

---

### STK: Stacked Queries Injection

**Severity:** CRITICAL  
**Description:** Executes multiple SQL statements in a single query using semicolons

**Technical Details:**  
Uses ; to separate and execute additional malicious commands

**Typical Targets:**
- API endpoints
- Batch processing
- Administrative interfaces

**Detection Strategy:** Detect semicolons followed by SQL keywords

**Example Attacks:**
``````
``````
``````
``````
``````

**Keywords:** ;, DROP, DELETE, UPDATE, INSERT, EXEC, CREATE

**False Positive Risks:**
- Stored procedures with multiple statements
- Legitimate batch operations

---

### TMB: Time-Based Blind Injection

**Severity:** CRITICAL  
**Description:** Infers information based on response time delays

**Technical Details:**  
Uses SLEEP(), WAITFOR, BENCHMARK() to cause delays

**Typical Targets:**
- Boolean-based queries
- Error-suppressed applications

**Detection Strategy:** Detect time-delay functions

**Example Attacks:**
``````
``````
``````
``````
``````

**Keywords:** SLEEP, WAITFOR, DELAY, BENCHMARK, pg_sleep

**False Positive Risks:**
- Legitimate performance testing queries
- Database maintenance scripts

---

### ADV: Advanced & Evasion Techniques

**Severity:** CRITICAL  
**Description:** Complex attacks using encoding, obfuscation, or stored procedures

**Technical Details:**  
Hex encoding, CHAR(), CONCAT(), stored proc abuse, XML/JSON injection

**Typical Targets:**
- API endpoints
- Complex applications
- Enterprise systems

**Detection Strategy:** Detect encoding patterns, function chaining, privilege escalation

**Example Attacks:**
``````
``````
``````
``````
``````

**Keywords:** 0x, CHAR, CONCAT, EXEC, xp_, sp_, LOAD_FILE, OUTFILE, EXTRACTVALUE, %27, %20

**False Positive Risks:**
- Legitimate hex values in data
- URL-encoded legitimate requests
- System administration queries

---

## Operational Requirements

### Performance
- Max Latency: 10ms per query
- Target Throughput: 1000 queries/sec
- Memory Limit: 512MB

### Accuracy Targets
- Overall Precision: ≥ 0.95
- Overall Recall: ≥ 0.92
- Overall F1-Score: ≥ 0.93
- High-Confidence Rules Precision: ≥ 0.98
- Max False Positive Rate: ≤ 0.02
- Max False Negative Rate: ≤ 0.08

## Next Steps
1. Day 12: Rule design and pattern engineering
2. Day 13-15: Rule implementation and validation
3. Day 16-18: Testing and performance optimization
