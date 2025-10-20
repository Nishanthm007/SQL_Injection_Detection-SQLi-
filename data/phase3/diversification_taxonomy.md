# Diversification Taxonomy - Phase 3

**Version:** 1.0  
**Date:** 2025-10-20  
**Phase:** 3 - Advanced Data Preprocessing & Diversification

## Overview

This document specifies all transformation types that will be applied to the Phase 1 master dataset to create a robust, diverse training corpus that prevents CNN overfitting.

## Seed Corpus

- **Phase 1 Master Dataset:** 212,895 samples
- **Phase 2 False Negatives:** 9,052 samples (attacks missed by rule engine)
- **Total Seed Samples:** 212,895

## Augmentation Goals

- **Primary Goal:** Increase adversarial diversity to 40-50% of training data
- **Estimated New Samples:** 1,765,420
- **Target Total Dataset Size:** 1,978,315 samples
- **Augmentation Ratio:** 20.1x per malicious sample

## Transformation Categories


### 1. Encoding Transformations

**Description:** Various encoding schemes to obfuscate attacks

**Augmentation Goal:** Generate 5 variants per malicious sample

**Estimated New Samples:** 440,035

**Transformations:**

#### URL encoding

Percent-encode characters

**Examples:**
- `' OR 1=1-- => %27%20OR%201%3D1--`
- `UNION SELECT => UNION%20SELECT`

#### Hex encoding

Convert strings to hex format

**Examples:**
- `admin => 0x61646d696e`
- `SELECT => 0x53454c454354`

#### Unicode escapes

Unicode escape sequences

**Examples:**
- `' => \u0027`
- `OR => \u004f\u0052`

#### Base64 encoding

Base64 encode payloads

**Examples:**
- `' OR 1=1 => JyBPUiAxPTE=`
- `UNION SELECT => VU5JT04gU0VMRUNUA==`

#### Octal encoding

Octal representation

**Examples:**
- `A => \101`
- `' => \047`


### 2. Time Based Blind

**Description:** Time-based blind SQL injection payloads

**Augmentation Goal:** Generate 3 time-based variants per sample

**Estimated New Samples:** 264,021

**Transformations:**

#### SLEEP functions

Database sleep functions

**Examples:**
- `' AND SLEEP(5)--`
- `'; WAITFOR DELAY '00:00:05'--`
- `' AND pg_sleep(5)--`

#### BENCHMARK functions

CPU-intensive operations for timing

**Examples:**
- `' AND BENCHMARK(5000000, MD5('A'))--`
- `' AND HEAVY_COMPUTATION()--`

#### Conditional timing

IF/CASE with timing

**Examples:**
- `' AND IF(1=1, SLEEP(5), 0)--`
- `' AND CASE WHEN 1=1 THEN SLEEP(5) END--`


### 3. Nosql Injection

**Description:** NoSQL injection patterns (MongoDB, etc.)

**Augmentation Goal:** Generate 4 NoSQL variants per 100 SQL samples

**Estimated New Samples:** 3,520

**Transformations:**

#### JSON operators

MongoDB query operators

**Examples:**
- `{"username": {"$ne": null}}`
- `{"$where": "this.username == 'admin'"}`
- `{"price": {"$gt": 0}}`

#### Operator chaining

Multiple NoSQL operators

**Examples:**
- `{"$and": [{"price": {"$gt": 0}}, {"stock": {"$ne": 0}}]}`
- `{"$or": [{"role": "admin"}, {"role": "superuser"}]}`

#### Regex payloads

Regex-based NoSQL injections

**Examples:**
- `{"username": {"$regex": "^admin"}}`
- `{"password": {"$regex": ".*"}}`


### 4. Second Order Injection

**Description:** Payloads that persist and execute later

**Augmentation Goal:** Generate 2 second-order variants per 100 samples

**Estimated New Samples:** 1,760

**Transformations:**

#### Stored payloads

Data stored then executed

**Examples:**
- `username: admin'-- (stored in DB, used in query later)`
- `comment: <script>alert(1)</script> (stored, rendered later)`

#### Multi stage attacks

Attack in multiple requests

**Examples:**
- `Stage 1: Store '; DROP TABLE--`
- `Stage 2: Trigger via search/report generation`


### 5. Context Specific

**Description:** Attack variants based on injection context

**Augmentation Goal:** Generate 3 context variants per sample

**Estimated New Samples:** 264,021

**Transformations:**

#### Web form fields

Form input injection

**Examples:**
- `username=' OR '1'='1`
- `password=anything&username=admin'--`

#### HTTP headers

Header-based injection

**Examples:**
- `User-Agent: ' OR 1=1--`
- `Referer: http://site.com?id=1' UNION SELECT--`

#### JSON bodies

JSON API injection

**Examples:**
- `{"id": "1' OR '1'='1"}`
- `{"search": "test' UNION SELECT--"}`

#### REST endpoints

URL path/query injection

**Examples:**
- `/api/users/1' OR '1'='1/profile`
- `/search?q=test' UNION SELECT--`

#### Cookies

Cookie-based injection

**Examples:**
- `session=abc123' OR 1=1--`
- `user_id=5' UNION SELECT--`


### 6. Character Substitution

**Description:** Character-level obfuscation

**Augmentation Goal:** Generate 4 character variants per sample

**Estimated New Samples:** 352,028

**Transformations:**

#### Leet speak

Replace letters with numbers/symbols

**Examples:**
- `SELECT => S3L3CT`
- `UNION => UN10N`
- `admin => 4dm1n`

#### Homoglyphs

Visually similar Unicode characters

**Examples:**
- `SELECT => SЕL ECT (Cyrillic E)`
- `UNION => UΝ ION (Greek N)`

#### Case variations

Mixed case to evade filters

**Examples:**
- `SELECT => SeLeCt`
- `UNION => UnIoN`
- `DROP => DrOp`


### 7. Obfuscation Techniques

**Description:** Advanced obfuscation methods

**Augmentation Goal:** Generate 5 obfuscation variants per sample

**Estimated New Samples:** 440,035

**Transformations:**

#### Comment injection

Insert comments within keywords

**Examples:**
- `SEL/**/ECT`
- `UN/*comment*/ION`
- `DR/**/OP`

#### Whitespace manipulation

Excessive or unusual whitespace

**Examples:**
- `SELECT     FROM`
- `UNION\t\t\tSELECT`
- `OR\n\n\n1=1`

#### Concatenation

String concatenation to build keywords

**Examples:**
- `CONCAT('SE','LECT')`
- `'UN'||'ION'`
- `'DR'+'OP'`

#### Function wrapping

Wrap in functions

**Examples:**
- `CHAR(83,69,76,69,67,84)`
- `UNHEX('53454C454354')`
- `FROM_BASE64('U0VMRUNUA==')`


## Augmentation Policy

### Per-Sample Limits

- Maximum variants per original sample: 25
- Encoding variants: 5
- Obfuscation variants: 5
- Context variants: 3
- Character variants: 4

### Class Balance

- Target malicious ratio: 0.6
- Target benign ratio: 0.4
- Malicious augmentation: Aggressive (all transformations)
- Benign augmentation: Minimal (only context variations)

### Quality Controls

- Deduplication: SHA256 hash-based
- Label verification: Automated heuristics + random 5% human review
- Provenance tracking: original_id + transformation_chain
- Validation set isolation: Never augment validation/test sets

## Implementation Order

1. Encoding transformations (deterministic)
2. Obfuscation techniques (deterministic)
3. Context-specific variants (rule-based)
4. Character substitution (controlled randomness)
5. Time-based blind (template-based)
6. NoSQL injection (rule-based generation)
7. Second-order injection (multi-stage templates)

## Validation Strategy

- Create specialized validation sets for each transformation type
- Never augment test/validation sets (keep pure for unbiased evaluation)
- Reserve 5% of augmented samples for human review
- Track provenance for all generated samples
