# SQL Injection Detection Rules Catalog
**Version:** 1.0  
**Date:** 2025-10-18  
**Total Rules:** 59

## Overview
This catalog contains 59 detection rules organized into 6 categories.

## Rule Statistics
- **Total Rules:** 59
- **High Confidence (>=0.90):** 38
- **Medium Confidence (0.75-0.89):** 14
- **Low Confidence (<0.75):** 7

## Rules by Category

### Tautology-Based Injection (10 rules)

#### TAU-001: Classic OR 1=1 Tautology

**Description:** Detects always-true condition OR 1=1 used to bypass authentication

**Severity:** HIGH  
**Confidence:** 0.95  
**Priority:** 10  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Identify basic tautology attacks in WHERE clauses

**Example Matches:**
- `' OR 1=1--`
- `admin' OR 1=1#`
- `' OR '1'='1`
- `password' OR 1=1 LIMIT 1--`

**False Positive Cases:**
- Mathematical expressions: quantity OR 1=1 (legitimate comparison)
- Text containing 'OR 1=1' in documentation

**Notes:** Case-insensitive, handles quotes around values

---

#### TAU-002: String Equality Tautology

**Description:** Detects OR 'a'='a' style always-true string comparisons

**Severity:** HIGH  
**Confidence:** 0.92  
**Priority:** 9  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Catch string-based tautology bypasses

**Example Matches:**
- `' OR 'a'='a'--`
- `' OR 'x'='x`
- `admin' OR 'abc'='abc'#`

**False Positive Cases:**
- Legitimate string comparisons in WHERE clauses
- Application comparing user input to constants

**Notes:** Matches identical string comparisons with OR

---

#### TAU-003: TRUE/FALSE Keyword Tautology

**Description:** Detects use of TRUE, FALSE keywords in tautology

**Severity:** MEDIUM  
**Confidence:** 0.85  
**Priority:** 7  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Identify boolean-based tautology attacks

**Example Matches:**
- `' OR TRUE--`
- `' OR 1`
- `password' OR FALSE#`

**False Positive Cases:**
- Legitimate boolean logic: status OR TRUE
- Boolean flags in queries

**Notes:** Lower confidence due to legitimate OR usage

---

#### TAU-004: IS NOT NULL Tautology

**Description:** Detects OR column IS NOT NULL always-true conditions

**Severity:** MEDIUM  
**Confidence:** 0.88  
**Priority:** 6  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Catch IS NOT NULL based bypasses

**Example Matches:**
- `' OR user_id IS NOT NULL--`
- `' OR 1 IS NOT NULL#`

**False Positive Cases:**
- Legitimate NULL checks in complex queries

**Notes:** Common in advanced injection attempts

---

#### TAU-005: Parenthesized Tautology

**Description:** Detects tautology wrapped in parentheses

**Severity:** HIGH  
**Confidence:** 0.9  
**Priority:** 8  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Identify parenthesis-escaped tautology

**Example Matches:**
- `') OR ('1'='1')`
- `') OR (1=1)--`

**False Positive Cases:**
- Complex legitimate queries with OR in subqueries

**Notes:** Handles multi-parameter injection

---

#### TAU-006: AND 1=1 Probe

**Description:** Detects AND 1=1 testing pattern

**Severity:** MEDIUM  
**Confidence:** 0.75  
**Priority:** 5  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Identify injection probing attempts

**Example Matches:**
- `' AND 1=1--`
- `id=1 AND 1=1`

**False Positive Cases:**
- Legitimate AND conditions with numeric comparison
- Version checks: version AND 1=1

**Notes:** High false positive rate, use with caution

---

#### TAU-007: Double Quote Tautology

**Description:** Detects OR with double quotes

**Severity:** HIGH  
**Confidence:** 0.91  
**Priority:** 8  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Catch double-quote escaped tautology

**Example Matches:**
- `" OR "1"="1`
- `" OR "a"="a"--`

**False Positive Cases:**
- JSON data with OR operator

**Notes:** Handles double-quote injection vectors

---

#### TAU-008: LIKE Wildcard Tautology

**Description:** Detects OR LIKE '%' always-true pattern

**Severity:** MEDIUM  
**Confidence:** 0.82  
**Priority:** 6  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Identify LIKE-based tautology

**Example Matches:**
- `' OR name LIKE '%'--`
- `' OR 1 LIKE '%'`

**False Positive Cases:**
- Legitimate wildcard searches

**Notes:** Lower confidence due to legitimate LIKE usage

---

#### TAU-009: Arithmetic Tautology

**Description:** Detects OR with arithmetic operations

**Severity:** LOW  
**Confidence:** 0.7  
**Priority:** 4  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Catch arithmetic-based tautology

**Example Matches:**
- `' OR 1+1=2--`
- `' OR 5*2=10`

**False Positive Cases:**
- Legitimate arithmetic in queries
- Mathematical calculations

**Notes:** High FP rate, disabled by default in strict mode

---

#### TAU-010: EXISTS Subquery Tautology

**Description:** Detects OR EXISTS with always-true subquery

**Severity:** HIGH  
**Confidence:** 0.93  
**Priority:** 9  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Identify EXISTS-based bypass

**Example Matches:**
- `' OR EXISTS(SELECT 1)--`
- `' OR EXISTS(SELECT * FROM users)--`

**False Positive Cases:**
- Complex legitimate queries with OR EXISTS

**Notes:** Strong indicator of advanced injection

---

### UNION-Based Injection (10 rules)

#### UNI-001: UNION SELECT Pattern

**Description:** Detects UNION SELECT keyword combination

**Severity:** CRITICAL  
**Confidence:** 0.98  
**Priority:** 15  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Primary UNION injection detector

**Example Matches:**
- `' UNION SELECT NULL--`
- `' UNION ALL SELECT username, password FROM users--`
- `1' UNION SELECT @@version--`

**False Positive Cases:**
- Legitimate UNION in stored procedures
- Documentation containing UNION SELECT

**Notes:** High confidence, primary UNION detector

---

#### UNI-002: UNION with NULL Columns

**Description:** Detects UNION SELECT with NULL padding

**Severity:** CRITICAL  
**Confidence:** 0.97  
**Priority:** 14  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Identify column enumeration attempts

**Example Matches:**
- `' UNION SELECT NULL, NULL, NULL--`
- `' UNION ALL SELECT NULL, NULL--`

**False Positive Cases:**
- Legitimate queries selecting NULL values

**Notes:** Strong indicator of column count testing

---

#### UNI-003: UNION from information_schema

**Description:** Detects UNION accessing schema information

**Severity:** CRITICAL  
**Confidence:** 0.99  
**Priority:** 16  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Catch database schema enumeration

**Example Matches:**
- `' UNION SELECT table_name FROM information_schema.tables--`
- `' UNION SELECT column_name FROM information_schema.columns--`

**False Positive Cases:**
- DBA maintenance scripts

**Notes:** Very high confidence, schema extraction attempt

---

#### UNI-004: UNION with CONCAT

**Description:** Detects UNION SELECT with CONCAT for data exfiltration

**Severity:** CRITICAL  
**Confidence:** 0.96  
**Priority:** 14  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Identify data concatenation for extraction

**Example Matches:**
- `' UNION SELECT CONCAT(username, ':', password) FROM users--`
- `' UNION SELECT CONCAT(0x7e, version(), 0x7e)--`

**False Positive Cases:**
- Legitimate string concatenation in queries

**Notes:** Indicates data aggregation attempt

---

#### UNI-005: UNION with Numeric Sequence

**Description:** Detects UNION SELECT 1,2,3... pattern

**Severity:** CRITICAL  
**Confidence:** 0.94  
**Priority:** 13  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Catch column position testing

**Example Matches:**
- `' UNION SELECT 1,2,3,4,5--`
- `' UNION ALL SELECT 1,2,3--`

**False Positive Cases:**
- Queries selecting literal numbers

**Notes:** Column enumeration technique

---

#### UNI-006: UNION with System Functions

**Description:** Detects UNION accessing database version/config

**Severity:** CRITICAL  
**Confidence:** 0.98  
**Priority:** 15  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Identify system information extraction

**Example Matches:**
- `' UNION SELECT @@version--`
- `' UNION SELECT user(), database()--`

**False Positive Cases:**
- System diagnostics queries

**Notes:** High value target - system enumeration

---

#### UNI-007: UNION INTO OUTFILE

**Description:** Detects UNION with file write attempt

**Severity:** CRITICAL  
**Confidence:** 0.99  
**Priority:** 18  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Catch file system write attempts

**Example Matches:**
- `' UNION SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/shell.php'--`

**False Positive Cases:**
- Legitimate export queries

**Notes:** Extremely dangerous - remote code execution

---

#### UNI-008: UNION with GROUP_CONCAT

**Description:** Detects UNION with GROUP_CONCAT aggregation

**Severity:** CRITICAL  
**Confidence:** 0.95  
**Priority:** 14  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Identify bulk data extraction

**Example Matches:**
- `' UNION SELECT GROUP_CONCAT(username) FROM users--`
- `' UNION SELECT GROUP_CONCAT(table_name) FROM information_schema.tables--`

**False Positive Cases:**
- Legitimate aggregation queries

**Notes:** Efficient data exfiltration method

---

#### UNI-009: UNION with LOAD_FILE

**Description:** Detects UNION with file read function

**Severity:** CRITICAL  
**Confidence:** 0.99  
**Priority:** 17  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Catch file system read attempts

**Example Matches:**
- `' UNION SELECT LOAD_FILE('/etc/passwd')--`
- `' UNION SELECT LOAD_FILE('C:\\boot.ini')--`

**False Positive Cases:**
- Legitimate file import queries

**Notes:** Sensitive file access attempt

---

#### UNI-010: UNION with CHAR Function

**Description:** Detects UNION with CHAR-based encoding

**Severity:** CRITICAL  
**Confidence:** 0.93  
**Priority:** 13  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Identify obfuscated UNION attacks

**Example Matches:**
- `' UNION SELECT CHAR(97,100,109,105,110)--`
- `' UNION SELECT CHAR(0x41)--`

**False Positive Cases:**
- Character encoding in legitimate queries

**Notes:** Evasion technique using ASCII encoding

---

### Comment-Based Injection (8 rules)

#### CMT-001: SQL Double Dash Comment

**Description:** Detects -- comment sequence

**Severity:** HIGH  
**Confidence:** 0.85  
**Priority:** 10  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Identify query truncation via comments

**Example Matches:**
- `admin'--`
- `' OR 1=1--`
- `'; DROP TABLE users--`

**False Positive Cases:**
- URLs with --: http://example.com/page--old
- Email addresses: user--test@example.com
- Product codes: MODEL-X--2024

**Notes:** High false positive rate, requires context

---

#### CMT-002: SQL Hash Comment

**Description:** Detects # comment for MySQL

**Severity:** HIGH  
**Confidence:** 0.8  
**Priority:** 9  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Catch MySQL-style comment injection

**Example Matches:**
- `admin'#`
- `' OR 1=1#`
- `'; DELETE FROM users#`

**False Positive Cases:**
- Hashtags in social media content
- Hex color codes: #FF5733
- Markdown headers

**Notes:** MySQL specific, high FP in web content

---

#### CMT-003: SQL Block Comment Start

**Description:** Detects /* comment block opening

**Severity:** HIGH  
**Confidence:** 0.88  
**Priority:** 11  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Identify multi-line comment injection

**Example Matches:**
- `admin'/*`
- `' OR 1=1/* comment */`
- `'; DROP TABLE users/*`

**False Positive Cases:**
- CSS comments: /* styling */
- JavaScript comments in code samples

**Notes:** Can span multiple lines

---

#### CMT-004: Comment After Quote

**Description:** Detects quote followed immediately by comment

**Severity:** HIGH  
**Confidence:** 0.92  
**Priority:** 12  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Catch immediate query truncation

**Example Matches:**
- `admin'--`
- `password'#`
- `user'/*`

**False Positive Cases:**
- Legitimate string literals with special chars

**Notes:** Strong indicator when combined with quotes

---

#### CMT-005: Inline SQL Comment

**Description:** Detects /*!... */ MySQL inline comment

**Severity:** CRITICAL  
**Confidence:** 0.96  
**Priority:** 14  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Catch version-specific comment bypass

**Example Matches:**
- `/*!50000 UNION SELECT */`
- `/*!32302 AND 1=1 */`

**False Positive Cases:**
- Rare in normal traffic

**Notes:** MySQL conditional execution, very suspicious

---

#### CMT-006: Comment with SQL Keywords

**Description:** Detects comments containing SQL keywords

**Severity:** MEDIUM  
**Confidence:** 0.78  
**Priority:** 7  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Identify commented-out malicious SQL

**Example Matches:**
- `-- SELECT * FROM users`
- `# DROP TABLE admin`

**False Positive Cases:**
- SQL documentation
- Code comments in applications

**Notes:** Context-dependent, useful for logging

---

#### CMT-007: Nested Comment Blocks

**Description:** Detects nested /*/* */ comments

**Severity:** MEDIUM  
**Confidence:** 0.85  
**Priority:** 8  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Catch advanced comment obfuscation

**Example Matches:**
- `/* /* nested */ */`
- `/* /* DROP TABLE */ */`

**False Positive Cases:**
- Malformed code comments

**Notes:** Rare pattern, indicates evasion attempt

---

#### CMT-008: Comment Whitespace Obfuscation

**Description:** Detects excessive whitespace before comments

**Severity:** LOW  
**Confidence:** 0.7  
**Priority:** 5  
**Enabled:** No

**Pattern:**
``````

**Purpose:** Identify whitespace-padded comments

**Example Matches:**
- `'          --`
- `'               #`

**False Positive Cases:**
- Formatted code with alignment

**Notes:** Disabled by default, experimental

---

### Stacked Queries Injection (8 rules)

#### STK-001: Semicolon with DROP

**Description:** Detects semicolon followed by DROP statement

**Severity:** CRITICAL  
**Confidence:** 0.99  
**Priority:** 20  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Catch destructive stacked query attempts

**Example Matches:**
- `'; DROP TABLE users--`
- `1'; DROP DATABASE testdb--`
- `'; DROP VIEW admin_view--`

**False Positive Cases:**
- SQL scripts with multiple statements
- Stored procedures

**Notes:** Extremely dangerous, highest priority

---

#### STK-002: Semicolon with DELETE

**Description:** Detects semicolon followed by DELETE

**Severity:** CRITICAL  
**Confidence:** 0.98  
**Priority:** 19  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Identify data deletion attempts

**Example Matches:**
- `'; DELETE FROM users--`
- `1'; DELETE FROM products WHERE 1=1--`

**False Positive Cases:**
- Batch operations in stored procedures

**Notes:** Data loss risk, very high severity

---

#### STK-003: Semicolon with UPDATE

**Description:** Detects semicolon followed by UPDATE

**Severity:** CRITICAL  
**Confidence:** 0.97  
**Priority:** 18  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Catch unauthorized data modification

**Example Matches:**
- `'; UPDATE users SET password='hacked'--`
- `1'; UPDATE products SET price=0--`

**False Positive Cases:**
- Legitimate batch updates

**Notes:** Privilege escalation potential

---

#### STK-004: Semicolon with INSERT

**Description:** Detects semicolon followed by INSERT

**Severity:** HIGH  
**Confidence:** 0.95  
**Priority:** 16  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Identify unauthorized data insertion

**Example Matches:**
- `'; INSERT INTO logs VALUES ('breach')--`
- `1'; INSERT INTO admin (user) VALUES ('attacker')--`

**False Positive Cases:**
- Batch insert operations

**Notes:** Can create backdoor accounts

---

#### STK-005: Semicolon with EXEC

**Description:** Detects semicolon followed by EXEC/EXECUTE

**Severity:** CRITICAL  
**Confidence:** 0.98  
**Priority:** 19  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Catch stored procedure execution

**Example Matches:**
- `'; EXEC xp_cmdshell('dir')--`
- `'; EXECUTE sp_executesql N'malicious'--`

**False Positive Cases:**
- Legitimate stored procedure calls

**Notes:** RCE potential, extremely dangerous

---

#### STK-006: Semicolon with CREATE

**Description:** Detects semicolon followed by CREATE

**Severity:** HIGH  
**Confidence:** 0.96  
**Priority:** 15  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Identify object creation attempts

**Example Matches:**
- `'; CREATE TABLE backdoor (id INT)--`
- `'; CREATE USER attacker@localhost--`

**False Positive Cases:**
- DDL scripts

**Notes:** Persistence mechanism

---

#### STK-007: Semicolon with GRANT

**Description:** Detects semicolon followed by GRANT

**Severity:** CRITICAL  
**Confidence:** 0.99  
**Priority:** 20  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Catch privilege escalation

**Example Matches:**
- `'; GRANT ALL PRIVILEGES ON *.* TO 'attacker'@'%'--`

**False Positive Cases:**
- DBA scripts

**Notes:** Complete system compromise potential

---

#### STK-008: Multiple Semicolons

**Description:** Detects multiple consecutive semicolons

**Severity:** MEDIUM  
**Confidence:** 0.75  
**Priority:** 7  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Identify chained statement attempts

**Example Matches:**
- `'; ; DROP TABLE users--`
- `1; ; DELETE FROM logs--`

**False Positive Cases:**
- Malformed queries
- CSS with double semicolons

**Notes:** May indicate fuzzing or obfuscation

---

### Time-Based Blind Injection (8 rules)

#### TMB-001: MySQL SLEEP Function

**Description:** Detects MySQL SLEEP function

**Severity:** CRITICAL  
**Confidence:** 0.97  
**Priority:** 17  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Identify time-delay based blind injection

**Example Matches:**
- `' AND SLEEP(5)--`
- `' OR IF(1=1, SLEEP(5), 0)--`
- `' AND (SELECT * FROM (SELECT(SLEEP(5)))xyz)--`

**False Positive Cases:**
- Performance testing queries
- Documentation mentioning SLEEP

**Notes:** Clear blind injection indicator

---

#### TMB-002: MSSQL WAITFOR DELAY

**Description:** Detects MS SQL Server WAITFOR DELAY

**Severity:** CRITICAL  
**Confidence:** 0.98  
**Priority:** 17  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Catch MSSQL time-based injection

**Example Matches:**
- `'; WAITFOR DELAY '00:00:05'--`
- `' AND WAITFOR DELAY '00:00:10'--`

**False Positive Cases:**
- Legitimate delay in stored procedures

**Notes:** MSSQL specific blind injection

---

#### TMB-003: BENCHMARK Function

**Description:** Detects BENCHMARK function for delays

**Severity:** CRITICAL  
**Confidence:** 0.95  
**Priority:** 16  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Identify MySQL BENCHMARK-based delay

**Example Matches:**
- `' AND BENCHMARK(5000000,MD5('A'))--`
- `' OR BENCHMARK(1000000,SHA1('test'))--`

**False Positive Cases:**
- Performance benchmarking scripts

**Notes:** CPU-intensive delay method

---

#### TMB-004: PostgreSQL pg_sleep

**Description:** Detects PostgreSQL pg_sleep function

**Severity:** CRITICAL  
**Confidence:** 0.97  
**Priority:** 17  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Catch PostgreSQL time-based injection

**Example Matches:**
- `'; SELECT pg_sleep(5)--`
- `' AND (SELECT pg_sleep(10))--`

**False Positive Cases:**
- Database maintenance scripts

**Notes:** PostgreSQL specific

---

#### TMB-005: Heavy Query Delay

**Description:** Detects heavy query patterns for delay

**Severity:** MEDIUM  
**Confidence:** 0.72  
**Priority:** 6  
**Enabled:** No

**Pattern:**
``````

**Purpose:** Identify resource-intensive delay attempts

**Example Matches:**
- `' AND (SELECT COUNT(*) FROM huge_table WHERE 1=1)--`

**False Positive Cases:**
- Legitimate aggregate queries

**Notes:** Disabled by default, high FP rate

---

#### TMB-006: Conditional Sleep

**Description:** Detects IF/CASE with SLEEP

**Severity:** CRITICAL  
**Confidence:** 0.96  
**Priority:** 17  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Catch conditional blind injection

**Example Matches:**
- `' AND IF(1=1, SLEEP(5), 0)--`
- `' AND CASE WHEN 1=1 THEN SLEEP(5) END--`

**False Positive Cases:**
- Complex legitimate queries

**Notes:** Advanced blind injection technique

---

#### TMB-007: SLEEP with Subquery

**Description:** Detects SLEEP in subquery

**Severity:** CRITICAL  
**Confidence:** 0.94  
**Priority:** 16  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Identify nested sleep injection

**Example Matches:**
- `' AND (SELECT SLEEP(5))--`
- `' OR (SELECT IF(1=1,SLEEP(5),0))--`

**False Positive Cases:**
- Rare in legitimate queries

**Notes:** Subquery-based blind injection

---

#### TMB-008: Time Function Arithmetic

**Description:** Detects manipulation of time functions

**Severity:** MEDIUM  
**Confidence:** 0.68  
**Priority:** 5  
**Enabled:** No

**Pattern:**
``````

**Purpose:** Catch time-based data inference

**Example Matches:**
- `' AND NOW() + INTERVAL 10 SECOND--`

**False Positive Cases:**
- Date arithmetic in legitimate queries

**Notes:** Experimental, disabled by default

---

### Advanced & Evasion Techniques (15 rules)

#### ADV-001: Hexadecimal Encoding

**Description:** Detects hex-encoded strings

**Severity:** HIGH  
**Confidence:** 0.85  
**Priority:** 12  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Identify hex-encoded payloads

**Example Matches:**
- `0x61646d696e`
- `SELECT 0x48656c6c6f`

**False Positive Cases:**
- Legitimate hex values in data
- Color codes (short hex)
- MAC addresses

**Notes:** Filter by length, longer = more suspicious

---

#### ADV-002: CHAR Function Encoding

**Description:** Detects CHAR() with multiple ASCII values

**Severity:** HIGH  
**Confidence:** 0.9  
**Priority:** 13  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Catch ASCII-encoded injection

**Example Matches:**
- `CHAR(97,100,109,105,110)`
- `CHAR(115,101,108,101,99,116)`

**False Positive Cases:**
- Character set conversions

**Notes:** Common obfuscation technique

---

#### ADV-003: URL Encoding in Query

**Description:** Detects URL-encoded characters

**Severity:** MEDIUM  
**Confidence:** 0.78  
**Priority:** 8  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Identify URL-encoded injection attempts

**Example Matches:**
- `%27%20OR%201=1--`
- `%27%20UNION%20SELECT%20--`

**False Positive Cases:**
- Legitimate URL-encoded parameters

**Notes:** Requires URL decoding before analysis

---

#### ADV-004: xp_cmdshell Execution

**Description:** Detects MSSQL xp_cmdshell

**Severity:** CRITICAL  
**Confidence:** 0.99  
**Priority:** 20  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Catch OS command execution attempts

**Example Matches:**
- `'; EXEC xp_cmdshell('net user')--`
- `'; EXEC xp_cmdshell('dir')--`

**False Positive Cases:**
- DBA maintenance scripts

**Notes:** Remote code execution, highest severity

---

#### ADV-005: Stored Procedure Abuse

**Description:** Detects suspicious sp_ procedures

**Severity:** CRITICAL  
**Confidence:** 0.97  
**Priority:** 18  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Identify privilege escalation via stored procs

**Example Matches:**
- `'; EXEC sp_addrolemember 'db_owner', 'attacker'--`
- `'; EXEC sp_executesql N'DROP TABLE users'--`

**False Positive Cases:**
- Legitimate admin operations

**Notes:** MSSQL privilege escalation

---

#### ADV-006: LOAD_FILE Function

**Description:** Detects MySQL LOAD_FILE

**Severity:** CRITICAL  
**Confidence:** 0.98  
**Priority:** 19  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Catch file system read attempts

**Example Matches:**
- `UNION SELECT LOAD_FILE('/etc/passwd')--`
- `' AND LOAD_FILE('C:\\boot.ini')--`

**False Positive Cases:**
- Legitimate file import

**Notes:** Sensitive file access

---

#### ADV-007: INTO OUTFILE Write

**Description:** Detects INTO OUTFILE

**Severity:** CRITICAL  
**Confidence:** 0.99  
**Priority:** 20  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Identify file write attempts

**Example Matches:**
- `SELECT '<?php ?>' INTO OUTFILE '/var/www/shell.php'--`

**False Positive Cases:**
- Data export operations

**Notes:** Web shell creation, RCE

---

#### ADV-008: EXTRACTVALUE XML Injection

**Description:** Detects EXTRACTVALUE for error-based injection

**Severity:** HIGH  
**Confidence:** 0.92  
**Priority:** 14  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Catch XML-based data extraction

**Example Matches:**
- `' AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT @@version)))--`

**False Positive Cases:**
- XML processing queries

**Notes:** Error-based injection technique

---

#### ADV-009: UPDATEXML Injection

**Description:** Detects UPDATEXML for injection

**Severity:** HIGH  
**Confidence:** 0.91  
**Priority:** 13  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Identify XML-based injection

**Example Matches:**
- `' AND UPDATEXML(1, CONCAT(0x7e, (SELECT user())), 1)--`

**False Positive Cases:**
- XML update operations

**Notes:** Error-based technique

---

#### ADV-010: Multi-Encoding Attack

**Description:** Detects mixed encoding (hex + URL)

**Severity:** HIGH  
**Confidence:** 0.88  
**Priority:** 12  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Catch multi-layer obfuscation

**Example Matches:**
- `%27%200x61646d696e`
- `0x41%20%20%27`

**False Positive Cases:**
- Rare in legitimate traffic

**Notes:** Advanced evasion attempt

---

#### ADV-011: Concatenation Obfuscation

**Description:** Detects excessive CONCAT usage

**Severity:** MEDIUM  
**Confidence:** 0.75  
**Priority:** 7  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Identify nested concatenation evasion

**Example Matches:**
- `CONCAT(CONCAT('SE','LECT'), ' * FROM users')`
- `CONCAT(CONCAT(0x41,0x42),0x43)`

**False Positive Cases:**
- Complex string building

**Notes:** Keyword fragmentation technique

---

#### ADV-012: Alternative Comment Syntax

**Description:** Detects MySQL alternative comment

**Severity:** HIGH  
**Confidence:** 0.93  
**Priority:** 14  
**Enabled:** Yes

**Pattern:**
``````

**Purpose:** Catch version-conditional code

**Example Matches:**
- `/*!50000UNION*/`
- `/*!32302AND*/1=1`

**False Positive Cases:**
- Rare in user input

**Notes:** MySQL version-specific execution

---

#### ADV-013: White Space Obfuscation

**Description:** Detects excessive whitespace between keywords

**Severity:** LOW  
**Confidence:** 0.65  
**Priority:** 4  
**Enabled:** No

**Pattern:**
``````

**Purpose:** Identify whitespace evasion

**Example Matches:**
- `SELECT     * FROM users`
- `UNION          SELECT`

**False Positive Cases:**
- Formatted SQL
- Pretty-printed queries

**Notes:** Disabled by default, experimental

---

#### ADV-014: Case Alternation Evasion

**Description:** Detects alternating case in keywords

**Severity:** LOW  
**Confidence:** 0.6  
**Priority:** 3  
**Enabled:** No

**Pattern:**
``````

**Purpose:** Catch case-based WAF bypass

**Example Matches:**
- `SeLeCt * FROM users`
- `UnIoN SELECT`

**False Positive Cases:**
- User-entered mixed case

**Notes:** Redundant if case-insensitive matching used

---

#### ADV-015: Scientific Notation Numbers

**Description:** Detects scientific notation in injection

**Severity:** LOW  
**Confidence:** 0.62  
**Priority:** 3  
**Enabled:** No

**Pattern:**
``````

**Purpose:** Identify numeric obfuscation

**Example Matches:**
- `1e0`
- `1e1`

**False Positive Cases:**
- Legitimate scientific notation in data

**Notes:** Rare evasion technique, low priority

---

