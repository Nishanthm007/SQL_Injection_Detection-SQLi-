# SQL Injection Detection Rule Engine Specification

**Version:** 1.0  
**Date:** 2025-10-18  
**Status:** APPROVED

## 1. Overview

This document specifies the architecture, configuration, and decision logic for the SQL Injection Detection Rule Engine.

## 2. Rule File Format

**Format:** JSON  
**Required Fields:** 8  
**Optional Fields:** 9

### 2.1 Required Fields

- `rule_id` (string): Unique identifier (e.g., TAU-001)
- `name` (string): Human-readable rule name
- `regex` (string): Detection pattern
- `category` (string): Attack category
- `severity` (string): LOW | MEDIUM | HIGH | CRITICAL
- `confidence` (float): 0.0-1.0
- `priority` (integer): 1-20
- `enabled` (boolean): Activation status

## 3. Decision Logic

### 3.1 Supported Strategies

1. **First Match** - Stop on first rule match
2. **Weighted Sum** - Calculate score from all matches (RECOMMENDED)
3. **Threshold Voting** - Require N rules to match
4. **Veto Rules** - Whitelist/blacklist override
5. **Category-Based** - Flag critical categories immediately

### 3.2 Recommended Strategy: Weighted Sum

**Formula:**
score = SUM(rule.confidence * rule.priority * severity_multiplier)

text

**Severity Multipliers:**
- LOW: 1.0
- MEDIUM: 1.5
- HIGH: 2.0
- CRITICAL: 3.0

**Detection Threshold:** 10.0

## 4. Configuration Management

### 4.1 Version Control

- **System:** Git
- **Branching:** main (prod), develop (test), feature/* (new rules)
- **Commit Format:** [RULE] <rule_id>: <action> - <description>

### 4.2 Versioning

- **Format:** Semantic Versioning (MAJOR.MINOR.PATCH)
- **MAJOR:** Incompatible changes
- **MINOR:** New rules (backward compatible)
- **PATCH:** Bug fixes, improvements

### 4.3 Deployment Workflow

1. Develop rule in feature branch
2. Test against datasets
3. Code + security review
4. Canary deployment (5%)
5. Monitor 24 hours
6. Full production deployment

### 4.4 Hot Reload

- **Enabled:** Yes
- **Watch Files:** rules_machine.json, engine_config.json
- **Validation:** Pre-reload syntax check
- **Rollback:** Automatic on error

## 5. Engine Configuration

### 5.1 Performance

- Max timeout: 10ms per query
- Caching: Enabled (1000 entries, 5min TTL)
- Compiled patterns: Yes

### 5.2 Detection

- Strategy: weighted_sum
- Threshold: 10.0
- Min confidence: 0.70
- Stop on critical: Yes

### 5.3 Logging

- Level: INFO
- Format: JSON
- Log matched queries: Yes
- Sensitive data masking: Yes

## 6. Implementation Notes

- **Language:** Python 3.8+
- **Regex Engine:** `re` (standard library)
- **Performance Target:** < 10ms per query
- **Deployment:** Docker container
- **Concurrency:** Thread-safe

## 7. Metrics & Monitoring

### 7.1 Key Metrics

- Query latency (p50, p95, p99)
- Rule hit rate per rule
- False positive rate
- False negative rate
- Throughput (queries/sec)

### 7.2 Alerting

- Critical rule matches
- High FP rate detection
- Latency threshold breach
- Rate limiting: 100 alerts/hour

## 8. Security Considerations

- No query content in standard logs (enable only for debugging)
- Sensitive data masking in logs
- Rate limiting on alerts
- Rule integrity validation on load
- Secure config file permissions

## 9. Future Enhancements

- Machine learning integration (Phase 4)
- Distributed rule evaluation
- Real-time rule A/B testing
- Automated false positive learning
