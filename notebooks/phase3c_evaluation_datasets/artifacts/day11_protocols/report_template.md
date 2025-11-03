# SQL Injection Detection System - Evaluation Report
**Date:** November 03, 2025
**Version:** 1.0
**Evaluator:** Phase 3D Evaluation Pipeline
**Dataset:** Phase 3C Evaluation Set (36,149 samples)
---
## Executive Summary
### Key Metrics Summary
| Metric | Value | Target | Status |
|--------|-------|--------|--------|
| **Accuracy** | TBD | ≥94% | TBD |
| **Precision** | TBD | ≥95% | TBD |
| **Recall** | TBD | ≥90% | TBD |
| **F1-Score** | TBD | ≥92% | TBD |
| **ROC-AUC** | TBD | ≥0.97 | TBD |
| **FPR (Benign)** | TBD | ≤5% | TBD |
| **Latency** | TBD | ≤50ms | TBD |
### Overall Status
**Status:** TBD
**Recommendation:** TBD
---
## 1. Dataset Overview
### Composition
- Total Samples: 36,149
- Benign: 15,570 (43.1%)
- Malicious: 20,579 (56.9%)
- High Confidence: 36,149 (100%)
- Inter-annotator Agreement: Cohen's Kappa = 1.0
### Distribution by Source
- Days 3-4 Novel Attacks: 2,000 (5.5%)
- Days 5-6 Adversarial Suite: 3,579 (9.9%)
- Day 7 Production Benign: 15,570 (43.1%)
- Day 8 Cross-Domain: 15,000 (41.5%)
---
## 2. Overall Performance
### Confusion Matrix (Hybrid Model)
Predicted Negative | Predicted Positive
Actual Negative [TN: TBD] | [FP: TBD]
Actual Positive [FN: TBD] | [TP: TBD]
### Classification Metrics
- **Accuracy:** TBD% (goal: ≥94%)
- **Precision:** TBD% (goal: ≥95%)
- **Recall:** TBD% (goal: ≥90%)
- **F1-Score:** TBD (goal: ≥0.92)
- **False Positive Rate:** TBD% (goal: ≤5%)
- **False Negative Rate:** TBD% (goal: ≤10%)
### Advanced Metrics
- **ROC-AUC:** TBD (goal: ≥0.97)
- **PR-AUC:** TBD (goal: ≥0.95)
---
## 3. Per-Domain Analysis
| Domain | Samples | Precision | Recall | F1-Score | Status |
|--------|---------|-----------|--------|----------|--------|
| SQL Analytics | 1,875 | TBD | TBD | TBD | TBD |
| REST API JSON | 1,875 | TBD | TBD | TBD | TBD |
| GraphQL | 1,875 | TBD | TBD | TBD | TBD |
| MongoDB | 1,875 | TBD | TBD | TBD | TBD |
| Elasticsearch | 1,875 | TBD | TBD | TBD | TBD |
| Stored Procedures | 1,875 | TBD | TBD | TBD | TBD |
| ORM (SQLAlchemy) | 1,875 | TBD | TBD | TBD | TBD |
| Search Engine | 1,875 | TBD | TBD | TBD | TBD |
---
## 4. Per-Category Analysis
| Category | Samples | Recall | Status |
|----------|---------|--------|--------|
| SQL Injection | TBD | TBD% | TBD |
| UNION-based SQLi | TBD | TBD% | TBD |
| OR-based SQLi | TBD | TBD% | TBD |
| Comment Injection | TBD | TBD% | TBD |
| Semicolon Exec | TBD | TBD% | TBD |
---
## 5. Performance Metrics
### Latency Analysis
- **Average Latency:** TBD ms (goal: ≤50ms)
- **P95 Latency:** TBD ms
- **P99 Latency:** TBD ms
### Throughput
- **Average Throughput:** TBD QPS (goal: ≥100 QPS)
- **Peak Throughput:** TBD QPS
### Memory Footprint
- **Total Model Size:** TBD MB
---
## 6. Acceptance Criteria Status
| Criterion | Target | Achieved | Pass/Fail |
|-----------|--------|----------|-----------|
| Accuracy | ≥94% | TBD | TBD |
| Precision | ≥95% | TBD | TBD |
| Recall | ≥90% | TBD | TBD |
| F1-Score | ≥92% | TBD | TBD |
| ROC-AUC | ≥0.97 | TBD | TBD |
| FPR | ≤5% | TBD | TBD |
**Overall Status:** TBD
---
**Report Generated:** November 03, 2025
**Approval Status:** ☐ Pending Review
