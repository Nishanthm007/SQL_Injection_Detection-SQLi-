# EVALUATION PLAN v1.0
**Date Created:** November 03, 2025
**Version:** 1.0
**Status:** Ready for Review & Approval
---
## 1. Executive Summary
This document defines the comprehensive evaluation protocol for the SQL Injection Detection System (SIDS) across 36,149 high-quality evaluation samples.
**Key Objectives:**
- Validate detection accuracy across diverse query types
- Measure robustness against adversarial variations
- Assess cross-domain generalization capability
- Benchmark performance (accuracy, latency, throughput)
- Identify model strengths and weaknesses
---
## 2. Evaluation Dataset Composition
### Dataset Overview
Total Samples: 36,149
- Days 3-4 Novel Attacks: 2,000 (malicious)
- Days 5-6 Adversarial Suite: 3,579 (malicious variants)
- Day 7 Production Benign: 15,570 (benign)
- Day 8 Cross-Domain: 15,000 (mixed domains)
Quality Metrics:
✅ Zero data leakage (verified vs Phase 3B training)
✅ Zero internal duplicates (dedup verified)
✅ 100% high-confidence labels (Cohen's kappa = 1.0)
✅ 100% inter-annotator agreement
---
## 3. Evaluation Runs
### Run 1: Rule-Only Baseline
- Models: Rule engine (7 detection rules)
- Threshold: 0.5
- Purpose: Establish baseline performance
### Run 2: CNN-Only
- Models: CNN trained on Phase 3B
- Threshold: 0.7
- Purpose: Evaluate ML-only performance
### Run 3: Hybrid Detection (Rule + CNN Fusion)
- Models: Rule engine + CNN
- Fusion: Weighted voting (rule=0.3, cnn=0.7)
- Threshold: 0.6
- Purpose: Evaluate complementary strengths
### Run 4: Per-Domain Evaluation
- Models: Hybrid detector
- Domains: 8 domains (SQL, REST API, GraphQL, MongoDB, Elasticsearch, Stored Procedures, ORM, Search)
- Purpose: Measure domain transfer generalization
---
## 4. Metrics Definition
### Primary Metrics
- **Precision:** TP / (TP + FP) | Target: ≥95%
- **Recall:** TP / (TP + FN) | Target: ≥90%
- **F1-Score:** 2×(Precision×Recall)/(Precision+Recall) | Target: ≥92%
- **Accuracy:** (TP+TN)/(TP+TN+FP+FN) | Target: ≥94%
### Advanced Metrics
- **ROC-AUC:** Target ≥0.97
- **PR-AUC:** Target ≥0.95
- **False Positive Rate (Benign Set):** Target ≤5%
- **False Negative Rate (Malicious Set):** Target ≤10%
### Performance Metrics
- **Latency:** Target ≤50ms
- **Throughput:** Target ≥100 QPS
- **Memory Footprint:** Target ≤500MB
---
## 5. Thresholds & Decision Rules
### Rule Engine Threshold
- Score Range: 0.0 - 1.0
- Threshold: 0.5
- Decision: score ≥ 0.5 → MALICIOUS
### CNN Model Threshold
- Score Range: 0.0 - 1.0
- Threshold: 0.7
- Decision: score ≥ 0.7 → MALICIOUS
### Hybrid Fusion Threshold
- Fusion Score: weighted_sum(rule_score × 0.3, cnn_score × 0.7)
- Threshold: 0.6
- Decision: fusion_score ≥ 0.6 → MALICIOUS
---
## 6. Success Criteria
| Metric | Target | Priority |
|--------|--------|----------|
| Overall Accuracy | ≥94% | CRITICAL |
| Precision | ≥95% | CRITICAL |
| Recall | ≥90% | CRITICAL |
| F1-Score | ≥92% | CRITICAL |
| ROC-AUC | ≥0.97 | HIGH |
| FPR (Benign) | ≤5% | CRITICAL |
| FNR (Malicious) | ≤10% | HIGH |
| Per-Domain F1 | ≥92% | HIGH |
| Latency | ≤50ms | MEDIUM |
| Throughput | ≥100 QPS | MEDIUM |
---
## 7. Evaluation Workflow
Step 1: Load Models (5 min) - Load rule engine, CNN model, fusion logic
Step 2: Load Evaluation Data (5 min) - Load manifest, filter high-confidence, organize by domain
Step 3: Run Evaluations (40 min) - Run all 4 evaluation scenarios
Step 4: Compute Metrics (15 min) - Classification, advanced, per-domain, per-category metrics
Step 5: Generate Report (10 min) - Confusion matrix, charts, domain/category analysis
---
## 8. Timeline & Resources
**Total Duration:** ~75 minutes
**GPU Required:** NVIDIA A100 or equivalent
**RAM:** 32GB
**Disk:** 50GB
---
## 9. Approval & Sign-Off
**Review Status:** PENDING STAKEHOLDER REVIEW
**Required Approvals:**
- [ ] ML Team Lead
- [ ] Security Lead
- [ ] Project Manager
- [ ] QA Lead
---
**Document Version:** 1.0
**Last Updated:** November 03, 2025
**Next Review:** Upon completion of Phase 3D evaluation
