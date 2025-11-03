# Phase 3C: Acceptance Criteria

**Document Version:** v1.0  
**Date:** November 2, 2025  
**Project:** SQL Injection Detection - Evaluation Acceptance Criteria  

---

## 1. Overall System Performance Targets

### 1.1 Hybrid System (Rule-Based + CNN Fusion)

| Metric | Target | Rationale |
|--------|--------|-----------|
| Overall Accuracy | ≥ 0.99 | Industry benchmark for SQLi detection |
| Overall F1-Score | ≥ 0.90 | Balanced precision/recall |
| Overall Precision | ≥ 0.92 | Minimize false positives |
| Overall Recall | ≥ 0.88 | Catch majority of attacks |

### 1.2 Component Baselines

- **Rule-based engine:** 84% accuracy (from earlier phase)
- **CNN standalone:** ≥ 95% accuracy required
- **Hybrid target:** ≥ 99% accuracy (5+ point improvement)

---

## 2. Per-Dataset Acceptance Thresholds

### 2.1 Novel Attack Test Set

| Metric | Threshold | Rationale |
|--------|-----------|-----------|
| Recall (Malicious) | ≥ 0.85 | Must catch 85%+ novel attacks |
| Precision (Malicious) | ≥ 0.90 | Limit false alarms |
| F1-Score | ≥ 0.87 | Balanced performance |
| Novelty Enforcement | 100% pass filter | Zero training leakage |
| Sample Size | ≥ 1,500 | Statistical significance |

### 2.2 Adversarial Evaluation Suite

| Metric | Threshold | Rationale |
|--------|-----------|-----------|
| Per-Category Recall | ≥ 0.80 | Consistent robustness |
| Hard-Difficulty Recall | ≥ 0.75 | Sophisticated evasion resistance |
| Easy-Difficulty Recall | ≥ 0.95 | Simple obfuscations handled |
| Coverage | All 8+ categories | Comprehensive assessment |
| Hard Case Volume | ≥ 200 per category | Sufficient challenge cases |

### 2.3 Production Benign Complex Queries

| Metric | Threshold | Rationale |
|--------|-----------|-----------|
| False Positive Rate | ≤ 0.05 | Industry acceptable (5%) |
| Precision (Benign) | ≥ 0.95 | 95%+ correctly classified |
| Specificity | ≥ 0.95 | True negative rate |
| Manual Review | Top-100 flagged | Identify FP root causes |
| Diversity | ≥5 dialects, ≥3 ORMs | Realistic variety |
| Sample Size | ≥ 5,000 | Statistical significance |

### 2.4 Cross-Domain Test Set

| Metric | Threshold | Rationale |
|--------|-----------|-----------|
| Per-Domain F1 | ≥ 0.75 | Transfer learning capability |
| Domain Coverage | ≥ 6 domains | Breadth of generalization |
| Per-Domain Samples | ≥ 300 | Statistical validity |
| Label Quality | ≥ 95% high confidence | Accuracy critical |

---

## 3. Per-Transformation Recall Matrix

### 3.1 Adversarial Suite Targets

| Transformation | Easy | Medium | Hard | Average |
|----------------|------|--------|------|---------|
| URL Encoding | ≥0.95 | ≥0.90 | ≥0.80 | ≥0.88 |
| Hex Encoding | ≥0.95 | ≥0.90 | ≥0.80 | ≥0.88 |
| Base64 Encoding | ≥0.90 | ≥0.85 | ≥0.75 | ≥0.83 |
| Comment Insertion | ≥0.95 | ≥0.90 | ≥0.85 | ≥0.90 |
| Case Manipulation | ≥0.95 | ≥0.90 | ≥0.85 | ≥0.90 |
| String Concatenation | ≥0.90 | ≥0.85 | ≥0.75 | ≥0.83 |
| Composite (≥3) | N/A | ≥0.80 | ≥0.70 | ≥0.75 |
| CHAR() Function | ≥0.90 | ≥0.85 | ≥0.75 | ≥0.83 |

---

## 4. Labeling Policy & Human Review

### 4.1 Label Categories

- **Malicious:** Confirmed SQL injection attempt
- **Benign:** Legitimate query, no malicious indicators
- **Uncertain:** Ambiguous (route to triage queue)

### 4.2 Confidence Levels

- **High:** Clear attack/legitimate pattern (target ≥95%)
- **Medium:** Some ambiguity (acceptable <5%)
- **Low:** Significant uncertainty (exclude from scoring)

### 4.3 Inter-Annotator Agreement

- **Minimum annotators:** 2 per sample subset
- **Cohen's kappa target:** ≥ 0.7
- **Sample size:** 200 samples per dataset
- **Disagreement resolution:** Senior SME tie-breaker

### 4.4 Review Quotas

- **Novel Attacks:** 100% manual review for novelty documentation
- **Adversarial Suite:** 20% random sample for transformation accuracy
- **Production Benigns:** Top-100 flagged + 100 random samples
- **Cross-Domain:** 50 samples per domain for label verification

---

## 5. Pass/Fail Decision Criteria

### 5.1 System PASSES If:

- All per-dataset thresholds met
- Overall hybrid F1-score ≥ 0.90
- Inter-annotator Cohen's kappa ≥ 0.7
- Zero training leakage (100% novelty enforcement)

### 5.2 System FAILS If:

- Any critical threshold missed by >5 points
- FPR on production benigns >10%
- Inter-annotator agreement <0.6
- Training leakage detected (>1% exceed similarity threshold)

### 5.3 Conditional Pass (Requires Remediation):

- Thresholds missed by 1-5 points → targeted retraining
- FPR 5-10% → threshold tuning or benign augmentation
- Specific category recall <0.75 → adversarial training on that category

---

## 6. Reporting Requirements

### 6.1 Metrics to Report

**Per Dataset:**
- Confusion matrix
- Precision, Recall, F1-Score (per-class and overall)
- ROC-AUC curves

**Adversarial Suite:**
- Robustness matrix (transformation × difficulty)
- Per-category recall bar charts
- Transformation recall heatmap

**Production Benign:**
- FPR analysis
- Top-K flagged benigns with root cause categories
- Precision-recall curves

**Cross-Domain:**
- Per-domain F1-scores
- Domain comparison bar chart
- Failure mode analysis

### 6.2 Performance Benchmarks

- Latency distribution histogram
- Throughput measurement (qps)
- Memory usage profile

---

## 7. Stakeholder Sign-Off

### 7.1 Approval Required From:

| Role | Name | Signature | Date |
|------|------|-----------|------|
| Model Owner | _____________ | _____________ | ______ |
| Security Lead | _____________ | _____________ | ______ |
| Project Sponsor | _____________ | _____________ | ______ |

### 7.2 Acceptance Statement

By signing above, stakeholders confirm:
- Evaluation objectives are clear and measurable
- Acceptance thresholds are appropriate for production deployment
- Labeling policy and review quotas are adequate
- Reporting requirements will support model acceptance decisions

---

**Status:** DRAFT - Awaiting Sign-Off  
**Approval Deadline:** November 2, 2025  
**Phase 3C Execution:** Begins upon approval
