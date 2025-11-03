# Metrics Definitions Reference
## Classification Metrics
### 1. Accuracy
**Formula:** (TP + TN) / (TP + TN + FP + FN)
**Interpretation:** Overall correctness
**Target:** ≥94%
### 2. Precision
**Formula:** TP / (TP + FP)
**Interpretation:** Of flagged samples, how many are correct?
**Target:** ≥95%
### 3. Recall
**Formula:** TP / (TP + FN)
**Interpretation:** Of malicious samples, how many are caught?
**Target:** ≥90%
### 4. F1-Score
**Formula:** 2 × (Precision × Recall) / (Precision + Recall)
**Interpretation:** Harmonic mean of precision and recall
**Target:** ≥92%
### 5. False Positive Rate (FPR)
**Formula:** FP / (FP + TN)
**Interpretation:** Rate of false alarms on benign traffic
**Target:** ≤5%
### 6. False Negative Rate (FNR)
**Formula:** FN / (FN + TP)
**Interpretation:** Rate of missed attacks
**Target:** ≤10%
## Advanced Metrics
### 7. ROC-AUC
**Interpretation:** Trade-off between TPR and FPR at various thresholds
**Target:** ≥0.97
### 8. PR-AUC
**Interpretation:** Precision vs Recall at various thresholds
**Target:** ≥0.95
## Performance Metrics
### 9. Latency
**Definition:** Time to classify one query
**Target:** ≤50ms
### 10. Throughput
**Definition:** Queries processed per second (QPS)
**Target:** ≥100 QPS
### 11. Memory Footprint
**Definition:** Total size of models in RAM
**Target:** ≤500 MB
## Success Criteria
| Metric | Target | Priority |
|--------|--------|----------|
| Accuracy | ≥94% | CRITICAL |
| Precision | ≥95% | CRITICAL |
| Recall | ≥90% | CRITICAL |
| F1-Score | ≥92% | CRITICAL |
| ROC-AUC | ≥0.97 | HIGH |
| FPR | ≤5% | CRITICAL |
| FNR | ≤10% | HIGH |
| Per-Domain F1 | ≥92% | HIGH |
| Latency | ≤50ms | MEDIUM |
| Throughput | ≥100 QPS | MEDIUM |
**Pass Criteria:**
- ALL CRITICAL metrics achieved
- ≥80% of HIGH metrics achieved
- ≥70% of MEDIUM metrics achieved
