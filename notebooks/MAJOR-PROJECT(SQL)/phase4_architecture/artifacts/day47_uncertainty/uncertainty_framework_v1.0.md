# Uncertainty-Aware Components Framework

## 1. CONFIDENCE CALIBRATION LAYER

### Temperature Scaling (Post-Softmax)

**Purpose:** Adjust model confidence without changing decision boundary

**Mathematical Definition:**
  p_calibrated = softmax(logits / T)
  
  where:
    T = temperature parameter (learnable in Phase 5)
    T < 1: Sharpens probabilities (high confidence)
    T > 1: Softens probabilities (low confidence)
    T = 1: No calibration (identity)

**Calibration Strategy:**
  - Initial T = 1.0 (no calibration)
  - Learn T on validation set (Phase 5)
  - Range: [0.1, 10.0] (sensible bounds)
  - Optimization: Minimize NLL on held-out set

**Implementation Plan:**
class TemperatureScaling(tf.keras.layers.Layer):
def init(self, initial_temp=1.0, learnable=True):
super().init()
self.temperature = tf.Variable(
[initial_temp],
trainable=learnable,
dtype=tf.float32
)

text
  def call(self, logits):
      # Ensure temperature > 0
      temp = tf.nn.softplus(self.temperature) + 0.1
      return logits / temp
text

---

## 2. UNCERTAINTY QUANTIFICATION

### Uncertainty Metrics Definition

#### A. Predictive Variance
- Measures output spread across predictions
- Formula: Var(y) = E[y²] - E[y]²
- Range: [0, 1] for probabilities
- Interpretation: High variance = high uncertainty

#### B. Confidence Distribution
- Probability mass on predicted class
- Formula: conf = max(p_1, p_2, ..., p_k)
- Range: [0, 1]
- Interpretation: Close to 1 = high confidence

#### C. Epistemic vs Aleatoric
- **Epistemic:** Model uncertainty (reducible with more data)
  - Multi-head disagreement (Bayesian approximation)
  - Ensemble variance
- **Aleatoric:** Data uncertainty (irreducible)
  - Output variance
  - Label noise

### Uncertainty Output Schema

{
"prediction": {
"class": 0,
"class_name": "benign",
"probability": 0.92
},
"confidence": {
"calibrated_confidence": 0.92,
"temperature": 1.0,
"confidence_percentile": 0.87
},
"uncertainty": {
"predictive_variance": 0.034,
"entropy": 0.198,
"margin": 0.12
},
"multi_head": {
"head_1_pred": 0,
"head_2_pred": 0,
"head_3_pred": 0,
"ensemble_agreement": 1.0,
"epistemic_uncertainty": 0.0
},
"calibration": {
"is_high_confidence": true,
"confidence_level": "HIGH",
"recommendation": "TRUST_PREDICTION"
}
}

text

---

## 3. MULTI-HEAD PREDICTION MECHANISM

### Architecture Design

**Concept:** Multiple classifier heads trained jointly for ensemble-style internal voting

Feature Vector (256-dim)
↓
┌─────────────────────────────────────────────┐
│ │
├─→ [Dense 128 → ReLU → Dropout] → Head 1 │
├─→ [Dense 128 → ReLU → Dropout] → Head 2 │
├─→ [Dense 128 → ReLU → Dropout] → Head 3 │
└─→ [Dense 128 → ReLU → Dropout] → Head 4 │
↓ ↓ ↓ ↓
Output 1 Output 2 Output 3 Output 4
↓
[Ensemble Combiner]
├─→ Vote-based averaging (simple)
├─→ Attention-based gating (learned)
└─→ Confidence weighting (adaptive)
↓
Final Prediction + Confidence + Epistemic Uncertainty

text

### Head Configuration

| Head | Type | Purpose | Parameters |
|------|------|---------|-----------|
| Head 1 | Detection | Detect SQL injection presence | 258 |
| Head 2 | Confidence | Estimate prediction confidence | 258 |
| Head 3 | Uncertainty | Measure epistemic uncertainty | 258 |
| Head 4 | Calibration | Assist temperature scaling | 258 |
| **Total** | - | - | **1,032** |

### Ensemble Combination Strategy

#### Option 1: Simple Averaging (Baseline)
final_pred = mean([head1, head2, head3, head4])
ensemble_agree = std([head1, head2, head3, head4])

text
- Pros: Simple, interpretable
- Cons: All heads weighted equally

#### Option 2: Attention-Based Gating (Recommended)
weights = softmax(Dense(4)(features))
final_pred = sum([w_i * head_i for i in 1:4])
epistemic_var = sum([w_i * (head_i - final_pred)² for i in 1:4])

text
- Pros: Learned weighting, dynamic importance
- Cons: Additional parameters

#### Option 3: Confidence Weighting (Phase 5 Tuning)
conf_weights = [conf_1, conf_2, conf_3, conf_4]
final_pred = sum([conf_i * head_i]) / sum(conf_i)

text
- Pros: Adaptive to prediction quality
- Cons: Circular (confidence depends on itself)

---

## 4. OUTPUT LOGGING SCHEMA

### Prediction Log Entry

{
"timestamp": "2025-11-07T20:15:30.123Z",
"sample_id": "SQL_12345",
"input": {
"query": "SELECT * FROM users WHERE id=1",
"query_hash": "abc123def456"
},
"output": {
"prediction": 0,
"probability": [0.92, 0.08],
"confidence": 0.92,
"temperature": 1.0
},
"uncertainty": {
"predictive_variance": 0.034,
"entropy": 0.198,
"epistemic": 0.025,
"aleatoric": 0.009
},
"multi_head": {
"heads": ,
"agreement_score": 1.0,
"diversity_score": 0.0
},
"calibration": {
"confidence_bin": "0.9-1.0",
"recommendation": "ACCEPT",
"rejection_reason": null
},
"metadata": {
"model_version": "phase4_day47_v1.0",
"inference_time_ms": 12.5,
"batch_size": 1
}
}

text

---

## 5. CALIBRATION METRICS

### Reliability Diagram
- X-axis: Mean predicted confidence
- Y-axis: True positive rate (actual accuracy)
- Perfect calibration: 45° diagonal line

### Expected Calibration Error (ECE)
ECE = Σ |P(confidence) - accuracy| × bin_size

text

### Maximum Calibration Error (MCE)
MCE = max |P(confidence) - accuracy|

text

### Brier Score
BS = mean((predicted_prob - ground_truth)²)

text

---

## 6. PHASE 5 INTEGRATION POINTS

### Training Loss
L_total = L_classification + L_calibration + L_multi_head

L_classification = cross_entropy(final_pred, target)
L_calibration = MSE(confidence, accuracy_on_batch)
L_multi_head = KL(head_i, final_pred) for all heads

text

### Validation Metrics
- Accuracy
- Confidence calibration
- Ensemble agreement
- Epistemic/aleatoric balance

---

## 7. INFERENCE WORKFLOW

1. **Forward Pass:** 256-dim features through 4 heads
2. **Head Outputs:** [pred_1, pred_2, pred_3, pred_4]
3. **Ensemble Combination:** Weighted average + confidence
4. **Uncertainty Quantification:** Epistemic + aleatoric
5. **Temperature Scaling:** Calibrate confidence
6. **Output Generation:** Structured JSON with all metrics
7. **Logging:** Save to database/file for analysis

