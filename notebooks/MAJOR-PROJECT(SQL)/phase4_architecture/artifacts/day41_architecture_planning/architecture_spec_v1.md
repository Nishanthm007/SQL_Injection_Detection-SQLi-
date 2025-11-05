# Phase 4 Day 41: Architecture Specification Document
**Version:** 1.0  
**Date:** 2025-11-05 22:56:32  
**Status:** APPROVED

---

## Executive Summary

This document specifies the multi-branch CNN architecture for SQL Injection Detection System (SIDS) Phase 4. The design addresses three critical objectives:

1. **Balanced Multi-Branch Learning**: Three input streams (character, word, structural) contribute equally to predictions
2. **Regularization-First Design**: Dropout, L2, and batch normalization prevent overfitting
3. **Uncertainty Awareness**: Multi-head classification with confidence calibration for reliable predictions

---

## Architecture Overview

### Design Principles

- **No Data Leakage**: Architecture designed using Phase 3B training data only (133,734 samples)
- **Balanced Contributions**: All three branches output 128-dimensional vectors before fusion
- **Aggressive Regularization**: Character branch (dropout 0.5), other branches (dropout 0.3)
- **Uncertainty Quantification**: Three parallel classifier heads provide ensemble voting and confidence calibration

---

## Branch 1: Character-Level Detection

### Purpose
Fine-grained obfuscation and encoding pattern detection through character sequences.

### Input Specification
- **Source**: `train_char_tokenized.parquet`
- **Shape**: `[batch_size, 1024]`
- **Type**: Integer-encoded character sequences
- **Vocabulary Size**: 256 (ASCII + special)

### Layer Architecture

| Layer | Type | Parameters | Output Shape | Regularization |
|-------|------|------------|--------------|----------------|
| char_embedding | Embedding | vocab=256, dim=32 | (batch, 1024, 32) | None |
| char_conv_block_1 | Conv1D | filters=64, kernel=3 | (batch, 1024, 64) | L2=0.01 |
| char_batch_norm_1 | BatchNormalization | - | (batch, 1024, 64) | - |
| char_conv_block_2 | Conv1D | filters=64, kernel=5 | (batch, 1024, 64) | L2=0.01 |
| char_batch_norm_2 | BatchNormalization | - | (batch, 1024, 64) | - |
| char_conv_block_3 | Conv1D | filters=64, kernel=7 | (batch, 1024, 64) | L2=0.01 |
| char_batch_norm_3 | BatchNormalization | - | (batch, 1024, 64) | - |
| char_global_maxpool | GlobalMaxPooling1D | - | (batch, 64) | - |
| char_dense_1 | Dense | units=256, relu | (batch, 256) | L2=0.01 |
| char_dropout | Dropout | rate=0.5 | (batch, 256) | Dropout |
| char_dense_2 | Dense | units=128, relu | (batch, 128) | L2=0.01 |

### Output
- **Shape**: `[batch_size, 128]`
- **Interpretation**: Character-level feature vector capturing obfuscation patterns

### Regularization Strategy
- **Dropout**: 0.5 (highest among branches due to potential overfitting)
- **L2 Regularization**: 0.01 on all Conv1D and Dense layers
- **Batch Normalization**: After each convolutional block

---

## Branch 2: Word-Level Semantic Understanding

### Purpose
Contextual understanding through token sequences and token type information.

### Input Specification
- **Source**: `train_word_tokenized_raw.parquet`
- **Shape**: `[batch_size, 150]` (tokens) + `[batch_size, 150]` (token types)
- **Type**: Integer-encoded word tokens with corresponding token type IDs
- **Vocabulary Size**: 5000 (words), 10 (token types)

### Layer Architecture

| Layer | Type | Parameters | Output Shape | Regularization |
|-------|------|------------|--------------|----------------|
| word_embedding | Embedding | vocab=5000, dim=100 | (batch, 150, 100) | None |
| word_token_type_embedding | Embedding | vocab=10, dim=16 | (batch, 150, 16) | None |
| word_concat_embeddings | Concatenate | axis=-1 | (batch, 150, 116) | - |
| word_conv_block_1 | Conv1D | filters=64, kernel=3 | (batch, 150, 64) | L2=0.01 |
| word_batch_norm_1 | BatchNormalization | - | (batch, 150, 64) | - |
| word_conv_block_2 | Conv1D | filters=64, kernel=5 | (batch, 150, 64) | L2=0.01 |
| word_batch_norm_2 | BatchNormalization | - | (batch, 150, 64) | - |
| word_dropout_conv | Dropout | rate=0.3 | (batch, 150, 64) | Dropout |
| word_global_avgpool | GlobalAveragePooling1D | - | (batch, 64) | - |
| word_dense_1 | Dense | units=256, relu | (batch, 256) | L2=0.01 |
| word_dropout_dense | Dropout | rate=0.3 | (batch, 256) | Dropout |
| word_dense_2 | Dense | units=128, relu | (batch, 128) | L2=0.01 |

### Output
- **Shape**: `[batch_size, 128]`
- **Interpretation**: Word-level semantic feature vector

### Regularization Strategy
- **Dropout**: 0.3 (moderate regularization)
- **L2 Regularization**: 0.01 on all Conv1D and Dense layers
- **Batch Normalization**: After each convolutional block

---

## Branch 3: Structural Feature Extraction

### Purpose
High-level syntax tree, statistical, and semantic role features.

### Input Specification
- **Sources**:
  - `features_statistical_v1.parquet` (34 features)
  - `features_syntax_v1.parquet` (34 features)
  - `semantic_roles_v1.parquet` (36 features)
- **Shape**: `[batch_size, 104]`
- **Type**: Normalized numeric features

### Feature Categories
1. **Statistical Features (34)**: Entropy, character ratios, encoding patterns
2. **Syntax Features (34)**: AST depth, query structure, SQL keyword counts
3. **Semantic Roles (36)**: Token role assignments, query component presence

### Layer Architecture

| Layer | Type | Parameters | Output Shape | Regularization |
|-------|------|------------|--------------|----------------|
| struct_input | Input | shape=(104,) | (batch, 104) | - |
| struct_normalization | LayerNormalization | - | (batch, 104) | - |
| struct_dense_1 | Dense | units=256, relu | (batch, 256) | L2=0.01 |
| struct_batch_norm_1 | BatchNormalization | - | (batch, 256) | - |
| struct_dropout_1 | Dropout | rate=0.3 | (batch, 256) | Dropout |
| struct_dense_2 | Dense | units=256, relu | (batch, 256) | L2=0.01 |
| struct_batch_norm_2 | BatchNormalization | - | (batch, 256) | - |
| struct_dropout_2 | Dropout | rate=0.3 | (batch, 256) | Dropout |
| struct_dense_3 | Dense | units=128, relu | (batch, 128) | L2=0.01 |

### Output
- **Shape**: `[batch_size, 128]`
- **Interpretation**: Structural feature vector

### Regularization Strategy
- **Dropout**: 0.3 (moderate regularization)
- **L2 Regularization**: 0.01 on all Dense layers
- **Batch Normalization**: After each major dense block
- **Layer Normalization**: Input feature scaling

---

## Fusion Module: Multi-Branch Attention

### Purpose
Dynamically weight and combine the three branch outputs using attention mechanism.

### Input Specification
- **Branch 1 Output**: `[batch_size, 128]`
- **Branch 2 Output**: `[batch_size, 128]`
- **Branch 3 Output**: `[batch_size, 128]`

### Architecture

| Layer | Type | Parameters | Output Shape | Purpose |
|-------|------|------------|--------------|---------|
| branch_concatenate | Concatenate | axis=-1 | (batch, 384) | Combine branch outputs |
| attention_query_dense | Dense | units=64, relu | (batch, 64) | Attention query |
| attention_key_dense | Dense | units=64, relu | (batch, 64) | Attention key |
| attention_value_dense | Dense | units=128, relu | (batch, 128) | Attention value |
| attention_scores | MultiHeadAttention | heads=3, key_dim=64 | (batch, 128) | Branch weighting |
| fused_features | Dense | units=256, relu | (batch, 256) | Fused representation |
| fusion_dropout | Dropout | rate=0.3 | (batch, 256) | Regularization |

### Output
- **Shape**: `[batch_size, 256]`
- **Interpretation**: Attention-weighted fused feature vector

### Attention Mechanism
- **Strategy**: Multi-head attention (3 heads)
- **Purpose**: Learn dynamic importance of each branch per sample
- **Expected Behavior**: Equal weighting (~33% each) for balanced contributions

---

## Uncertainty Module: Multi-Head Classification

### Purpose
Provide reliable predictions with calibrated confidence scores through ensemble voting.

### Architecture

#### Parallel Classifier Heads (3 Independent Paths)

Each head:
**Head 0**: Classifier with independent weights  
**Head 1**: Classifier with independent weights  
**Head 2**: Classifier with independent weights

#### Ensemble & Calibration

| Layer | Type | Parameters | Output Shape | Purpose |
|-------|------|------------|--------------|---------|
| logits_average | Average | from 3 heads | (batch, 2) | Ensemble voting |
| softmax_output | Dense + Softmax | units=2 | (batch, 2) | Probabilities |
| temperature_scaling | TemperatureScaling | learnable=True | (batch, 2) | Confidence calibration |

### Output Specification

#### Primary Output
- **classification_logits**: `[batch_size, 2]`
  - Class 0: Benign query probability
  - Class 1: Malicious query probability

#### Auxiliary Outputs
- **confidence_score**: `[batch_size, 1]`
  - Range: [0.0, 1.0]
  - Interpretation: Calibrated confidence in prediction
  
- **predictive_variance**: `[batch_size, 1]`
  - Range: [0.0, 1.0]
  - Interpretation: Disagreement among the 3 classifier heads
  
- **epistemic_uncertainty**: `[batch_size, 1]`
  - Range: [0.0, 1.0]
  - Interpretation: Model's uncertainty (high = requires human review)

### Uncertainty Quantification Strategy
1. **Aleatoric Uncertainty**: Captured through softmax probabilities
2. **Epistemic Uncertainty**: Measured as variance across 3 head predictions
3. **Confidence Calibration**: Temperature scaling learned during training

---

## Regularization Summary

### Dropout Strategy
| Component | Dropout Rate | Justification |
|-----------|--------------|---------------|
| Character Branch | 0.5 | Highest risk of overfitting on char patterns |
| Word Branch | 0.3 | Moderate semantic complexity |
| Structural Branch | 0.3 | Engineered features, moderate dropout |
| Fusion Module | 0.3 | Post-concatenation regularization |
| Uncertainty Heads | 0.2 | Light regularization for ensemble diversity |

### L2 Regularization
- **Value**: 0.01 across all Conv1D and Dense layers
- **Purpose**: Weight smoothing and generalization
- **Scope**: All trainable weight matrices

### Batch Normalization
- **Applied To**: After each major convolutional or dense block
- **Purpose**: Gradient stabilization, faster convergence
- **Locations**: All three branches + structural branch

---

## Training Configuration (For Phase 5)

### Data Splits
- **Training**: Phase 3B data (133,734 samples)
- **Validation**: 15% holdout from training data
- **Evaluation**: Phase 3C data (36,149 samples) - LOCKED until Phase 5

### Optimizer Recommendations
- **Optimizer**: Adam with weight decay
- **Learning Rate**: 1e-4 (initial) with ReduceLROnPlateau
- **Batch Size**: 32 or 64 (depending on GPU memory)

### Loss Functions
- **Primary Loss**: Categorical Cross-Entropy
- **Auxiliary Loss**: Confidence calibration loss (Expected Calibration Error)
- **Total Loss**: Weighted combination

### Evaluation Metrics
- Precision, Recall, F1-Score (threshold = 0.5)
- ROC-AUC, PR-AUC
- Expected Calibration Error (ECE)
- False Positive Rate @ 95% TPR

---

## Acceptance Criteria - DAY 41

- [x] Architecture diagram created and visualized
- [x] All three input branches fully specified with dimensions
- [x] Fusion and attention mechanism defined
- [x] Uncertainty module with multi-head classification designed
- [x] Regularization strategy documented
- [x] Input/output dimensions mapped and verified
- [x] Zero data leakage confirmed (training data only)
- [x] Complete documentation generated

---

## Next Steps (Days 42-50)

- **Day 42**: Character branch implementation and validation
- **Day 43**: Word branch implementation and validation
- **Day 44**: Structural branch implementation and validation
- **Day 45**: Fusion and attention mechanism implementation
- **Day 46**: Regularization framework integration
- **Day 47**: Uncertainty module implementation
- **Day 48**: End-to-end integration testing
- **Day 49**: Architecture validation on training subset
- **Day 50**: Final documentation and Phase 5 handoff

---

**Document Status**: APPROVED FOR IMPLEMENTATION  
**Approval Date**: 2025-11-05  
**Next Milestone**: Day 42 - Character Branch Implementation
