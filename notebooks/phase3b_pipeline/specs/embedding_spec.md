# Embedding Specification

**Version:** v1.0  
**Date:** October 22, 2025  
**Phase:** 3B - Robust Text Processing Pipeline  
**Owner:** ML Engineering & NLP Team

---

## 1. Overview

This specification defines embedding strategies for converting SQL queries into dense vector representations. Three complementary approaches are implemented to capture different aspects of SQL injection patterns.

---

## 2. Embedding Approaches

### 2.1 Option A: Character-CNN Embeddings (Lightweight)

**Purpose:** Capture fine-grained obfuscation patterns for CNN-based detection

**Architecture:**
Input: Character sequence (1024 chars)
↓
Char Embedding Layer (256 vocab → 64 dim)
↓
Conv1D Layers:

128 filters, kernel=3

256 filters, kernel=5

512 filters, kernel=7
↓
Global Max Pooling
↓
Dense Layer (256 dim)
↓
Output: 256-dim query embedding

text

**Training:**
- Supervised on augmented training set
- Binary cross-entropy loss + contrastive learning
- 10 epochs, early stopping (patience=3)
- Batch size: 128
- Learning rate: 1e-3 with cosine decay

**Advantages:**
- Fast inference (<1ms per query)
- Small model size (~5MB)
- Robust to character-level obfuscation
- No external dependencies

**Output:** 256-dimensional vector per query

---

### 2.2 Option B: Token Embeddings (FastText-style)

**Purpose:** Semantic similarity and subword robustness

**Configuration:**
- Algorithm: Skip-gram with negative sampling
- Dimensions: 300
- Window size: 5
- Min count: 3
- Character n-grams: 3-6 (for OOV handling)
- Epochs: 20

**Vocabulary:**
- SQL keywords: 500 tokens
- Identifiers: Top 50K from training
- Subword units: Character n-grams

**Training Corpus:**
- Phase 3A training queries (133K)
- Additional SQL corpora for pretraining (optional)

**Pooling Strategies:**
- Mean pooling: Average of all token embeddings
- Max pooling: Element-wise max
- Attention pooling: Learned attention weights

**Advantages:**
- Handles OOV via subword
- Interpretable token similarities
- Moderate training cost

**Output:** 
- Token-level: (seq_len, 300)
- Query-level: (300,) via pooling

---

### 2.3 Option C: CodeBERT Contextual Embeddings (Production)

**Purpose:** Deep semantic understanding with context awareness

**Base Model:** microsoft/codebert-base or microsoft/graphcodebert-base

**Architecture:**
- Transformer: 12 layers, 768 hidden dim
- Attention heads: 12
- Parameters: 125M
- Max sequence: 512 tokens

**Fine-tuning Strategy:**

**Phase 1 - Masked Language Modeling (MLM):**
- Mask 15% of tokens randomly
- Predict masked tokens
- 3 epochs on augmented corpus
- Learning rate: 2e-5

**Phase 2 - Binary Classification:**
- Add classification head on [CLS] token
- Train on SQL injection detection task
- 5 epochs with early stopping
- Learning rate: 3e-5
- Warmup steps: 500

**Data Augmentation During Fine-tuning:**
- Random token masking (10%)
- Synonym replacement for identifiers
- Structural perturbations (swap WHERE clauses)

**Pooling Options:**
[CLS] token (recommended)
cls_embedding = output.last_hidden_state[:, 0, :]

Mean pooling
mean_embedding = output.last_hidden_state.mean(dim=1)

Attention pooling
attention_weights = model.attention_pooler(output.last_hidden_state)
weighted_embedding = (output.last_hidden_state * attention_weights).sum(dim=1)

text

**Advantages:**
- Best semantic understanding
- Context-aware representations
- State-of-the-art on code tasks
- Pretrained on large code corpus

**Disadvantages:**
- Slower inference (10-50ms per query)
- Large model size (500MB)
- Requires GPU for training

**Output:**
- Token-level: (seq_len, 768)
- Query-level: (768,) via [CLS] or pooling

---

## 3. Recommended Strategy

**Development Phase:**
Implement Option A (Char-CNN) + Option C (CodeBERT) for comparison

**Production Deployment:**
- Fast path: Char-CNN embeddings for real-time screening
- Accurate path: CodeBERT for detailed analysis
- Ensemble: Combine both for final decision

---

## 4. Storage Format

### 4.1 HDF5 Structure

embeddings_train_v1.h5
├── /metadata
│ ├── model_version: "v1.0"
│ ├── creation_date: "2025-10-22"
│ ├── sample_count: 133734
│
├── /char_cnn_256
│ ├── /query_level (133734, 256) float32
│ └── /sample_ids (133734,) string
│
├── /codebert_768
│ ├── /query_level (133734, 768) float32
│ ├── /token_level (133734, 150, 768) float32
│ └── /sample_ids (133734,) string
│
└── /fasttext_300 (optional)
├── /query_level (133734, 300) float32
└── /sample_ids (133734,) string

text

### 4.2 File Naming Convention

embeddings_{split}_{model}_v{version}.h5

Examples:

embeddings_train_char_cnn_v1.h5

embeddings_train_codebert_v1.h5

embeddings_val_char_cnn_v1.h5

text

---

## 5. Performance Requirements

### 5.1 Inference Speed

| Model | Batch Size | Throughput | Latency (single) |
|-------|------------|------------|------------------|
| Char-CNN | 512 | 5000 qps | <1ms |
| FastText | 1024 | 3000 qps | <1ms |
| CodeBERT (CPU) | 32 | 50 qps | 20ms |
| CodeBERT (GPU) | 128 | 500 qps | 2ms |

### 5.2 Storage Requirements

| Dataset | Model | Compressed Size | Uncompressed |
|---------|-------|-----------------|--------------|
| Train (134K) | Char-CNN | 32 MB | 128 MB |
| Train (134K) | CodeBERT (query) | 390 MB | 780 MB |
| Train (134K) | CodeBERT (token) | 5.8 GB | 11.6 GB |

**Recommendation:** Store token-level embeddings on-demand or use memory-mapped files

---

## 6. Quality Metrics

### 6.1 Embedding Quality

**Intrinsic Metrics:**
- Cosine similarity between variants: >0.85
- Distance between benign/malicious: >0.3
- Clustering silhouette score: >0.4

**Extrinsic Metrics:**
- Classification accuracy using embeddings as features
- Nearest neighbor precision: >90% same-class in top-5

### 6.2 Validation Tests

1. **Variant Clustering:** Augmented queries cluster with originals
2. **Semantic Similarity:** Similar SQL patterns have high cosine similarity
3. **Injection Discrimination:** Malicious patterns separate from benign

---

## 7. Implementation Checklist

- [ ] Implement Char-CNN architecture
- [ ] Train Char-CNN on augmented dataset
- [ ] Download CodeBERT pretrained model
- [ ] Fine-tune CodeBERT with MLM
- [ ] Fine-tune CodeBERT for classification
- [ ] Implement embedding extraction pipeline
- [ ] Create HDF5 storage with compression
- [ ] Generate embeddings for train/val/test
- [ ] Validate embedding quality metrics
- [ ] Benchmark inference speed
- [ ] Document model hyperparameters

---

## 8. Output Files

phase3b_pipeline/data/embeddings/
├── models/
│ ├── char_cnn_v1.pt
│ ├── codebert_finetuned_v1/
│ └── model_configs.json
│
├── embeddings/
│ ├── train_char_cnn_v1.h5
│ ├── train_codebert_v1.h5
│ ├── val_char_cnn_v1.h5
│ ├── val_codebert_v1.h5
│ ├── test_char_cnn_v1.h5
│ └── test_codebert_v1.h5
│
└── validation/
├── embedding_quality_report_v1.pdf
└── similarity_analysis_v1.csv

text

---

## 9. Version History

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| v1.0 | 2025-10-22 | Initial specification | Phase 3B Team |

---

**Document Status:** APPROVED  
**Next Review Date:** 2025-11-22
