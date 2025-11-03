# Embedding Specification Document

**Version:** v1.0  
**Date:** October 30, 2025  
**Status:** Prototype Complete

---

## 1. Overview

This document specifies the embedding approaches designed and tested for SQL injection detection in Phase 3B. We evaluated three embedding strategies and provide detailed specifications for each.

---

## 2. Embedding Approaches

### 2.1 Option A: Token-Level Embeddings (Word2Vec)

**Status:** ✅ **IMPLEMENTED & TESTED**

**Architecture:**
- **Algorithm**: Word2Vec Skip-gram
- **Dimensions**: 64
- **Window Size**: 5
- **Min Count**: 2
- **Epochs**: 10
- **Vocabulary**: 18,397 unique tokens

**Pooling Strategy:**
- **Method**: Mean pooling
- **Description**: Average token embeddings to create query-level representation

**Implementation:**
model = Word2Vec(
sentences=tokenized_queries,
vector_size=64,
window=5,
min_count=2,
workers=4,
epochs=10,
sg=1 # Skip-gram
)

text

**Results:**
- ✅ Clustering validation: **98% accuracy**
- ✅ Malicious query variants cluster together
- ✅ Fast training (~30 seconds on 10K queries)
- ✅ Fast inference (<1ms per query)

**Use Cases:**
- Baseline feature extraction
- Real-time detection (low latency)
- Ensemble with other models

---

### 2.2 Option B: Contextual Embeddings (Transformer)

**Status:** 📋 **SPECIFIED (Not Implemented)**

**Recommended Model:**
- **Primary**: CodeBERT or GraphCodeBERT
- **Alternative**: DistilBERT (lightweight)
- **SQL-Specific**: SQLCoder (if available)

**Architecture:**
- **Dimensions**: 256 (768 for full BERT)
- **Layers**: 6-12 transformer layers
- **Attention Heads**: 8-12
- **Max Sequence Length**: 512 tokens

**Pooling Strategies:**
1. **[CLS] token**: Use the CLS token embedding
2. **Mean pooling**: Average all token embeddings
3. **Attention pooling**: Weighted average with learned attention

**Training Strategy:**
Load pre-trained CodeBERT

Add classification head

Fine-tune on SQL injection dataset

Use mixed precision (FP16) for efficiency

text

**Expected Benefits:**
- Context-aware representations
- Better semantic understanding
- Higher accuracy (estimated 95%+)

**Challenges:**
- Slower inference (50-100ms per query)
- Higher memory (2-4GB GPU)
- More complex training

---

### 2.3 Option C: Character-CNN Embeddings

**Status:** 📋 **SPECIFIED (Not Implemented)**

**Architecture:**
Input: Character sequence (max length 512)
↓
Character Embedding (64-dim)
↓
Conv1D layers (3-5 filters)

Kernel sizes: 3, 4, 5

Filters: 128 per kernel
↓
MaxPooling over time
↓
Concatenate (128 x 3 = 384-dim)
↓
Dense layer (128-dim)
↓
Output: Query embedding

text

**Parameters:**
- **Embedding Dim**: 64 per character
- **Conv Filters**: 128 per kernel size
- **Kernel Sizes**: [3, 4, 5]
- **Final Dim**: 128
- **Activation**: ReLU
- **Dropout**: 0.3

**Advantages:**
- No vocabulary needed
- Handles obfuscation naturally
- Captures character-level patterns
- Good for encoded attacks

**Implementation Priority:**
- High for obfuscation detection
- Medium for general SQLi detection

---

## 3. Validation Results

### 3.1 Nearest Neighbor Clustering (Option A)

**Test Setup:**
- 5 malicious seed queries
- Top 10 neighbors per seed
- Total: 50 nearest neighbors

**Results:**
| Metric | Value |
|--------|-------|
| Malicious Neighbors | 49 / 50 (98%) |
| Benign Neighbors | 1 / 50 (2%) |
| **Status** | ✅ **PASS** |

**Qualitative Analysis:**
- UNION-based attacks cluster tightly (>97% similarity)
- OR-based attacks show good clustering (>90% similarity)
- Obfuscated variants correctly identified

### 3.2 Sample Clustering Examples

**Seed: `1' UNION SELECT NULL--`**

Top neighbors (all malicious):
1. `1' union all select null,null,null#` (sim: 0.977)
2. `1' union all select null--` (sim: 0.976)
3. `1%' ) union all select null,null,null,...` (sim: 0.975)

**Seed: `' OR '1'='1`**

Top neighbors (all malicious):
1. Similar OR-based attacks
2. Boolean-based blind SQLi
3. Obfuscated variants

✅ **Clustering Quality: Excellent**

---

## 4. Storage Format

### 4.1 HDF5 Format (Recommended)

**File**: `embeddings_train_v1.h5`

**Structure:**
embeddings_train_v1.h5/
├── embeddings (dataset) # Shape: (n_samples, embedding_dim)
├── sample_ids (dataset) # Sample IDs for indexing
└── attributes (metadata)
├── dimensions: 64
├── method: 'Word2Vec'
├── n_samples: 10000
├── vocabulary_size: 18397
└── pooling: 'mean'

text

**Advantages:**
- Efficient compression
- Fast random access
- Metadata storage
- Industry standard

### 4.2 NumPy Format (Alternative)

**Files:**
- `embeddings.npy`: Embedding matrix
- `sample_ids.npy`: Sample ID array
- `metadata.json`: Metadata dictionary

**Use Case**: Simpler workflows, smaller datasets

---

## 5. Reproducibility

### 5.1 Reproducible Mapping

**Sample ID Format**: `train_XXXXXX` (6-digit index)

**Mapping File**: `sample_id_mapping.json`
{
"sample_ids": ["train_000123", "train_004567", ...],
"indices": [0, 1, 2, ...],
"n_samples": 10000
}

text

### 5.2 Model Checkpoints

**Word2Vec Model**: `word2vec_model.bin`
- Can be loaded for inference
- Preserves vocabulary
- Reproducible embeddings

---

## 6. Recommendations

### 6.1 For Production

**Primary Model:**
- Option B (Contextual Embeddings)
- CodeBERT or DistilBERT
- 256-dim embeddings
- Mean pooling

**Fallback Model:**
- Option A (Token Embeddings)
- Word2Vec 64-dim
- For low-latency scenarios

### 6.2 For Research

**Hybrid Approach:**
- Combine Option A (tokens) + Option C (char-CNN)
- Concatenate embeddings
- Train ensemble classifier

### 6.3 For Obfuscation Detection

**Specialized Model:**
- Option C (Character-CNN)
- Focus on encoded attacks
- Combine with encoding detection features

---

## 7. Implementation Timeline

| Phase | Task | Status |
|-------|------|--------|
| Phase 1 | Design specification | ✅ Complete |
| Phase 2 | Prototype Option A | ✅ Complete |
| Phase 3 | Implement Option B | 📋 Planned |
| Phase 4 | Implement Option C | 📋 Planned |
| Phase 5 | Ensemble model | 📋 Planned |

---

## 8. Performance Metrics

### 8.1 Option A (Tested)

| Metric | Value |
|--------|-------|
| Training Time | ~30 seconds (10K queries) |
| Inference Time | <1ms per query |
| Memory | ~50 MB (model + embeddings) |
| Clustering | 98% accuracy |

### 8.2 Option B (Estimated)

| Metric | Estimated Value |
|--------|-----------------|
| Training Time | 2-4 hours (full dataset) |
| Inference Time | 50-100ms per query |
| Memory | 2-4 GB GPU |
| Accuracy | 95%+ (expected) |

---

## 9. Files Generated

| File | Size | Description |
|------|------|-------------|
| `embeddings_train_v1.h5` | ~2.5 MB | HDF5 embeddings |
| `word2vec_model.bin` | ~9 MB | Word2Vec model |
| `sample_id_mapping.json` | ~200 KB | ID mapping |
| `embedding_spec.md` | This document | Specification |

---

**Document Status:** COMPLETE  
**Last Updated:** 2025-10-30 22:18 IST
