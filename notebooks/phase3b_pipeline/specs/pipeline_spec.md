# Pipeline Orchestration Specification

**Version:** 1.0.0  
**Date:** October 30, 2025  
**Status:** Production Ready  
**Execution ID:** 20251030_223220

---

## 1. Overview

This document specifies the complete data processing pipeline for SQL injection detection in Phase 3B. The pipeline transforms raw SQL queries into multi-modal features suitable for machine learning classification.

---

## 2. Pipeline Architecture

### 2.1 Pipeline Flow Diagram

Raw Data (CSV)
↓
[Stage 1] Data Ingestion
↓
[Stage 2] Data Normalization
↓
├──→ [Stage 3] Character Tokenization → char_tokenized_v1.parquet
├──→ [Stage 4] Word Tokenization → word_tokenized_*.parquet
├──→ [Stage 5] SQL Parsing → ast_dumps_v1.parquet
↓
├──→ [Stage 6] Syntax Features → features_syntax_v1.parquet
├──→ [Stage 7] Semantic Roles → semantic_roles_v1.parquet
├──→ [Stage 8] Statistical Features → features_statistical_v1.parquet
└──→ [Stage 9] Embeddings → embeddings_train_v1.h5
↓
[Stage 10] Provenance Tracking → provenance_manifest_v1.csv

text

### 2.2 Pipeline Stages

| Stage | Name | Component | Version | Status |
|-------|------|-----------|---------|--------|
| 1 | Data Ingestion | pandas | - | ✅ Complete |
| 2 | Normalization | Custom | 1.0.0 | ✅ Complete |
| 3 | Char Tokenization | CharacterTokenizer | 1.0.0 | ✅ Complete |
| 4 | Word Tokenization | WordTokenizer | 1.0.0 | ✅ Complete |
| 5 | SQL Parsing | SQLParser (sqlparse) | 1.0.0 | ✅ Complete |
| 6 | Syntax Features | ASTFeatureExtractor | 1.0.0 | ✅ Complete |
| 7 | Semantic Roles | SemanticRoleLabeler | 1.0.0 | ✅ Complete |
| 8 | Statistical Features | StatisticalAnomalyExtractor | 1.0.0 | ✅ Complete |
| 9 | Embeddings | Word2VecEmbedder | 1.0.0 | ✅ Complete |
| 10 | Provenance | ProvenanceTracker | 1.0.0 | ✅ Complete |

---

## 3. Component Specifications

### 3.1 CharacterTokenizer v1.0.0
- **Vocabulary Size**: 260 characters
- **Max Length**: 500 characters
- **Padding**: post-padding
- **Unknown Token**: `<UNK>`
- **Output**: Integer sequences

### 3.2 WordTokenizer v1.0.0
- **Vocabulary Size**: 65,603 words
- **Max Length**: 100 tokens
- **Masking**: Enabled (15% mask rate)
- **Special Tokens**: `<PAD>`, `<UNK>`, `<MASK>`
- **Output**: Two variants (raw, masked)

### 3.3 SQLParser v1.0.0
- **Library**: sqlparse 0.4.4
- **Method**: AST extraction
- **Error Handling**: Graceful fallback
- **Output**: AST dumps + parse errors

### 3.4 ASTFeatureExtractor v1.0.0
- **Features**: 32 syntax features
- **Method**: Regex + pattern matching
- **Includes**: Keywords, operators, nesting depth
- **Output**: Numeric feature vectors

### 3.5 SemanticRoleLabeler v1.0.0
- **Roles**: 16 semantic roles
- **Method**: Pattern-based extraction
- **Coverage**: Mean 52.71%
- **Output**: Role presence/counts

### 3.6 StatisticalAnomalyExtractor v1.0.0
- **Features**: 33 statistical features
- **Baseline**: Benign-only baseline
- **Z-scores**: 6 normalized features
- **Output**: Stats + anomaly scores

### 3.7 Word2VecEmbedder v1.0.0
- **Dimensions**: 64
- **Algorithm**: Skip-gram
- **Window**: 5
- **Min Count**: 2
- **Pooling**: Mean pooling
- **Output**: Dense embeddings

---

## 4. Batching & Parallelism

### 4.1 Batching Strategy

| Stage | Batch Size | Workers | Memory/Batch | Caching |
|-------|------------|---------|--------------|---------|
| Char Tokenization | 5,000 | 4 | ~50 MB | No |
| Word Tokenization | 5,000 | 4 | ~100 MB | No |
| SQL Parsing | 1,000 | 4 | ~200 MB | Yes |
| Feature Extraction | 2,000 | 4 | ~150 MB | No |
| Embedding Generation | 1,000 | 1 | ~300 MB | Yes |

### 4.2 Caching Strategy

**Cached Components:**
1. **SQL Parsing**: Cache AST dumps
   - Location: `phase3b_pipeline/cache/ast_cache/`
   - Reason: Parsing is expensive
   
2. **Embeddings**: Cache computed embeddings
   - Location: `phase3b_pipeline/cache/embedding_cache/`
   - Reason: Model inference overhead

**Cache Invalidation:**
- Cache cleared when component version changes
- TTL: 7 days for development

### 4.3 Memory Management

**Total Pipeline Memory:**
- Peak memory: ~1.5 GB
- Average memory: ~800 MB
- Batch processing prevents OOM

**Optimization Strategies:**
- Lazy loading of vocabularies
- Streaming for large files
- Generator-based processing

---

## 5. Provenance Tracking

### 5.1 Provenance Metadata Schema

Each sample tracked with:
{
"execution_id": "20251030_223220",
"sample_id": "train_000000",
"stage": "char_tokenization",
"component": "CharacterTokenizer",
"component_version": "1.0.0",
"timestamp": "2025-10-30T22:32:20.265273",
"inputs": {...},
"outputs": {...},
"pipeline_version": "1.0.0"
}

text

### 5.2 Provenance Fields

| Field | Type | Description |
|-------|------|-------------|
| execution_id | string | Unique pipeline run ID |
| sample_id | string | Sample identifier |
| stage | string | Pipeline stage name |
| component | string | Component name |
| component_version | string | Component version |
| timestamp | datetime | Processing timestamp |
| inputs | json | Input metadata |
| outputs | json | Output metadata |
| pipeline_version | string | Pipeline version |

### 5.3 Provenance Storage

**Format**: CSV file  
**Location**: `phase3b_pipeline/data/provenance/provenance_manifest_v1.csv`  
**Retention**: Permanent (audit trail)

---

## 6. Reproducibility

### 6.1 Version Control

All components versioned semantically (MAJOR.MINOR.PATCH):
- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes

### 6.2 Deterministic Execution

**Random Seeds:**
- Tokenizer splits: seed=42
- Word2Vec training: seed=42
- Data sampling: seed=42

**Fixed Parameters:**
- All hyperparameters documented
- Configuration files versioned

### 6.3 Data Checksums

**Sample ID Format**: `train_XXXXXX` (6-digit zero-padded)

**File Checksums** (SHA256):
- Tracked in provenance manifest
- Validated on pipeline restart

---

## 7. Pipeline Outputs

### 7.1 Data Files

| File | Size | Records | Description |
|------|------|---------|-------------|
| char_tokenized_v1.parquet | 35.99 MB | 133,734 | Character sequences |
| word_tokenized_raw_v1.parquet | 43.57 MB | 133,734 | Word sequences |
| word_tokenized_masked_v1.parquet | 33.68 MB | 133,734 | Masked sequences |
| ast_dumps_v1.parquet | 1.08 MB | 2,359 | AST structures |
| features_syntax_v1.parquet | 2.04 MB | 133,734 | Syntax features |
| semantic_roles_v1.parquet | 2.35 MB | 133,734 | Role features |
| features_statistical_v1.parquet | 10.66 MB | 133,734 | Statistical features |
| embeddings_train_v1.h5 | 2.91 MB | 10,000 | Dense embeddings |
| provenance_manifest_v1.csv | ~6 KB | 30 | Provenance records |

**Total Data Generated**: ~142 MB

### 7.2 Feature Summary

| Feature Type | Count | Source |
|--------------|-------|--------|
| Syntax features | 32 | Stage 6 |
| Semantic roles | 38 | Stage 7 |
| Statistical features | 33 | Stage 8 |
| Embeddings | 64-dim | Stage 9 |
| **Total Features** | **167** | All stages |

---

## 8. Validation & Quality Assurance

### 8.1 Data Quality Checks

✅ **Passed Validations:**
- No NaN values in features
- No Inf values in features
- All z-scores finite
- Label distribution balanced (50/50)
- Embedding clustering: 98% accuracy

### 8.2 Pipeline Validation

✅ **End-to-End Tests:**
- All outputs generated
- File sizes within expected ranges
- Provenance records complete
- Sample IDs consistent across files

### 8.3 Performance Benchmarks

| Stage | Processing Time | Throughput |
|-------|----------------|------------|
| Char Tokenization | ~45 sec | 2,972 samples/sec |
| Word Tokenization | ~60 sec | 2,229 samples/sec |
| SQL Parsing | ~15 min | 148 samples/sec |
| Feature Extraction | ~90 sec | 1,486 samples/sec |
| Embedding Generation | ~30 sec | 333 samples/sec |
| **Total Pipeline** | **~20 min** | **111 samples/sec** |

---

## 9. Usage

### 9.1 Running the Pipeline

Initialize pipeline
pipeline = SQLInjectionPipeline(version='1.0.0')

Run full pipeline
pipeline.run(
input_data='train.csv',
output_dir='phase3b_pipeline/data/',
batch_size=5000,
num_workers=4
)

text

### 9.2 Loading Processed Data

Load features
syntax_features = pd.read_parquet('features_syntax_v1.parquet')
semantic_features = pd.read_parquet('semantic_roles_v1.parquet')
statistical_features = pd.read_parquet('features_statistical_v1.parquet')

Load embeddings
import h5py
with h5py.File('embeddings_train_v1.h5', 'r') as f:
embeddings = f['embeddings'][:]

text

---

## 10. Future Enhancements

### 10.1 Planned Improvements

1. **Distributed Processing**: Add Apache Spark support
2. **Streaming Pipeline**: Real-time processing capability
3. **Advanced Embeddings**: Implement Transformer-based (Option B)
4. **Model Registry**: MLflow integration
5. **Monitoring**: Add pipeline metrics dashboard

### 10.2 Scalability Considerations

**Current Capacity**: 150K samples/hour  
**Target Capacity**: 1M samples/hour  
**Bottleneck**: SQL Parsing stage

---

**Document Status:** COMPLETE  
**Last Updated:** 2025-10-30 22:32 IST  
**Pipeline Version:** 1.0.0
