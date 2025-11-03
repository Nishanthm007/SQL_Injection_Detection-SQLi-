# Statistical Anomaly Features Documentation

**Version:** v1.0  
**Date:** October 30, 2025  
**Status:** Production Ready

---

## 1. Overview

This document specifies the statistical anomaly features extracted for SQL injection detection in Phase 3B. These features capture entropy, character frequency distributions, encoding schemes, and anomaly patterns based on benign baseline statistics.

---

## 2. Feature Categories

### 2.1 Entropy Features

**Shannon Entropy**: Measures the randomness/information content of a query.

\[ H(X) = -\sum_{i} p(x_i) \log_2(p(x_i)) \]

| Feature | Type | Range | Description |
|---------|------|-------|-------------|
| `shannon_entropy` | float | [0, ∞) | Information entropy of character distribution |
| `shannon_entropy_zscore` | float | (-∞, ∞) | Z-score relative to benign baseline |

**Benign Baseline:**
- Mean: 4.0592
- Std: 0.7406
- Median: 4.1162

**Interpretation:**
- Higher entropy → more random/complex queries
- Lower entropy → repetitive patterns (common in SQLi)

### 2.2 Character Frequency Features

Character type distribution ratios:

| Feature | Type | Range | Description |
|---------|------|-------|-------------|
| `alphanumeric_ratio` | float | [0, 1] | Proportion of alphanumeric characters |
| `digit_ratio` | float | [0, 1] | Proportion of digit characters |
| `uppercase_ratio` | float | [0, 1] | Proportion of uppercase letters |
| `lowercase_ratio` | float | [0, 1] | Proportion of lowercase letters |
| `whitespace_ratio` | float | [0, 1] | Proportion of whitespace characters |
| `special_char_ratio` | float | [0, 1] | Proportion of special characters |
| `non_alphanumeric_ratio` | float | [0, 1] | Proportion of non-alphanumeric (1 - alphanumeric_ratio) |

**Benign Baseline Statistics:**

| Feature | Mean | Std | Min | Max |
|---------|------|-----|-----|-----|
| alphanumeric_ratio | 0.8013 | 0.0827 | 0.0 | 1.0 |
| digit_ratio | 0.0618 | 0.2044 | 0.0 | 1.0 |
| special_char_ratio | 0.0425 | 0.0407 | 0.0 | 0.75 |

### 2.3 Encoding Detection Features

Detect various encoding schemes used in SQLi attacks:

| Feature | Type | Description |
|---------|------|-------------|
| `has_url_encoding` | bool | 1 if %XX pattern detected |
| `has_hex_encoding` | bool | 1 if 0xXX pattern detected |
| `has_base64` | bool | 1 if base64-like pattern detected |
| `has_unicode_escape` | bool | 1 if \uXXXX pattern detected |
| `url_encoding_ratio` | float | Proportion of URL-encoded characters |
| `hex_encoding_ratio` | float | Proportion of hex-encoded characters |

**Detection Statistics (Full Dataset):**

| Encoding | Benign | Malicious | Total | Malicious % |
|----------|--------|-----------|-------|-------------|
| URL Encoding | 17 | 5,883 | 5,900 | 99.7% |
| Hex Encoding | 2 | 16,234 | 16,236 | 100.0% |
| Base64 | 590 | 25,474 | 26,064 | 97.7% |
| Unicode Escape | 0 | 2,998 | 2,998 | 100.0% |

**Key Insight:** Encoding is almost exclusively present in malicious queries.

### 2.4 Special Character Counts

Count specific characters frequently used in SQLi:

| Feature | Description |
|---------|-------------|
| `single_quote_count` | Count of ' characters |
| `double_quote_count` | Count of " characters |
| `backtick_count` | Count of ` characters |
| `semicolon_count` | Count of ; characters |
| `dash_count` | Count of - characters |
| `percent_count` | Count of % characters |
| `ampersand_count` | Count of & characters |
| `pipe_count` | Count of \| characters |
| `parenthesis_count` | Count of ( and ) characters |
| `bracket_count` | Count of [ and ] characters |

### 2.5 Query Metrics

Basic query characteristics:

| Feature | Type | Description |
|---------|------|-------------|
| `query_length` | int | Total character count |
| `unique_char_count` | int | Number of distinct characters |
| `unique_char_ratio` | float | unique_char_count / query_length |

---

## 3. Z-Score Normalization

### 3.1 Z-Score Calculation

For each feature, compute z-score relative to benign baseline:

\[ z = \frac{x - \mu_{benign}}{\sigma_{benign}} \]

Where:
- \(x\) = feature value
- \(\mu_{benign}\) = benign mean
- \(\sigma_{benign}\) = benign std

### 3.2 Z-Score Features

| Feature | Benign Mean | Benign Std |
|---------|-------------|------------|
| shannon_entropy_zscore | 0.0 | 1.0 |
| alphanumeric_ratio_zscore | 0.0 | 1.0 |
| digit_ratio_zscore | 0.0 | 1.0 |
| special_char_ratio_zscore | 0.0 | 1.0 |
| non_alphanumeric_ratio_zscore | 0.0 | 1.0 |
| unique_char_ratio_zscore | 0.0 | 1.0 |

**Validation:** All z-scores are finite with no NaN or Inf values.

---

## 4. Anomaly Detection Thresholds

### 4.1 Threshold Definition

Based on standard normal distribution:

| Threshold | Z-Score | Coverage | Description |
|-----------|---------|----------|-------------|
| Normal | \|z\| ≤ 2.0 | 95% | Within 2 standard deviations |
| Moderate Anomaly | \|z\| > 2.0 | ~5% | Beyond 2 standard deviations |
| Severe Anomaly | \|z\| > 3.0 | ~0.3% | Beyond 3 standard deviations |

### 4.2 Anomaly Statistics

Percentage of queries flagged as anomalies:

| Feature | Moderate (>2σ) | Severe (>3σ) |
|---------|----------------|--------------|
| shannon_entropy | 15.61% | 3.98% |
| alphanumeric_ratio | 27.47% | 10.33% |
| digit_ratio | 10.60% | 6.20% |
| special_char_ratio | 25.54% | 18.61% |
| non_alphanumeric_ratio | 27.47% | 10.33% |
| unique_char_ratio | 2.32% | 0.00% |

---

## 5. Discriminative Analysis

### 5.1 Label-wise Comparison

Mean values by label showing discriminative power:

| Feature | Benign | Malicious | Difference | Interpretation |
|---------|--------|-----------|------------|----------------|
| shannon_entropy | 4.0592 | 4.2015 | +0.1423 | Malicious slightly higher |
| alphanumeric_ratio | 0.8013 | 0.7303 | -0.0710 | Malicious lower (more symbols) |
| special_char_ratio | 0.0425 | 0.1403 | +0.0978 | Malicious 3.3x higher |
| has_url_encoding | 0.0003 | 0.0880 | +0.0877 | Malicious 293x higher |
| has_hex_encoding | 0.0000 | 0.2428 | +0.2428 | Malicious only |

### 5.2 Key Findings

**Malicious queries are characterized by:**
1. Lower alphanumeric ratio (more special characters)
2. Higher special character ratio (~3.3x)
3. Much higher encoding usage (293x for URL, ∞ for hex)
4. Slightly higher entropy (more randomness)

**Benign queries are characterized by:**
1. Higher alphanumeric ratio (cleaner text)
2. Lower special character usage
3. Minimal to no encoding
4. More consistent patterns

---

## 6. Implementation Details

### 6.1 Feature Extraction

extractor = StatisticalAnomalyExtractor()
features = extractor.extract_features(query)

text

**Output:** Dictionary with 27 base features

### 6.2 Z-Score Computation

z_score = (feature_value - baseline_mean) / baseline_std

text

**Requires:** Benign baseline statistics (loaded from `char_freq_baseline.json`)

---

## 7. Data Files

| File | Size | Records | Description |
|------|------|---------|-------------|
| `features_statistical_v1.parquet` | 10.66 MB | 133,734 | All statistical features + z-scores |
| `char_freq_baseline.json` | 1.80 KB | 8 features | Benign baseline statistics |

---

## 8. Validation Results

### 8.1 Data Quality

✅ **PASS** - No NaN values  
✅ **PASS** - No Inf values  
✅ **PASS** - All z-scores finite and interpretable  
✅ **PASS** - Benign baseline computed for 8 features  
✅ **PASS** - Anomaly thresholds documented  

### 8.2 Baseline Statistics

Benign baseline successfully computed:
- **Shannon entropy**: μ = 4.0592, σ = 0.7406
- **Alphanumeric ratio**: μ = 0.8013, σ = 0.0827
- **Special char ratio**: μ = 0.0425, σ = 0.0407

---

## 9. Usage Examples

### 9.1 Extract Features

query = "SELECT * FROM users WHERE id = 1"
features = extractor.extract_features(query)
print(features['shannon_entropy']) # 4.011
print(features['has_url_encoding']) # 0

text

### 9.2 Compute Z-Score

z_score = (features['shannon_entropy'] - 4.0592) / 0.7406
if abs(z_score) > 2.0:
print("Moderate anomaly detected")

text

---

## 10. Future Enhancements

1. **N-gram frequency analysis**: Compute bigram/trigram rarity scores
2. **Token rarity metrics**: Measure deviation from benign token distributions
3. **Time-series features**: Detect temporal anomalies
4. **Advanced encoding detection**: Detect double encoding, mixed encoding
5. **Context-aware baselines**: Separate baselines per source/context

---

**Document Status:** COMPLETE  
**Last Updated:** 2025-10-30 18:58 IST
