import re
import numpy as np

class CNNPreprocessor:
    def __init__(self, vocab, word_types, max_len=150):
        self.vocab = vocab
        self.word_types = word_types
        self.max_len = max_len

    # ---------------------------------------------------------
    # TOKENIZER — MUST MATCH TRAINING NOTEBOOK EXACTLY
    # ---------------------------------------------------------
    def _tokenize_query(self, query):
        """
        Splits query into tokens exactly like training:
        - lowercase
        - words + punctuation
        - regex identical to model training version
        """
        return re.findall(r'\w+|[^\w\s]', query.lower())

    # ---------------------------------------------------------
    # WORD TOKEN INDICES (OOV = 0, PAD = 0)
    # ---------------------------------------------------------
    def _tokens_to_indices(self, tokens):
        indices = []

        for t in tokens:
            if t in self.vocab:
                indices.append(self.vocab[t])
            else:
                indices.append(0)   # PAD / OOV = 0

        # TRUNCATE
        indices = indices[:self.max_len]

        # PAD
        while len(indices) < self.max_len:
            indices.append(0)

        return indices

    # ---------------------------------------------------------
    # WORD TYPE INDICES
    # ---------------------------------------------------------
    def _types_to_indices(self, tokens):
        type_ids = []

        for t in tokens:
            if t in self.word_types:
                type_ids.append(self.word_types[t])
            else:
                type_ids.append(0)

        # TRUNCATE
        type_ids = type_ids[:self.max_len]

        # PAD
        while len(type_ids) < self.max_len:
            type_ids.append(0)

        return type_ids

    # ---------------------------------------------------------
    # CHARACTER FEATURES (PLACEHOLDER 128 floats)
    # ---------------------------------------------------------
    def _extract_char_features(self, query):
        """Extract character-level statistical features"""
        features = np.zeros(128, dtype=np.float32)
        
        if not query:
            return features
            
        # Basic stats
        features[0] = len(query)
        features[1] = query.count(' ')
        features[2] = query.count(';')
        features[3] = query.count(',')
        features[4] = query.count('(')
        features[5] = query.count(')')
        features[6] = query.count('\'')
        features[7] = query.count('"')
        features[8] = query.count('-')
        features[9] = query.count('=')
        
        # SQL keywords count
        query_upper = query.upper()
        features[10] = query_upper.count('SELECT')
        features[11] = query_upper.count('FROM')
        features[12] = query_upper.count('WHERE')
        features[13] = query_upper.count('UNION')
        features[14] = query_upper.count('OR')
        features[15] = query_upper.count('AND')
        features[16] = query_upper.count('DROP')
        features[17] = query_upper.count('DELETE')
        features[18] = query_upper.count('INSERT')
        features[19] = query_upper.count('UPDATE')
        
        # Special patterns
        features[20] = 1 if '--' in query else 0
        features[21] = 1 if '/*' in query else 0
        features[22] = 1 if '*/' in query else 0
        features[23] = 1 if '||' in query else 0
        features[24] = query.count('1=1')
        features[25] = query.count('OR 1')
        
        # Character type ratios
        total_chars = len(query)
        if total_chars > 0:
            features[30] = sum(c.isdigit() for c in query) / total_chars
            features[31] = sum(c.isalpha() for c in query) / total_chars
            features[32] = sum(c in '!@#$%^&*()' for c in query) / total_chars
            
        return features

    # ---------------------------------------------------------
    # STRUCTURAL FEATURES (PLACEHOLDER 32 floats)
    # ---------------------------------------------------------
    def _extract_struct_features(self, query):
        """Extract structural and syntactic features"""
        features = np.zeros(32, dtype=np.float32)
        
        if not query:
            return features
            
        query_upper = query.upper()
        
        # Clause presence
        features[0] = 1 if 'SELECT' in query_upper else 0
        features[1] = 1 if 'FROM' in query_upper else 0
        features[2] = 1 if 'WHERE' in query_upper else 0
        features[3] = 1 if 'GROUP BY' in query_upper else 0
        features[4] = 1 if 'ORDER BY' in query_upper else 0
        features[5] = 1 if 'HAVING' in query_upper else 0
        features[6] = 1 if 'LIMIT' in query_upper else 0
        features[7] = 1 if 'UNION' in query_upper else 0
        
        # Suspicious patterns
        features[10] = 1 if 'SLEEP(' in query_upper else 0
        features[11] = 1 if 'BENCHMARK(' in query_upper else 0
        features[12] = 1 if 'WAITFOR' in query_upper else 0
        features[13] = 1 if 'EXEC(' in query_upper or 'EXECUTE(' in query_upper else 0
        features[14] = 1 if 'CONCAT(' in query_upper else 0
        
        # Comment patterns
        features[15] = 1 if '--' in query else 0
        features[16] = 1 if '/*' in query else 0
        features[17] = 1 if '#' in query else 0
        
        # Quote balance (suspicious if imbalanced)
        single_quotes = query.count("'")
        double_quotes = query.count('"')
        features[20] = single_quotes
        features[21] = double_quotes
        features[22] = 1 if single_quotes % 2 != 0 else 0  # Imbalanced single quotes
        features[23] = 1 if double_quotes % 2 != 0 else 0  # Imbalanced double quotes
        
        # Parentheses balance
        open_paren = query.count('(')
        close_paren = query.count(')')
        features[24] = open_paren
        features[25] = close_paren
        features[26] = 1 if open_paren != close_paren else 0  # Imbalanced
        
        return features

    # ---------------------------------------------------------
    # MAIN PREPROCESS FUNCTION
    # ---------------------------------------------------------
    def preprocess(self, query):
        tokens = self._tokenize_query(query)

        word_indices = self._tokens_to_indices(tokens)
        type_indices = self._types_to_indices(tokens)

        return {
            "word_tokens": np.array([word_indices], dtype=np.int32),
            "word_types": np.array([type_indices], dtype=np.int32),
            "char_features": np.array([self._extract_char_features(query)], dtype=np.float32),
            "struct_features": np.array([self._extract_struct_features(query)], dtype=np.float32)
        }
