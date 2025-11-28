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
        # Zero vector – can be extended later
        return np.zeros(128, dtype=np.float32)

    # ---------------------------------------------------------
    # STRUCTURAL FEATURES (PLACEHOLDER 32 floats)
    # ---------------------------------------------------------
    def _extract_struct_features(self, query):
        return np.zeros(32, dtype=np.float32)

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
