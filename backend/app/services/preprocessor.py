import re
import json
import numpy as np
from pathlib import Path

class CNNPreprocessor:
    def __init__(self, vocab: dict, word_types: dict, max_len=150):
        self.vocab = vocab
        self.word_types = word_types
        self.max_len = max_len

    # ---------------------------------------------------------
    def _tokenize_query(self, query):
        return re.findall(r'\w+|[^\w\s]', query.lower())

    # ---------------------------------------------------------
    def _tokens_to_indices(self, tokens):
        indices = [(self.vocab.get(t, 0)) for t in tokens]
        indices = indices[:self.max_len]
        while len(indices) < self.max_len:
            indices.append(0)
        return indices

    # ---------------------------------------------------------
    def _types_to_indices(self, tokens):
        type_ids = [(self.word_types.get(t, 0)) for t in tokens]
        type_ids = type_ids[:self.max_len]
        while len(type_ids) < self.max_len:
            type_ids.append(0)
        return type_ids

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


# -------------------------------------------------------------
# Singleton Loader
# -------------------------------------------------------------
_preprocessor = None

def get_preprocessor(vocab_path: str = None, wordtype_path: str = None):
    """
    Singleton loader for CNNPreprocessor.
    By default loads paths from config.settings (VOCAB_PATH, WORD_TYPES_PATH).
    Optional arguments allow overrides for testing.
    """
    global _preprocessor
    if _preprocessor is None:
        # Lazily import settings to avoid import cycles in different run contexts.
        try:
            # When running scripts directly (python preprocessor.py)
            from config import settings
        except Exception:
            # When running as a package (uvicorn app.main:app)
            from app.core.config import settings

        # Allow override for tests; otherwise use settings defaults.
        vocab_path = Path(vocab_path) if vocab_path else Path(settings.VOCAB_PATH)
        wordtype_path = Path(wordtype_path) if wordtype_path else Path(settings.WORD_TYPES_PATH)

        print("[PREPROCESSOR] Loading vocab & type vocab:")
        print("  - Vocab:", vocab_path)
        print("  - Types:", wordtype_path)

        # Fail early with a readable error if files are missing
        if not vocab_path.exists():
            raise FileNotFoundError(f"Vocab file not found at: {vocab_path}")
        if not wordtype_path.exists():
            raise FileNotFoundError(f"Word types file not found at: {wordtype_path}")

        with open(vocab_path, "r", encoding="utf-8") as vf:
            vocab = json.load(vf)
        with open(wordtype_path, "r", encoding="utf-8") as wt:
            word_types = json.load(wt)

        _preprocessor = CNNPreprocessor(vocab, word_types)

    return _preprocessor
