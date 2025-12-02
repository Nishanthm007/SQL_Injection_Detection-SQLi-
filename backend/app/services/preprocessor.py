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
        return np.zeros(128, dtype=np.float32)

    # ---------------------------------------------------------
    def _extract_struct_features(self, query):
        return np.zeros(32, dtype=np.float32)

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
