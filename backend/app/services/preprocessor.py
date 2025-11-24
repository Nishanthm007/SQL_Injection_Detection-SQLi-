"""
CNN Preprocessing Pipeline - Extracted from Phase 5A
Implements character, word, and structural feature extraction
"""
import numpy as np
import pickle
import re
from pathlib import Path
from typing import Dict, List, Tuple

class CNNPreprocessor:
    """Phase 5A-compatible CNN preprocessor for production"""
    
    def __init__(self, vocab_path: Path):
        """Load vocabularies and configuration"""
        # Load vocab from Phase 5A artifacts
        with open(vocab_path, 'rb') as f:
            vocab_data = pickle.load(f)
        
        self.word_to_idx = vocab_data['vocab']
        self.type_to_idx = vocab_data['type_vocab']
        
        # Phase 5A dimensions (from your training)
        self.max_word_length = 150
        self.max_char_length = 1024
        self.structural_dim = 104
        
        print(f"[PREPROCESSOR] Loaded vocab: {len(self.word_to_idx)} words, {len(self.type_to_idx)} types")
    
    def preprocess(self, query: str) -> Dict[str, np.ndarray]:
        """
        Main preprocessing entry point.
        Returns dict with all CNN input features.
        """
        # Extract features
        X_word_tokens = self._extract_word_tokens(query)
        X_word_types = self._extract_word_types(query)
        X_char = self._extract_char_features(query)
        X_structural = self._extract_structural_features(query)
        
        return {
            'word_tokens': X_word_tokens,
            'word_types': X_word_types,
            'char_input': X_char,
            'structural_features': X_structural
        }
    
    def _tokenize_query(self, query: str) -> List[str]:
        """Tokenize query into words/symbols"""
        query = query.lower()
        # Split on whitespace and special chars, keeping operators/punctuation
        tokens = re.findall(r'\w+|[^\w\s]', query)
        return tokens
    
    def _extract_word_tokens(self, query: str) -> np.ndarray:
        """Extract word token indices (vocab-based encoding)"""
        tokens = self._tokenize_query(query)
        
        # Encode tokens using vocabulary
        encoded = []
        for token in tokens[:self.max_word_length]:
            idx = self.word_to_idx.get(token, self.word_to_idx.get('<UNK>', 1))
            encoded.append(idx)
        
        # Pad or truncate to max_word_length
        if len(encoded) < self.max_word_length:
            encoded += [0] * (self.max_word_length - len(encoded))
        else:
            encoded = encoded[:self.max_word_length]
        
        return np.array([encoded], dtype=np.int32)
    
    def _extract_word_types(self, query: str) -> np.ndarray:
        """Extract word type indices (keyword/identifier/operator/etc)"""
        tokens = self._tokenize_query(query)
        
        # SQL keywords (expanded set)
        SQL_KEYWORDS = {
            'select', 'from', 'where', 'and', 'or', 'not', 'in', 'like',
            'union', 'join', 'insert', 'update', 'delete', 'drop', 'create',
            'order', 'by', 'group', 'having', 'limit', 'null', 'is', 'as',
            'distinct', 'count', 'sum', 'avg', 'min', 'max', 'between',
            'exists', 'case', 'when', 'then', 'else', 'end', 'cast', 'convert',
            'sleep', 'waitfor', 'benchmark', 'concat', 'char', 'substring',
            'information_schema', 'database', 'table', 'column'
        }
        
        SQL_OPERATORS = {'=', '<', '>', '<=', '>=', '!=', '<>', '+', '-', '*', '/', '%'}
        SQL_PUNCTUATION = {'(', ')', ',', ';', '.', ':', '[', ']', '{', '}', '#', '--'}
        
        def get_token_type(token):
            """Classify token type"""
            if token in SQL_KEYWORDS:
                return self.type_to_idx.get('keyword', 3)
            elif token in SQL_OPERATORS:
                return self.type_to_idx.get('operator', 4)
            elif token in SQL_PUNCTUATION:
                return self.type_to_idx.get('punctuation', 6)
            elif token.isdigit():
                return self.type_to_idx.get('numeric_literal', 5)
            elif token.startswith("'") or token.startswith('"'):
                return self.type_to_idx.get('string_literal', 7)
            elif re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', token):
                return self.type_to_idx.get('identifier', 2)
            else:
                return self.type_to_idx.get('<UNK>', 1)
        
        # Encode types
        encoded = []
        for token in tokens[:self.max_word_length]:
            type_idx = get_token_type(token)
            encoded.append(type_idx)
        
        # Pad or truncate
        if len(encoded) < self.max_word_length:
            encoded += [0] * (self.max_word_length - len(encoded))
        else:
            encoded = encoded[:self.max_word_length]
        
        return np.array([encoded], dtype=np.int32)
    
    def _extract_char_features(self, query: str) -> np.ndarray:
        """Extract character-level features (ASCII values)"""
        # Convert to bytes, take first max_char_length chars
        char_indices = []
        for char in query[:self.max_char_length]:
            # Clip ASCII values to 0-255 range
            char_idx = min(ord(char), 255)
            char_indices.append(char_idx)
        
        # Pad or truncate
        if len(char_indices) < self.max_char_length:
            char_indices += [0] * (self.max_char_length - len(char_indices))
        else:
            char_indices = char_indices[:self.max_char_length]
        
        return np.array([char_indices], dtype=np.int32)
    
    def _extract_structural_features(self, query: str) -> np.ndarray:
        """
        Extract 104 structural features (approximation).
        In production, these would come from full feature engineering pipeline.
        """
        query_lower = query.lower()
        
        # Basic structural features (104 dims from Phase 5A)
        features = np.zeros(self.structural_dim, dtype=np.float32)
        
        # Query length features (positions 0-9)
        features[0] = len(query)
        features[1] = len(query.split())
        features[2] = query.count(' ')
        features[3] = query.count(',')
        features[4] = query.count('(')
        features[5] = query.count(')')
        features[6] = query.count(';')
        features[7] = query.count("'")
        features[8] = query.count('"')
        features[9] = query.count('--')
        
        # Keyword counts (positions 10-39)
        keywords = ['select', 'from', 'where', 'union', 'insert', 'update', 
                   'delete', 'drop', 'create', 'alter', 'and', 'or', 'not',
                   'join', 'order', 'by', 'group', 'having', 'limit', 'like',
                   'in', 'between', 'exists', 'case', 'when', 'null', 
                   'count', 'sum', 'avg', 'distinct']
        for i, kw in enumerate(keywords):
            features[10 + i] = query_lower.count(kw)
        
        # Operator counts (positions 40-54)
        operators = ['=', '<', '>', '<=', '>=', '!=', '+', '-', '*', '/', 
                    '%', '||', '&&', '!', '~']
        for i, op in enumerate(operators):
            features[40 + i] = query.count(op)
        
        # Attack pattern indicators (positions 55-79)
        attack_patterns = [
            '1=1', '2=2', "' or '", '" or "', 'sleep(', 'waitfor',
            'benchmark', 'load_file', 'concat', 'char(', 'substring',
            'information_schema', 'sysobjects', 'syscolumns',
            'xp_cmdshell', 'exec(', 'execute(', 'script>', 'javascript:',
            '<iframe', 'onload=', 'onerror=', '../', '..\\', 'eval('
        ]
        for i, pattern in enumerate(attack_patterns):
            features[55 + i] = 1.0 if pattern in query_lower else 0.0
        
        # Statistical features (positions 80-103) - normalized
        features[80] = len(query) / 1000.0  # Normalized length
        features[81] = len(query.split()) / 100.0  # Normalized word count
        features[82] = query.count('(') / 20.0  # Normalized paren count
        features[83] = query_lower.count('select') / 5.0
        features[84] = query_lower.count('union') / 3.0
        features[85] = query_lower.count('where') / 5.0
        features[86] = query.count('--') / 2.0
        features[87] = query.count(';') / 3.0
        
        # Fill remaining features with derived stats
        for i in range(88, 104):
            features[i] = 0.0  # Placeholder for advanced features
        
        return np.array([features], dtype=np.float32)


# Singleton instance
_preprocessor = None

def get_preprocessor() -> CNNPreprocessor:
    """Get or create preprocessor singleton"""
    global _preprocessor
    if _preprocessor is None:
        vocab_path = Path(__file__).parent.parent / "artifacts" / "word_vocabulary_5k.pkl"
        _preprocessor = CNNPreprocessor(vocab_path)
    return _preprocessor


if __name__ == "__main__":
    # Quick test for ruthless debugging!
    import pickle
    from pathlib import Path

    # Use your real vocab path!
    vocab_path = Path(__file__).parent.parent / "artifacts" / "word_vocabulary_5k.pkl"
    preprocessor = CNNPreprocessor(vocab_path)

    # Test query
    query = "SELECT * FROM users WHERE id=1 OR 1=1--"
    tokens = preprocessor._tokenize_query(query)
    indices = [preprocessor.word_to_idx.get(t, preprocessor.word_to_idx.get('<UNK>', 1)) for t in tokens]
    print("QUERY:", query)
    print("TOKENS:", tokens)
    print("INDICES:", indices)
    print("Top 30 vocab entries:", list(preprocessor.word_to_idx.items())[:30])
    print("Word vocab size:", len(preprocessor.word_to_idx))
