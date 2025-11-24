"""
Extract vocabularies from Phase 3C dataset
"""
import json
import pickle
from pathlib import Path
from collections import Counter
import re

print("=" * 70)
print("VOCABULARY EXTRACTION FROM DATASET")
print("=" * 70)

# Load dataset
base_path = Path("D:/Major-Project(SQLi)_Latest/Major-Project(SQLi)_Latest/Major-Project(SQLi)")
dataset_path = base_path / "notebooks/phase3c_evaluation_datasets/artifacts/day9_deduplication/clean_eval_datasets/day7_benign_balanced_clean.jsonl"

print(f"\n1. Loading dataset from: {dataset_path.name}")
queries = []
with open(dataset_path, 'r', encoding='utf-8') as f:
    for line in f:
        data = json.loads(line)
        query = data.get('raw_query')  # ← Fixed field name
        if query:
            queries.append(query)

print(f"   Loaded {len(queries)} queries")
print(f"   Sample: {queries[0][:80]}...")

# Build word vocabulary
print("\n2. Building word vocabulary...")

def tokenize_query(query):
    """Simple tokenization"""
    query = str(query).lower()
    tokens = re.findall(r'\w+|[^\w\s]', query)
    return tokens

all_tokens = []
for query in queries:
    tokens = tokenize_query(query)
    all_tokens.extend(tokens)

token_counts = Counter(all_tokens)
print(f"   Total unique tokens: {len(token_counts)}")

# Create vocab: top 5000 most common
VOCAB_SIZE = 5000
most_common = token_counts.most_common(VOCAB_SIZE - 2)

word_to_idx = {
    '<PAD>': 0,
    '<UNK>': 1
}
for i, (token, count) in enumerate(most_common, start=2):
    word_to_idx[token] = i

print(f"   Created vocabulary with {len(word_to_idx)} tokens")
print(f"   Top 30 tokens: {list(word_to_idx.keys())[2:32]}")

# Build type vocabulary
print("\n3. Building type vocabulary...")

SQL_KEYWORDS = {
    'select', 'from', 'where', 'and', 'or', 'insert', 'update', 'delete',
    'union', 'join', 'inner', 'left', 'right', 'on', 'order', 'by',
    'group', 'having', 'limit', 'offset', 'distinct', 'as', 'table',
    'drop', 'create', 'alter', 'null', 'not', 'in', 'like', 'between',
    'exists', 'case', 'when', 'then', 'else', 'end', 'into', 'values',
    'set', 'database', 'truncate', 'grant', 'revoke', 'sleep', 'waitfor',
    'benchmark', 'load_file', 'concat', 'char', 'substring', 'ascii',
    'information_schema'
}

SQL_OPERATORS = {
    '=', '<', '>', '<=', '>=', '!=', '<>', '+', '-', '*', '/', '%',
    '||', '&&', '!', '~', '|', '&', '^', '<<', '>>'
}

SQL_PUNCTUATION = {
    '(', ')', ',', ';', '.', ':', '[', ']', '{', '}', '@', '#', '--', '/*', '*/'
}

def get_token_type(token):
    """Classify token type"""
    token_lower = token.lower()
    
    if token_lower in SQL_KEYWORDS:
        return 'KEYWORD'
    elif token in SQL_OPERATORS:
        return 'OPERATOR'
    elif token in SQL_PUNCTUATION:
        return 'PUNCTUATION'
    elif token.isdigit():
        return 'NUMBER'
    elif token.startswith("'") or token.startswith('"'):
        return 'STRING'
    elif re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', token):
        return 'IDENTIFIER'
    else:
        return 'OTHER'

type_to_idx = {
    '<PAD>': 0,
    '<UNK>': 1,
    'KEYWORD': 2,
    'OPERATOR': 3,
    'PUNCTUATION': 4,
    'NUMBER': 5,
    'STRING': 6,
    'IDENTIFIER': 7,
    'OTHER': 8
}

print(f"   Created type vocabulary with {len(type_to_idx)} types")

# Save vocabularies
print("\n4. Saving vocabularies...")
output_dir = base_path / "backend/app/artifacts"
output_dir.mkdir(exist_ok=True)

vocab_data = {
    'word_to_idx': word_to_idx,
    'type_to_idx': type_to_idx,
    'vocab_size': VOCAB_SIZE,
    'max_word_length': 150,
    'max_char_length': 1024,
    'structural_dim': 104,
    'sql_keywords': SQL_KEYWORDS,
    'sql_operators': SQL_OPERATORS,
    'sql_punctuation': SQL_PUNCTUATION
}

output_path = output_dir / "preprocessing_vocab.pkl"
with open(output_path, 'wb') as f:
    pickle.dump(vocab_data, f)

print(f"   ✓ Saved to: {output_path}")

# Test
print("\n5. Testing vocabulary...")
test_query = "SELECT * FROM users WHERE id=1 OR 1=1--"
tokens = tokenize_query(test_query)
print(f"   Test query: {test_query}")
print(f"   Tokens: {tokens}")
encoded = [word_to_idx.get(t, word_to_idx['<UNK>']) for t in tokens]
print(f"   Encoded: {encoded}")

print("\n" + "=" * 70)
print("✓ VOCABULARY EXTRACTION COMPLETE")
print("=" * 70)
