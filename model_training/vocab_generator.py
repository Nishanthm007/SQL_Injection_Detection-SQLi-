import pandas as pd
import json
import re
from collections import Counter
from pathlib import Path

# ---------------------------------------------------------
# CONFIG
# ---------------------------------------------------------

CSV_PATH = r"D:\Major-Project(SQLi)_Latest - Copy\Major-Project(SQLi)_Latest\Major-Project(SQLi)\data\raw\SQL_Injection_Detection_Dataset[IEEE].csv"
VOCAB_OUTPUT = "vocab.json"
WORD_TYPES_OUTPUT = "word_types.json"

MAX_VOCAB_SIZE = 5000   # enough for SQL datasets


# ---------------------------------------------------------
# TOKENIZER (MUST MATCH PREPROCESSOR EXACTLY)
# ---------------------------------------------------------

def tokenize(text):
    text = text.lower()
    return re.findall(r'\w+|[^\w\s]', text)


# ---------------------------------------------------------
# SQL Token Type Classification
# ---------------------------------------------------------

SQL_KEYWORDS = {
    'select', 'from', 'where', 'and', 'or', 'not', 'in', 'like',
    'union', 'join', 'insert', 'update', 'delete', 'drop', 'create',
    'order', 'by', 'group', 'having', 'limit', 'null', 'is', 'as',
    'distinct', 'count', 'sum', 'avg', 'min', 'max', 'between',
    'exists', 'case', 'when', 'then', 'else', 'end', 'cast', 'convert',
    'sleep', 'benchmark', 'waitfor', 'concat', 'char', 'substring',
    'information_schema', 'database', 'table', 'column'
}

SQL_OPERATORS = {'=', '<', '>', '<=', '>=', '!=', '<>', '+', '-', '*', '/', '%'}

SQL_PUNCT = {'(', ')', ',', ';', '.', ':', '[', ']', '{', '}', '#', '--'}


def get_type(token):
    if token in SQL_KEYWORDS:
        return "keyword"
    if token in SQL_OPERATORS:
        return "operator"
    if token in SQL_PUNCT:
        return "punctuation"
    if token.isdigit():
        return "numeric_literal"
    if token.startswith("'") or token.startswith('"'):
        return "string_literal"
    if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', token):
        return "identifier"
    return "<UNK>"


# ---------------------------------------------------------
# MAIN SCRIPT
# ---------------------------------------------------------

def build_vocab():
    print("[*] Loading CSV dataset...")
    df = pd.read_csv(CSV_PATH, encoding='latin1')

    
    df.columns = df.columns.str.strip()
    df = df[['Query', 'Label']]

    all_tokens = []
    type_set = set()

    for q in df['Query'].astype(str):
        tokens = tokenize(q)
        all_tokens.extend(tokens)
        for t in tokens:
            type_set.add(get_type(t))

    print(f"[*] Total tokens collected: {len(all_tokens)}")

    # Count tokens
    counter = Counter(all_tokens)
    most_common = counter.most_common(MAX_VOCAB_SIZE - 1)

    # ID 0 is reserved for PAD/OOV
    vocab = {"<PAD>": 0}

    for i, (word, _) in enumerate(most_common, start=1):
        vocab[word] = i

    # Build type vocabulary (also reserve 0 for PAD)
    word_types = {"<PAD>": 0}
    for i, t in enumerate(sorted(type_set), start=1):
        word_types[t] = i

    # Save vocab.json
    with open(VOCAB_OUTPUT, "w") as f:
        json.dump(vocab, f, indent=2)
    print(f"[+] Saved word vocabulary → {VOCAB_OUTPUT} ({len(vocab)} entries)")

    # Save word_types.json
    with open(WORD_TYPES_OUTPUT, "w") as f:
        json.dump(word_types, f, indent=2)
    print(f"[+] Saved token type vocabulary → {WORD_TYPES_OUTPUT} ({len(word_types)} entries)")


if __name__ == "__main__":
    build_vocab()
