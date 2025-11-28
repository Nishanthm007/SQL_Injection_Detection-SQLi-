import pandas as pd
import numpy as np
import tensorflow as tf
from sklearn.model_selection import train_test_split
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint
import json

from cnn_model import build_cnn_model
from preprocessor import CNNPreprocessor   # Adjust path if different


# ---------------------------------------------------------
# 1. LOAD CSV DATASET
# ---------------------------------------------------------

def load_csv_dataset(path):
    df = pd.read_csv(path, encoding='latin1')

    df.columns = df.columns.str.strip()
    df = df[['Query', 'Label']]

    # Clean Label column
    def safe_label(x):
        try:
            # Remove spaces, quotes, garbage
            x = str(x).strip().replace('"', '').replace("'", "")
            # Convert to int if possible
            return int(float(x))
        except:
            return 0   # default to benign for bad labels

    df['Label'] = df['Label'].apply(safe_label)

    # Limit labels to 0 or 1 ONLY
    df['Label'] = df['Label'].apply(lambda x: 1 if x == 1 else 0)

    queries = df['Query'].astype(str).tolist()
    labels = df['Label'].astype(int).values

    return queries, labels




# ---------------------------------------------------------
# 2. TRAIN MODEL
# ---------------------------------------------------------

def train_model():

    CSV_PATH = r"D:\Major-Project(SQLi)_Latest - Copy\Major-Project(SQLi)_Latest\Major-Project(SQLi)\data\raw\SQL_Injection_Detection_Dataset[IEEE].csv"

    print("Loading CSV dataset...")
    queries, labels = load_csv_dataset(CSV_PATH)

    print("Dataset size:", len(queries))

    # -----------------------------------------------------
    # LOAD VOCAB + WORD TYPES
    # -----------------------------------------------------
    print("Loading vocab & word types...")

    vocab = {}
    word_types = {}

    # Load vocab.json
    vocab_path = r"D:\Major-Project(SQLi)_Latest - Copy\Major-Project(SQLi)_Latest\Major-Project(SQLi)\model_training\vocab.json"
    wordtype_path = r"D:\Major-Project(SQLi)_Latest - Copy\Major-Project(SQLi)_Latest\Major-Project(SQLi)\model_training\word_types.json"

    vocab = json.load(open(vocab_path))
    word_types = json.load(open(wordtype_path))

    max_len = 150

    pre = CNNPreprocessor(vocab, word_types, max_len)

    # -----------------------------------------------------
    # PREPROCESS ALL QUERIES
    # -----------------------------------------------------
    print("Preprocessing queries...")

    word_tokens = []
    word_types_list = []
    char_features = []
    struct_features = []

    for q in queries:
        out = pre.preprocess(q)
        word_tokens.append(out["word_tokens"][0])
        word_types_list.append(out["word_types"][0])
        char_features.append(out["char_features"][0])
        struct_features.append(out["struct_features"][0])

    word_tokens = np.array(word_tokens, dtype=np.int32)
    word_types_list = np.array(word_types_list, dtype=np.int32)
    char_features = np.array(char_features, dtype=np.float32)
    struct_features = np.array(struct_features, dtype=np.float32)
    labels = np.array(labels, dtype=np.float32)

    # -----------------------------------------------------
    # TRAIN/VAL SPLIT
    # -----------------------------------------------------
    X_train_w, X_val_w, \
    X_train_t, X_val_t, \
    X_train_c, X_val_c, \
    X_train_s, X_val_s, \
    y_train, y_val = train_test_split(
        word_tokens,
        word_types_list,
        char_features,
        struct_features,
        labels,
        test_size=0.2,
        random_state=42
    )

    # -----------------------------------------------------
    # BUILD MODEL
    # -----------------------------------------------------
    print("Building model...")

    vocab_size = len(vocab) + 1
    word_type_size = len(word_types) + 1

    model = build_cnn_model(
        vocab_size=vocab_size,
        word_type_size=word_type_size,
        max_len=max_len
    )

    model.summary()

    # -----------------------------------------------------
    # COMPILE (AUC + Precision + Recall)
    # -----------------------------------------------------
    model.compile(
        optimizer=tf.keras.optimizers.Adam(1e-3),
        loss="binary_crossentropy",
        metrics=[
            tf.keras.metrics.AUC(name="auc"),
            tf.keras.metrics.Precision(name="precision"),
            tf.keras.metrics.Recall(name="recall")
        ]
    )

    # -----------------------------------------------------
    # CALLBACKS
    # -----------------------------------------------------
    callbacks = [
        EarlyStopping(
            monitor="val_auc",
            patience=3,
            restore_best_weights=True
        ),
        ModelCheckpoint(
            filepath="best_model.h5",
            save_best_only=True,
            monitor="val_auc",
            mode="max"
        )
    ]

    # -----------------------------------------------------
    # TRAIN
    # -----------------------------------------------------
    print("Training model...")

    history = model.fit(
        {
            "word_tokens": X_train_w,
            "word_types": X_train_t,
            "char_features": X_train_c,
            "struct_features": X_train_s,
        },
        y_train,
        validation_data=(
            {
                "word_tokens": X_val_w,
                "word_types": X_val_t,
                "char_features": X_val_c,
                "struct_features": X_val_s,
            },
            y_val
        ),
        epochs=20,
        batch_size=32,
        callbacks=callbacks
    )

    # -----------------------------------------------------
    # SAVE FINAL MODEL
    # -----------------------------------------------------
    model.save("saved_model_final")
    print("Training complete. Saved best_model.h5 and saved_model_final/")


if __name__ == "__main__":
    train_model()
