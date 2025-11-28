import tensorflow as tf
from tensorflow.keras import layers, models, regularizers

def build_cnn_model(
    vocab_size,
    word_type_size,
    max_len=150,
    embed_dim=64
):

    # -------------------------------------------------------------
    # INPUT 1: WORD TOKENS
    # -------------------------------------------------------------
    word_input = layers.Input(shape=(max_len,), name="word_tokens")

    word_embedding = layers.Embedding(
        input_dim=vocab_size,
        output_dim=embed_dim,
        mask_zero=True,
        embeddings_regularizer=regularizers.l2(1e-4)
    )(word_input)

    x1 = layers.Conv1D(128, kernel_size=3, activation="relu")(word_embedding)
    x1 = layers.GlobalMaxPooling1D()(x1)
    x1 = layers.Dropout(0.4)(x1)

    # -------------------------------------------------------------
    # INPUT 2: WORD TYPES
    # -------------------------------------------------------------
    type_input = layers.Input(shape=(max_len,), name="word_types")

    type_embedding = layers.Embedding(
        input_dim=word_type_size,
        output_dim=32,
        mask_zero=True,
        embeddings_regularizer=regularizers.l2(1e-4)
    )(type_input)

    x2 = layers.Conv1D(64, kernel_size=3, activation="relu")(type_embedding)
    x2 = layers.GlobalMaxPooling1D()(x2)
    x2 = layers.Dropout(0.4)(x2)

    # -------------------------------------------------------------
    # INPUT 3: CHARACTER FEATURES
    # -------------------------------------------------------------
    char_input = layers.Input(shape=(128,), name="char_features")
    x3 = layers.Dense(64, activation="relu")(char_input)
    x3 = layers.Dropout(0.3)(x3)

    # -------------------------------------------------------------
    # INPUT 4: STRUCTURAL FEATURES
    # -------------------------------------------------------------
    struct_input = layers.Input(shape=(32,), name="struct_features")
    x4 = layers.Dense(32, activation="relu")(struct_input)

    # -------------------------------------------------------------
    # CONCATENATE ALL FEATURES
    # -------------------------------------------------------------
    concat = layers.Concatenate()([x1, x2, x3, x4])

    dense = layers.Dense(
        64,
        activation="relu",
        kernel_regularizer=regularizers.l2(1e-4)
    )(concat)

    dense = layers.Dropout(0.5)(dense)

    output = layers.Dense(1, activation="sigmoid")(dense)

    model = models.Model(
        inputs=[word_input, type_input, char_input, struct_input],
        outputs=output
    )

    return model
