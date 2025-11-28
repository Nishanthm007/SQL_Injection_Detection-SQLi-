import numpy as np
import tensorflow as tf
from app.core.config import settings


class CNNModelLoader:
    """
    Loads the Phase-8 CNN model (best_model.h5) using the path from settings.
    """

    def __init__(self):
        self.model_path = settings.CNN_MODEL_PATH

        print(f"[MODEL LOADER] Looking for model at: {self.model_path}")

        if not self.model_path.exists():
            raise FileNotFoundError(f"[ERROR] best_model.h5 missing at:\n{self.model_path}")

        print(f"[MODEL LOADER] Loading Keras model: {self.model_path}")
        # best_model.h5 from your train.py
        self.model = tf.keras.models.load_model(self.model_path, compile=False)
        print("[MODEL LOADER] ✓ Model loaded successfully")

    def predict(self, inputs: dict) -> float:
        """
        Run CNN forward-pass.
        Expected dict keys from preprocessor:
            - word_tokens
            - word_types
            - char_features
            - struct_features
        """
        wt = np.asarray(inputs["word_tokens"], dtype=np.int32)
        tp = np.asarray(inputs["word_types"], dtype=np.int32)
        cf = np.asarray(inputs["char_features"], dtype=np.float32)
        sf = np.asarray(inputs["struct_features"], dtype=np.float32)

        print(
            f"[PREDICT] Shapes → "
            f"word_tokens={wt.shape}, "
            f"word_types={tp.shape}, "
            f"char_features={cf.shape}, "
            f"struct_features={sf.shape}"
        )

        pred = self.model([wt, tp, cf, sf])
        prob = float(pred.numpy()[0][0])
        return prob


# Singleton
_model_loader = None

def get_model_loader():
    global _model_loader
    if _model_loader is None:
        _model_loader = CNNModelLoader()
    return _model_loader


if __name__ == "__main__":
    # Quick sanity test (only if you run this file directly)
    dummy = {
        "word_tokens": np.zeros((1, 150)),
        "word_types": np.zeros((1, 150)),
        "char_features": np.zeros((1, 128)),
        "struct_features": np.zeros((1, 32)),
    }
    loader = CNNModelLoader()
    out = loader.predict(dummy)
    print("Output:", out)
