# app/utils/model_loader.py
"""
Model loader wrapper that loads the Keras CNN model and the calibrator (if present).
Provides:
 - get_model_loader() -> singleton ModelWrapper
 - ModelWrapper.predict(features) -> raw model probability (float)
 - ModelWrapper.predict_calibrated(features) -> calibrated probability (float)
"""

from pathlib import Path
import pickle
import numpy as np
import time
from typing import Any

# Keras import (may be tensorflow.keras)
try:
    from tensorflow.keras.models import load_model
except Exception:
    # fallback to keras if installed differently
    from keras.models import load_model

# settings
try:
    from app.core.config import settings
except Exception:
    # defensive fallback if run standalone
    from config import settings

_calibrator = None
_model_wrapper_singleton = None


def _load_calibrator():
    global _calibrator
    try:
        p = Path(settings.MODEL_TRAINING_DIR) / "calibrator.pkl"
        if p.exists():
            with p.open("rb") as fh:
                _calibrator = pickle.load(fh)
            print("[MODEL LOADER] Calibrator loaded:", p)
        else:
            _calibrator = None
            print("[MODEL LOADER] No calibrator found at:", p)
    except Exception as e:
        _calibrator = None
        print("[MODEL LOADER] Error loading calibrator:", e)


class ModelWrapper:
    def __init__(self, keras_model):
        self.model = keras_model
        # load calibrator lazily once model wrapper created
        _load_calibrator()

    def predict_raw(self, features: dict) -> float:
        """
        Predict raw model output (probability/logit depending on model).
        Returns scalar float.
        """
        start = time.time()
        # model.predict returns array-like, probably shape (1,1)
        out = self.model.predict(features)
        # try safe extraction
        try:
            # if numpy array
            val = float(out[0]) if hasattr(out, "__len__") else float(out)
        except Exception:
            try:
                val = float(np.asarray(out).ravel()[0])
            except Exception:
                # fallback
                val = float(out)
        return val

    def predict_calibrated(self, features: dict) -> float:
        """
        Return calibrated probability using sklearn calibrator if available.
        If calibrator not present, return raw probability.
        """
        raw = self.predict_raw(features)
        if _calibrator is not None:
            try:
                # sklearn wants 2D array input
                calibrated = float(_calibrator.predict_proba([[raw]])[0, 1])
                return calibrated
            except Exception as e:
                # on any failure, fallback to raw
                print("[MODEL LOADER] Calibrator predict_proba failed:", e)
                return raw
        return raw

    # convenience: keep old API name 'predict' for backward compatibility (returns raw)
    def predict(self, features: dict) -> float:
        return self.predict_raw(features)


def _load_keras_model():
    model_path = Path(settings.CNN_MODEL_PATH)
    print("[MODEL LOADER] Looking for model at:", model_path)
    if not model_path.exists():
        raise FileNotFoundError(f"Keras model not found at {model_path}")
    print("[MODEL LOADER] Loading Keras model:", model_path)
    model = load_model(str(model_path))
    print("[MODEL LOADER] ✓ Model loaded successfully")
    return model


def get_model_loader() -> ModelWrapper:
    """
    Singleton accessor for the model wrapper.
    """
    global _model_wrapper_singleton
    if _model_wrapper_singleton is None:
        keras_model = _load_keras_model()
        _model_wrapper_singleton = ModelWrapper(keras_model)
    return _model_wrapper_singleton
