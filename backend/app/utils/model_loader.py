"""
Model loader utility for Phase 8 API.
Loads Phase 7 artifacts (SavedModel, rules, metrics) into memory.
Thread-safe singleton pattern for production use.
Handles both Keras and raw TensorFlow SavedModel formats.
"""

# ============================================================
# IMPORT PATH FIX (for standalone testing)
# ============================================================
import sys
from pathlib import Path

if __name__ == "__main__":
    # When run directly, add backend directory to Python path
    backend_dir = Path(__file__).resolve().parent.parent.parent
    sys.path.insert(0, str(backend_dir))

# ============================================================
# STANDARD IMPORTS
# ============================================================
import json
import numpy as np
from typing import Dict, Any, Optional, List, Union
from functools import lru_cache

# TensorFlow import with suppressed warnings
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'  # Suppress TF warnings
import tensorflow as tf

from app.core.config import settings


class ModelArtifacts:
    """
    Container for all Phase 7 artifacts.
    Loaded once at startup, reused across all requests.
    """
    
    def __init__(self):
        """Load all artifacts from disk"""
        print("\n[MODEL LOADER] Initializing Phase 7 artifacts...")
        
        # Load TensorFlow SavedModel (handle both Keras and raw TF formats)
        print(f"[MODEL LOADER] Loading fusion model from:")
        print(f"  {settings.FUSION_MODEL_PATH}")
        
        try:
            # First, try loading as Keras model (preferred)
            self.fusion_model = tf.keras.models.load_model(
                str(settings.FUSION_MODEL_PATH),
                compile=False
            )
            self._model_type = "keras"
            print(f"[MODEL LOADER] ✓ Model loaded as Keras model")
            print(f"  - Layers: {len(self.fusion_model.layers)}")
            print(f"  - Inputs: {len(self.fusion_model.inputs)}")
            print(f"  - Outputs: {len(self.fusion_model.outputs)}")
            
        except ValueError as e:
            # Fallback: Load as raw TensorFlow SavedModel
            if "lacks the Keras metadata file" in str(e):
                print(f"[MODEL LOADER] ⚠ Keras metadata missing, loading as TF SavedModel...")
                
                self.fusion_model = tf.saved_model.load(str(settings.FUSION_MODEL_PATH))
                self._model_type = "tf_savedmodel"
                
                # Get the serving function (usually 'serving_default')
                if hasattr(self.fusion_model, 'signatures'):
                    self._serve_fn = self.fusion_model.signatures['serving_default']
                    print(f"[MODEL LOADER] ✓ Model loaded as TF SavedModel")
                    print(f"  - Signature keys: {list(self.fusion_model.signatures.keys())}")
                    
                    # Show input signature
                    signature = self._serve_fn.structured_input_signature[1]
                    print(f"  - Inputs: {list(signature.keys())}")
                else:
                    raise ValueError("SavedModel has no serving signature")
            else:
                print(f"[MODEL LOADER] ✗ Failed to load model: {e}")
                raise
        except Exception as e:
            print(f"[MODEL LOADER] ✗ Failed to load model: {e}")
            raise
        
        # Load rules engine JSON
        print(f"\n[MODEL LOADER] Loading rules from:")
        print(f"  {settings.RULES_JSON_PATH}")
        
        try:
            with open(settings.RULES_JSON_PATH, 'r', encoding='utf-8') as f:
                rules_data = json.load(f)
            
            # Handle different rule formats
            if isinstance(rules_data, list):
                self.rules = rules_data
                print(f"[MODEL LOADER] ✓ Rules loaded: {len(self.rules)} rules")
            elif isinstance(rules_data, dict):
                # If it's a dict, extract rules list
                self.rules = rules_data.get("rules", [])
                print(f"[MODEL LOADER] ✓ Rules loaded: {len(self.rules)} rules from dict")
            else:
                print(f"[MODEL LOADER] ⚠ Warning: Unexpected rules format")
                self.rules = []
                
        except Exception as e:
            print(f"[MODEL LOADER] ✗ Failed to load rules: {e}")
            raise
        
        # Load metrics (contains threshold, version, performance stats)
        print(f"\n[MODEL LOADER] Loading metrics from:")
        print(f"  {settings.METRICS_JSON_PATH}")
        
        try:
            with open(settings.METRICS_JSON_PATH, 'r', encoding='utf-8') as f:
                self.metrics = json.load(f)
            
            # Extract key values from metrics
            self.threshold = self.metrics.get("threshold", settings.DEFAULT_THRESHOLD)
            self.model_version = self.metrics.get("model_version", "1.0.0")
            self.accuracy = self.metrics.get("accuracy", None)
            self.f1_score = self.metrics.get("f1_score", None)
            self.precision = self.metrics.get("precision", None)
            self.recall = self.metrics.get("recall", None)
            
            print(f"[MODEL LOADER] ✓ Metrics loaded:")
            print(f"  - Threshold: {self.threshold}")
            print(f"  - Version: {self.model_version}")
            if self.accuracy:
                print(f"  - Accuracy: {self.accuracy:.4f}")
            if self.f1_score:
                print(f"  - F1 Score: {self.f1_score:.4f}")
            if self.precision:
                print(f"  - Precision: {self.precision:.4f}")
            if self.recall:
                print(f"  - Recall: {self.recall:.4f}")
        except Exception as e:
            print(f"[MODEL LOADER] ⚠ Warning: Could not load metrics: {e}")
            # Use defaults if metrics file missing
            self.threshold = settings.DEFAULT_THRESHOLD
            self.model_version = "1.0.0"
            self.accuracy = None
            self.f1_score = None
            self.precision = None
            self.recall = None
        
        # Fusion weights (from Phase 7 spec)
        self.cnn_weight = settings.CNN_WEIGHT
        self.rule_weight = settings.RULE_WEIGHT
        
        print(f"\n[MODEL LOADER] ✓ Fusion configuration:")
        print(f"  - CNN weight: {self.cnn_weight}")
        print(f"  - Rule weight: {self.rule_weight}")
        print(f"  - Decision threshold: {self.threshold}")
        
        print("\n[MODEL LOADER] ✓ Initialization complete\n")
    
    def get_model_info(self) -> Dict[str, Any]:
        """
        Returns model metadata for health checks and monitoring.
        
        Returns:
            dict: Model information including version, performance, layers
        """
        info = {
            "model_version": self.model_version,
            "model_type": self._model_type,
            "threshold": self.threshold,
            "accuracy": self.accuracy,
            "f1_score": self.f1_score,
            "precision": self.precision,
            "recall": self.recall,
            "rule_count": len(self.rules),
            "fusion_weights": {
                "cnn": self.cnn_weight,
                "rule": self.rule_weight
            },
            "model_path": str(settings.FUSION_MODEL_PATH),
            "model_format": "TensorFlow SavedModel"
        }
        
        # Add layer count only for Keras models
        if self._model_type == "keras":
            info["cnn_layers"] = len(self.fusion_model.layers)
        
        return info
    
    def get_input_shapes(self) -> Dict[str, tuple]:
        """
        Returns expected input shapes for the CNN model.
        Useful for validation and preprocessing.
        
        Returns:
            dict: Input layer names and their shapes
        """
        input_shapes = {}
        
        if self._model_type == "keras":
            for inp in self.fusion_model.inputs:
                name = inp.name.replace(':0', '')
                input_shapes[name] = inp.shape.as_list()
        else:
            # TF SavedModel - extract from signature
            signature = self._serve_fn.structured_input_signature[1]
            for name, spec in signature.items():
                input_shapes[name] = spec.shape.as_list()
        
        return input_shapes
    
    def get_rule_summary(self) -> Dict[str, Any]:
        """
        Returns summary of loaded rules.
        Handles both string-based and dict-based rule formats.
        
        Returns:
            dict: Rule statistics
        """
        if not self.rules:
            return {"total": 0, "format": "empty", "categories": {}}
        
        # Detect rule format
        first_rule = self.rules[0]
        
        if isinstance(first_rule, str):
            # Rules are strings (simple format)
            return {
                "total": len(self.rules),
                "format": "string_list",
                "categories": {"string_rules": len(self.rules)}
            }
        
        elif isinstance(first_rule, dict):
            # Rules are dictionaries (complex format)
            categories = {}
            for rule in self.rules:
                if isinstance(rule, dict):
                    category = rule.get("category", "unknown")
                    categories[category] = categories.get(category, 0) + 1
            
            return {
                "total": len(self.rules),
                "format": "dict_list",
                "categories": categories
            }
        
        else:
            # Unknown format
            return {
                "total": len(self.rules),
                "format": "unknown",
                "categories": {}
            }
    
    def predict_cnn(self, inputs: Dict[str, np.ndarray]) -> float:
        """
        Run CNN inference with proper input mapping.
        Maps preprocessor outputs to model's expected input names.
        """
        import tensorflow as tf
        
        try:
            # Map preprocessor keys to model input names
            model_inputs = {
                'word_input': tf.convert_to_tensor(inputs['word_tokens'], dtype=tf.float32),
                'type_input': tf.convert_to_tensor(inputs['word_types'], dtype=tf.float32),
                'char_input': tf.convert_to_tensor(inputs['char_input'], dtype=tf.float32),
                'structural_input': tf.convert_to_tensor(inputs['structural_features'][:, :66], dtype=tf.float32)
            }

            for key, arr in model_inputs.items():
                print(f"[DEBUG] {key}: dtype={arr.dtype}, shape={arr.shape}")
            
            # Get serving function
            infer = self.fusion_model.signatures['serving_default']
            
            # Run prediction
            predictions = infer(**model_inputs)
            
            # Extract probability (first key, first batch item, first output)
            output_key = list(predictions.keys())[0]
            prob = float(predictions[output_key][0][0])
            
            return prob
            
        except Exception as e:
            print(f"[MODEL LOADER] CNN prediction error: {e}")
            raise



@lru_cache(maxsize=1)
def get_model_artifacts() -> ModelArtifacts:
    """
    Singleton factory for ModelArtifacts.
    Loaded once at first call, cached for all subsequent calls.
    Thread-safe via lru_cache.
    
    Returns:
        ModelArtifacts: Loaded model, rules, and metrics
    """
    return ModelArtifacts()


# Convenience function for FastAPI dependency injection
def get_artifacts() -> ModelArtifacts:
    """
    FastAPI dependency function.
    Use with Depends(get_artifacts) in endpoint functions.
    
    Returns:
        ModelArtifacts: Singleton instance
    """
    return get_model_artifacts()


# ============================================================
# STANDALONE TEST
# ============================================================

if __name__ == "__main__":
    """Test model loading"""
    print("=" * 70)
    print("MODEL LOADER STANDALONE TEST")
    print("=" * 70)
    
    try:
        # Load artifacts
        artifacts = get_model_artifacts()
        
        # Display model info
        print("\n" + "=" * 70)
        print("MODEL INFORMATION")
        print("=" * 70)
        info = artifacts.get_model_info()
        for key, value in info.items():
            if isinstance(value, dict):
                print(f"\n{key}:")
                for k, v in value.items():
                    print(f"  {k:20s}: {v}")
            else:
                print(f"{key:20s}: {value}")
        
        # Display input shapes
        print("\n" + "=" * 70)
        print("MODEL INPUT SHAPES")
        print("=" * 70)
        shapes = artifacts.get_input_shapes()
        for name, shape in shapes.items():
            print(f"{name:30s}: {shape}")
        
        # Display rule summary
        print("\n" + "=" * 70)
        print("RULE ENGINE SUMMARY")
        print("=" * 70)
        rule_summary = artifacts.get_rule_summary()
        print(f"Total rules: {rule_summary['total']}")
        print(f"Format: {rule_summary['format']}")
        if rule_summary['categories']:
            print("\nRules by category:")
            for cat, count in rule_summary['categories'].items():
                print(f"  {cat:20s}: {count}")
        
        # Success message
        print("\n" + "=" * 70)
        print("✓ MODEL LOADER TEST PASSED")
        print("=" * 70)
        print("\nAll artifacts loaded successfully!")
        print(f"Model type: {artifacts._model_type}")
        print(f"Model inputs: {list(artifacts.get_input_shapes().keys())}")
        print(f"Rules format: {rule_summary['format']}")
        print("\nReady for integration with detection service.")
        
    except Exception as e:
        print("\n" + "=" * 70)
        print("✗ MODEL LOADER TEST FAILED")
        print("=" * 70)
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
