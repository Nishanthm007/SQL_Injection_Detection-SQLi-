"""
app/services/detector.py

HybridDetector tuned: adjusted CNN weight + larger bonuses for high-risk rules, and higher suspicious floor.
Single-file replacement to tune recall/precision tradeoff from observed outputs.
"""

import time
import re
import numpy as np
from typing import Tuple, List, Any

# Prefer package imports; fall back to local for script-run convenience
try:
    from app.services.preprocessor import get_preprocessor
    from app.utils.model_loader import get_model_loader
    from app.core.config import settings
except Exception:
    from preprocessor import get_preprocessor  # type: ignore
    from model_loader import get_model_loader  # type: ignore
    # Minimal fallback settings if app.core.config not available
    class _FallbackSettings:
        CNN_WEIGHT = 0.45    # lowered fallback weight to reduce benign FPs (tuned)
        RULE_WEIGHT = 0.55
        DEFAULT_THRESHOLD = 0.5
        HIGH_CNN_BLOCK = 0.95
        HIGH_RULE_BLOCK = 0.75
        RISKY_RULE_THRESHOLD = 0.35
        SUSPICIOUS_LOWER = 0.35
    settings = _FallbackSettings()  # type: ignore


class HybridDetector:
    """
    Hybrid CNN + Rule Engine detector with tuned bonuses for high-risk rules and higher suspicious floor.
    """

    def __init__(self):
        print("[DETECTOR] Initializing Preprocessor + Model Loader...")
        self.pre = get_preprocessor()
        self.model = get_model_loader()
        self.model.last_raw_output = None
        print("[DETECTOR] ✓ HybridDetector ready")

    # -------------------------
    # Robust model-output extractor
    # -------------------------
    def _safe_extract_attack_prob(self, model_output: Any) -> float:
        """
        Extract attack probability from model output.
        NOTE: If model outputs benign probability, invert it to get attack probability.
        Model output interpretation: value close to 1.0 = BENIGN, value close to 0.0 = ATTACK
        So we return (1.0 - model_output) to get attack probability.
        """
        try:
            if model_output is None:
                return 0.0
            if hasattr(model_output, "shape") or isinstance(model_output, (list, tuple, np.ndarray)):
                arr = np.asarray(model_output)
                if arr.size == 0:
                    return 0.0
                if arr.ndim >= 2 and arr.shape[-1] >= 2:
                    # Model outputs [p_attack, p_benign], take last column for benign
                    benign_prob = float(arr[0, -1])
                    # Invert to get attack probability
                    return 1.0 - benign_prob
                flat = arr.flatten()
                benign_prob = float(flat[0])
                # Invert to get attack probability  
                return 1.0 - benign_prob
            if isinstance(model_output, dict):
                for k in ("attack_prob", "p_attack", "prob_attack", "p_malicious", "prob"):
                    if k in model_output:
                        return float(model_output[k])
                for k in ("raw", "output"):
                    if k in model_output:
                        try:
                            benign_prob = float(model_output[k])
                            return 1.0 - benign_prob
                        except Exception:
                            pass
            benign_prob = float(model_output)
            return 1.0 - benign_prob
        except Exception:
            return 0.0

    # -------------------------
    # Rule engine
    # -------------------------
    def _rule_engine(self, query: str) -> Tuple[float, List[str]]:
        q = (query or "").lower()
        stacked_pattern = re.search(r';\s*(select|insert|update|delete|drop|exec|xp_cmdshell)\b', q)
        stacked_detected = bool(stacked_pattern)

        patterns = {
            "tautology": {
                "keys": [" or 1=1", " or '1'='1", "' or 1=1 --", "\" or \"1\"=\"1"],
                "weight": 0.30
            },
            "union_select": {
                "keys": ["union select", "union all select"],
                "weight": 0.25
            },
            "comment_tail": {
                "keys": ["--", "#", "/*", "*/"],
                "weight": 0.20
            },
            "time_delay": {
                "keys": ["sleep(", "benchmark(", "waitfor delay"],
                "weight": 0.40
            },
            "logical_ops": {
                "keys": [" and ", " or "],
                "weight": 0.10
            },
            "stacked": {
                "keys": ["exec ", "xp_cmdshell"],
                "weight": 0.30
            }
        }

        score = 0.0
        matched = []

        for name, info in patterns.items():
            if name == "stacked":
                continue
            for k in info["keys"]:
                if k in q:
                    score += info["weight"]
                    matched.append(name)
                    break

        if stacked_detected:
            score += patterns["stacked"]["weight"]
            matched.append("stacked")

        score = min(1.0, float(score))
        return score, matched

    # -------------------------
    # Fusion logic with rule bonuses (tuned)
    # -------------------------
    def _fuse(self, p_cnn: float, p_rule: float, matched_rules: List[str]) -> Tuple[float, int, str]:
        # Use settings but provide tuned fallbacks
        cnn_w = float(getattr(settings, "CNN_WEIGHT", 0.55))
        rule_w = float(getattr(settings, "RULE_WEIGHT", 0.45))
        default_threshold = float(getattr(settings, "DEFAULT_THRESHOLD", 0.5))
        high_cnn_block = float(getattr(settings, "HIGH_CNN_BLOCK", 0.95))
        high_rule_block = float(getattr(settings, "HIGH_RULE_BLOCK", 0.75))
        risky_rule_threshold = float(getattr(settings, "RISKY_RULE_THRESHOLD", 0.35))
        suspicious_lower = float(getattr(settings, "SUSPICIOUS_LOWER", 0.35))

        # base fused
        fused = (cnn_w * float(p_cnn)) + (rule_w * float(p_rule))
        fused = max(0.0, min(1.0, fused))

        # Rule-specific bonus mapping — tuned after inspection
        rule_bonus_map = {
            "union_select": 0.25,   # increased to ensure UNION variants block even with quiet CNN
            "time_delay": 0.20,     # keep time delay high
            "stacked": 0.12,        # slightly higher
            "tautology": 0.06,
            "comment_tail": 0.02,
            "logical_ops": 0.0
        }

        bonus = 0.0
        for r in matched_rules or []:
            bonus += rule_bonus_map.get(r, 0.0)

        fused_adj = max(0.0, min(1.0, fused + bonus))

        # Safety overrides
        if float(p_cnn) >= high_cnn_block:
            return fused_adj, 1, "BLOCK_CNN_HIGH"
        if float(p_rule) >= high_rule_block:
            return fused_adj, 1, "BLOCK_RULE_HIGH"

        # FORCE-BLOCK for time-delay when rule signal strong enough
        if "time_delay" in (matched_rules or []) and float(p_rule) >= 0.35:
            return fused_adj, 1, "BLOCK_TIME_DELAY"

        # Risky-rule shortcut: if high-risk rule present and adjusted score meets lower threshold,
        # treat as attack to improve recall (now tuned at risky_rule_threshold).
        high_risk_rules = {"union_select", "time_delay", "stacked", "tautology"}
        if any(r in high_risk_rules for r in (matched_rules or [])) and fused_adj >= risky_rule_threshold:
            return fused_adj, 1, "BLOCK_RISKY_RULE"

        # Normal fused decision
        if fused_adj >= default_threshold:
            return fused_adj, 1, "BLOCK_FUSED"

        # Suspicious range (raised floor so benign borderline queries are not flagged)
        if fused_adj >= suspicious_lower:
            return fused_adj, 0, "SUSPICIOUS"

        return fused_adj, 0, "ALLOW"

    # -------------------------
    # Analyze public
    # -------------------------
    def analyze(self, query: str) -> dict:
        start_ts = time.time()

        features = self.pre.preprocess(query)

        # raw model and timing
        cnn_start = time.time()
        raw_out = None
        try:
            if hasattr(self.model, "predict_raw"):
                raw_out = self.model.predict_raw(features)
            else:
                raw_out = self.model.predict(features)
        except Exception:
            try:
                raw_out = self.model.predict(features)
            except Exception:
                raw_out = None
        cnn_end = time.time()
        cnn_latency_ms = (cnn_end - cnn_start) * 1000.0

        # store raw output defensively
        try:
            self.model.last_raw_output = float(self._safe_extract_attack_prob(raw_out))
        except Exception:
            self.model.last_raw_output = None

        # calibrated prob if available
        try:
            if hasattr(self.model, "predict_calibrated"):
                p_cnn = float(self._safe_extract_attack_prob(self.model.predict_calibrated(features)))
            elif hasattr(self.model, "predict_proba"):
                p_cnn = float(self._safe_extract_attack_prob(self.model.predict_proba(features)))
            else:
                p_cnn = float(self._safe_extract_attack_prob(raw_out))
        except Exception:
            p_cnn = float(self._safe_extract_attack_prob(raw_out))

        # rules
        rule_start = time.time()
        p_rule, matched_rules = self._rule_engine(query)
        rule_end = time.time()
        rule_latency_ms = (rule_end - rule_start) * 1000.0

        # fusion uses matched_rules for bonuses
        fused_score, final_label, decision = self._fuse(p_cnn, p_rule, matched_rules)

        # finalize strings and legacy names
        label_str = "attack" if int(final_label) == 1 else ("suspicious" if decision == "SUSPICIOUS" else "benign")
        p_cnn_f = float(round(float(p_cnn), 4))
        p_rule_f = float(round(float(p_rule), 4))
        fused_f = float(round(float(fused_score), 4))
        raw_out_f = float(self.model.last_raw_output) if getattr(self.model, "last_raw_output", None) is not None else 0.0
        total_latency_ms = (time.time() - start_ts) * 1000.0

        result = {
            "query": query,
            "cnn_prob": p_cnn_f,
            "rule_score": p_rule_f,
            "fused_score": fused_f,
            "matched_rules": matched_rules or [],
            "final_label": int(final_label),
            "label_str": label_str,
            "decision": decision,
            "raw_model_output": raw_out_f,
            "cnn_latency_ms": float(round(cnn_latency_ms, 3)),
            "rule_latency_ms": float(round(rule_latency_ms, 3)),
            "latency_ms": float(round(total_latency_ms, 3)),
            # legacy-friendly
            "p_cnn": p_cnn_f,
            "p_rule": p_rule_f,
            "fused": fused_f,
            "scores": {"p_cnn": p_cnn_f, "p_rule": p_rule_f, "fused": fused_f},
            "details": {"raw_model_output": raw_out_f, "cnn_latency_ms": float(round(cnn_latency_ms, 3)), "rule_latency_ms": float(round(rule_latency_ms, 3))}
        }

        return result


# Singleton accessor
_detector: HybridDetector = None  # type: ignore


def get_detector() -> HybridDetector:
    global _detector
    if _detector is None:
        _detector = HybridDetector()
    return _detector
