import numpy as np
from app.services.preprocessor import get_preprocessor
from app.utils.model_loader import get_model_loader


class HybridDetector:
    """
    Final Phase-8 SQL Injection Detector
    CNN + Rule Engine + Fusion Logic
    """

    def __init__(self):
        print("[DETECTOR] Initializing Preprocessor + Model Loader...")
        self.pre = get_preprocessor()
        self.model = get_model_loader()
        print("[DETECTOR] ✓ HybridDetector ready")

    # ---------------------------------------------------------
    def analyze(self, query: str) -> dict:

        # Preprocess
        features = self.pre.preprocess(query)

        # CNN probability
        p_attack = self.model.predict(features)

        # Rule engine
        rule_score, matched_rules = self._rule_engine(query)

        # Fusion → final label + decision
        final_label, decision = self._fuse(p_attack, rule_score)

        return {
            "query": query,
            "cnn_prob": float(round(p_attack, 4)),
            "rule_score": float(round(rule_score, 4)),
            "matched_rules": matched_rules,
            "final_label": int(final_label),
            "decision": decision
        }

    # ---------------------------------------------------------
    def _rule_engine(self, query: str):
        """
        Updated rule engine with better weights and pattern coverage.
        """

        q = query.lower()

        # Rule patterns with improved weights
        patterns = {
            "OR 1=1": {
                "keys": [" or 1=1", " or '1'='1", "' or 1=1 --", "\" or \"1\"=\"1"],
                "weight": 0.25
            },
            "UNION SELECT": {
                "keys": ["union select", "union all select"],
                "weight": 0.25
            },
            "COMMENT": {
                "keys": ["--", "#", "/*", "*/"],
                "weight": 0.20
            },
            "TIME DELAY": {
                "keys": ["sleep(", "benchmark(", "waitfor delay"],
                "weight": 0.30
            },
            "LOGICAL OPS": {
                "keys": [" and ", " or "],
                "weight": 0.15
            },
            "STACKED QUERIES": {
                "keys": [";", "exec", "xp_cmdshell"],
                "weight": 0.25
            }
        }

        score = 0.0
        matched = []

        for rule_name, info in patterns.items():
            for k in info["keys"]:
                if k in q:
                    score += info["weight"]
                    matched.append(rule_name)
                    break  # Avoid double-counting similar patterns

        # Cap score to 1.0 max
        score = min(score, 1.0)

        return score, matched


    # ---------------------------------------------------------
    def _fuse(self, cnn_prob: float, rule_score: float):
        """
        Industry-grade fusion logic.
        Priority:
            1. CNN strong → block
            2. Rules strong → block
            3. CNN + Rules medium → block
            4. Suspicious → allow with caution
            5. Otherwise → allow
        """

        # 1️⃣ CNN ALONE — STRONG MALICIOUS
        if cnn_prob >= 0.95:
            return 1, "BLOCK_CNN_HIGH"

        # 2️⃣ RULES ALONE — STRONG MALICIOUS
        if rule_score >= 0.50:
            return 1, "BLOCK_RULE_STRONG"

        # 3️⃣ FUSED: Medium CNN + Medium Rules → malicious
        if (cnn_prob >= 0.85 and rule_score >= 0.25):
            return 1, "BLOCK_FUSED"

        # 4️⃣ CNN suspicious OR rules suspicious → soft allow
        if (cnn_prob >= 0.70 or rule_score >= 0.15):
            return 0, "ALLOW_SUSPICIOUS"

        # 5️⃣ Default benign
        return 0, "ALLOW"



# ---------------------------------------------------------
# Singleton
# ---------------------------------------------------------
_detector = None

def get_detector():
    global _detector
    if _detector is None:
        _detector = HybridDetector()
    return _detector
