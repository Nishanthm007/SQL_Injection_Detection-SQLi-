"""
Hybrid SQL Injection Detection Service.
Implements Phase 7 fusion logic: 0.7*CNN + 0.3*Rules with fallback.
"""

# ============================================================
# IMPORT PATH FIX (for standalone testing)
# ============================================================
import sys
from pathlib import Path

if __name__ == "__main__":
    backend_dir = Path(__file__).resolve().parent.parent.parent
    sys.path.insert(0, str(backend_dir))

# ============================================================
# STANDARD IMPORTS
# ============================================================
import asyncio
import time
import re
from typing import Dict, List, Optional, Tuple
import numpy as np

from app.core.config import settings
from app.utils.model_loader import ModelArtifacts


class HybridDetector:
    """
    Core detection service implementing hybrid CNN + rules fusion.
    Thread-safe, async-compatible, with timeout and fallback handling.
    """
    
    def __init__(self, artifacts: ModelArtifacts):
        """Initialize detector with loaded artifacts."""
        self.artifacts = artifacts
        self.timeout_ms = settings.CNN_TIMEOUT_MS
        
        self.cnn_weight = self.artifacts.cnn_weight
        self.rule_weight = self.artifacts.rule_weight
        self.threshold = self.artifacts.threshold
        
        print(f"[DETECTOR] Initialized with:")
        print(f"  - CNN weight: {self.cnn_weight}")
        print(f"  - Rule weight: {self.rule_weight}")
        print(f"  - Threshold: {self.threshold}")
        print(f"  - Timeout: {self.timeout_ms}ms")
    
    async def predict(self, query: str, metadata: Optional[Dict] = None) -> Dict:
        """Main prediction method with hybrid fusion and fallback."""
        start_time = time.perf_counter()
        
        # Run CNN with timeout protection
        try:
            cnn_task = asyncio.create_task(self._predict_cnn_async(query))
            p_cnn, cnn_latency = await asyncio.wait_for(
                cnn_task,
                timeout=self.timeout_ms / 1000
            )
            timeout_occurred = False
            
        except asyncio.TimeoutError:
            print(f"[DETECTOR] CNN timeout ({self.timeout_ms}ms), using rules fallback")
            return await self._predict_rules_only(query, metadata)
        
        except Exception as e:
            print(f"[DETECTOR] CNN error: {e}, using rules fallback")
            return await self._predict_rules_only(query, metadata)
        
        # Run rules engine
        p_rule, rule_matches, rule_latency = await self._predict_rules_async(query)
        
        # Fusion: 0.7*CNN + 0.3*Rules
        fused_score = self.cnn_weight * p_cnn + self.rule_weight * p_rule
        label = int(fused_score >= self.threshold)
        
        total_latency = (time.perf_counter() - start_time) * 1000
        
        return {
            'label': label,
            'p_cnn': float(p_cnn),
            'p_rule': float(p_rule),
            'fused_score': float(fused_score),
            'decision_source': 'hybrid',
            'latency_ms': round(total_latency, 2),
            'cnn_latency_ms': round(cnn_latency, 2),
            'rule_latency_ms': round(rule_latency, 2),
            'rule_matches': rule_matches,
            'timeout_occurred': timeout_occurred
        }
    
    async def _predict_cnn_async(self, query: str) -> Tuple[float, float]:
        """Run CNN inference asynchronously."""
        start = time.perf_counter()
        
        inputs = self._preprocess_query(query)
        
        loop = asyncio.get_event_loop()
        prediction = await loop.run_in_executor(
            None,
            self.artifacts.predict_cnn,
            inputs
        )
        
        latency = (time.perf_counter() - start) * 1000
        return prediction, latency
    
    async def _predict_rules_async(self, query: str) -> Tuple[float, List[str], float]:
        """Run rule engine asynchronously with regex pattern matching."""
        start = time.perf_counter()
        
        matched_rules = []
        total_confidence = 0.0
        max_priority = 0
        
        for rule in self.artifacts.rules:
            if isinstance(rule, dict):
                # Skip disabled rules
                if not rule.get("enabled", True):
                    continue
                
                # Get pattern from 'regex' key (your rules use 'regex', not 'pattern')
                pattern = rule.get("regex", "")
                name = rule.get("name", "Unknown Rule")
                confidence = rule.get("confidence", 0.5)
                priority = rule.get("priority", 1)
                
                if not pattern:
                    continue
                
                # Check if rule matches
                try:
                    if re.search(pattern, query, re.IGNORECASE):
                        matched_rules.append(name)
                        
                        # Weight confidence by priority (priority is 1-10)
                        weighted_confidence = confidence * (priority / 10.0)
                        total_confidence += weighted_confidence
                        max_priority = max(max_priority, priority)
                        
                except re.error as e:
                    # Skip rules with invalid regex
                    continue
            
            elif isinstance(rule, str):
                # Handle simple string rules (legacy format)
                if rule.lower() in query.lower():
                    matched_rules.append(rule)
                    total_confidence += 0.5
        
        # Normalize confidence to [0, 1] range
        if matched_rules:
            # Average weighted confidence, capped at 1.0
            normalized_confidence = min(total_confidence / len(matched_rules), 1.0)
        else:
            normalized_confidence = 0.0
        
        latency = (time.perf_counter() - start) * 1000
        return normalized_confidence, matched_rules, latency
    
    async def _predict_rules_only(self, query: str, metadata: Optional[Dict] = None) -> Dict:
        """Fallback prediction using rules engine only."""
        start_time = time.perf_counter()
        
        p_rule, rule_matches, rule_latency = await self._predict_rules_async(query)
        label = int(p_rule >= 0.5)
        
        total_latency = (time.perf_counter() - start_time) * 1000
        
        return {
            'label': label,
            'p_cnn': None,
            'p_rule': float(p_rule),
            'fused_score': None,
            'decision_source': 'rules_fallback',
            'latency_ms': round(total_latency, 2),
            'cnn_latency_ms': None,
            'rule_latency_ms': round(rule_latency, 2),
            'rule_matches': rule_matches,
            'timeout_occurred': True
        }
    
    def _preprocess_query(self, query: str) -> Dict[str, np.ndarray]:
        """Preprocess query for CNN inference using Phase 5A pipeline"""
        from app.services.preprocessor import get_preprocessor
        
        preprocessor = get_preprocessor()
        return preprocessor.preprocess(query)
    
    def get_detector_info(self) -> Dict:
        """Returns detector configuration and status."""
        return {
            "cnn_weight": self.cnn_weight,
            "rule_weight": self.rule_weight,
            "threshold": self.threshold,
            "timeout_ms": self.timeout_ms,
            "model_type": self.artifacts._model_type,
            "model_version": self.artifacts.model_version,
            "rule_count": len(self.artifacts.rules)
        }


if __name__ == "__main__":
    from app.utils.model_loader import get_model_artifacts
    
    print("=" * 70)
    print("HYBRID DETECTOR STANDALONE TEST")
    print("=" * 70)
    
    async def test_detector():
        print("\nLoading model artifacts...")
        artifacts = get_model_artifacts()
        
        print("\nInitializing detector...")
        detector = HybridDetector(artifacts)
        
        print("\n" + "=" * 70)
        print("DETECTOR CONFIGURATION")
        print("=" * 70)
        info = detector.get_detector_info()
        for key, value in info.items():
            print(f"{key:20s}: {value}")
        
        test_queries = [
            "SELECT * FROM users WHERE id = 1",
            "SELECT * FROM users WHERE id = 1 OR 1=1",
            "SELECT * FROM users WHERE id = 1; DROP TABLE users--",
            "SELECT * FROM users WHERE id = 1 UNION SELECT * FROM passwords"
        ]
        
        print("\n" + "=" * 70)
        print("PREDICTION TESTS")
        print("=" * 70)
        
        for i, query in enumerate(test_queries, 1):
            print(f"\nTest {i}: {query[:60]}...")
            result = await detector.predict(query)
            
            print(f"  Label: {result['label']} ({'ATTACK' if result['label'] == 1 else 'BENIGN'})")
            print(f"  CNN prob: {result['p_cnn']}")
            print(f"  Rule prob: {result['p_rule']:.4f}")
            print(f"  Fused score: {result['fused_score']}")
            print(f"  Source: {result['decision_source']}")
            print(f"  Latency: {result['latency_ms']:.2f}ms")
            if result['rule_matches']:
                print(f"  Rules matched: {len(result['rule_matches'])}")
                print(f"    {', '.join(result['rule_matches'][:3])}" + 
                      ("..." if len(result['rule_matches']) > 3 else ""))
        
        print("\n" + "=" * 70)
        print("✓ HYBRID DETECTOR TEST PASSED")
        print("=" * 70)
        print("\nDetector working! CNN uses placeholder preprocessing.")
    
    try:
        asyncio.run(test_detector())
    except Exception as e:
        print("\n" + "=" * 70)
        print("✗ HYBRID DETECTOR TEST FAILED")
        print("=" * 70)
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
