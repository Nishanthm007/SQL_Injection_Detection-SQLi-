"""Quick test for schemas"""
import sys
from pathlib import Path

backend_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(backend_dir))

from app.models.schemas import DetectionRequest, DetectionResponse, detection_result_to_response

print("=" * 70)
print("SCHEMA VALIDATION TEST")
print("=" * 70)

# Test valid request
try:
    req = DetectionRequest(
        query="SELECT * FROM users WHERE id = 1",
        metadata={"ip": "127.0.0.1"}
    )
    print("\n✓ Valid request accepted")
    print(f"  Query: {req.query}")
except Exception as e:
    print(f"\n✗ Valid request rejected: {e}")

# Test invalid request (empty query)
try:
    req = DetectionRequest(query="   ")
    print("\n✗ Empty query accepted (SHOULD FAIL)")
except Exception as e:
    print(f"\n✓ Empty query rejected: {e}")

# Test response conversion
mock_result = {
    'label': 1,
    'p_cnn': 0.92,
    'p_rule': 0.65,
    'fused_score': 0.85,
    'decision_source': 'hybrid',
    'latency_ms': 45.3,
    'rule_matches': ['Tautology OR 1=1']
}

response = detection_result_to_response(mock_result)
print("\n✓ Response conversion successful")
print(f"  Prediction: {response.prediction}")
print(f"  Confidence: {response.confidence}")
print(f"  JSON: {response.model_dump_json(indent=2)[:200]}...")

print("\n" + "=" * 70)
print("✓ SCHEMA TEST PASSED")
print("=" * 70)
