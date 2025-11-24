"""Quick endpoint test"""
import sys
from pathlib import Path

backend_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(backend_dir))

import asyncio
from app.api.v1.endpoints.detection import get_detector, detect_sql_injection
from app.models.schemas import DetectionRequest

print("=" * 70)
print("ENDPOINT TEST")
print("=" * 70)

async def test_endpoint():
    # Get detector
    print("\nInitializing detector...")
    detector = get_detector()
    
    # Test request
    request = DetectionRequest(
        query="SELECT * FROM users WHERE id = 1 OR 1=1",
        metadata={"test": True}
    )
    
    print(f"\nTesting detection endpoint...")
    print(f"Query: {request.query}")
    
    # Call endpoint
    response = await detect_sql_injection(request, detector)
    
    print(f"\n✓ Endpoint response:")
    print(f"  Label: {response.label} ({response.prediction})")
    print(f"  Confidence: {response.confidence:.4f}")
    print(f"  Source: {response.decision_source}")
    print(f"  Latency: {response.latency_ms}ms")
    if response.rule_matches:
        print(f"  Rules matched: {len(response.rule_matches)}")
    
    print("\n" + "=" * 70)
    print("✓ ENDPOINT TEST PASSED")
    print("=" * 70)

try:
    asyncio.run(test_endpoint())
except Exception as e:
    print(f"\n✗ ENDPOINT TEST FAILED: {e}")
    import traceback
    traceback.print_exc()
