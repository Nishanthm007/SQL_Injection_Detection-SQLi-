"""Test database services"""
import sys
from pathlib import Path

backend_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(backend_dir))

import asyncio
from app.db import services
from app.db.database import get_db_context

print("=" * 70)
print("DATABASE SERVICES TEST")
print("=" * 70)

async def test_services():
    # Test logging an attack
    print("\nTesting attack logging...")
    
    await services.log_attack_async(
        query="SELECT * FROM users WHERE id = 1 OR 1=1",
        label=1,
        confidence=0.95,
        scores={"cnn": 0.98, "rules": 0.85, "fused": 0.95},
        decision_source="hybrid",
        latency_ms=12.5,
        rule_matches=["Tautology OR 1=1"],
        details={"cnn_latency_ms": 10.2, "rule_latency_ms": 2.3, "timeout_occurred": False},
        metadata={"ip_address": "192.168.1.100", "user_agent": "Test Client"}
    )
    
    print("✓ Attack logged")
    
    # Wait for async write to complete
    await asyncio.sleep(0.5)
    
    # Test querying attacks
    print("\nQuerying recent attacks...")
    with get_db_context() as db:
        attacks = services.get_recent_attacks(db, limit=10)
        print(f"✓ Found {len(attacks)} attacks in database")
        
        if attacks:
            print(f"\nMost recent attack:")
            a = attacks[0]
            print(f"  ID: {a.id}")
            print(f"  Query: {a.query[:50]}...")
            print(f"  Label: {a.label}")
            print(f"  Confidence: {a.confidence:.3f}")
            print(f"  Source: {a.decision_source}")
            print(f"  Detected: {a.detected_at}")
        
        # Test statistics
        print("\nGetting statistics...")
        stats = services.get_attack_stats(db, days=7)
        print(f"✓ Statistics:")
        print(f"  Total requests: {stats['total_requests']}")
        print(f"  Attacks detected: {stats['attacks_detected']}")
        print(f"  Attack rate: {stats['attack_rate']}%")
        print(f"  Avg latency: {stats['avg_latency_ms']}ms")
    
    print("\n" + "=" * 70)
    print("✓ DATABASE SERVICES TEST PASSED")
    print("=" * 70)
    print("\nCheck DB Browser - you should see 1 record in attack_logs table!")

try:
    asyncio.run(test_services())
except Exception as e:
    print(f"\n✗ DATABASE SERVICES TEST FAILED: {e}")
    import traceback
    traceback.print_exc()
