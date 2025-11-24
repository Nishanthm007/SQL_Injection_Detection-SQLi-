"""Test database setup"""
import sys
from pathlib import Path

backend_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(backend_dir))

from app.db.database import engine, Base

print("=" * 70)
print("DATABASE SETUP TEST")
print("=" * 70)

try:
    # Test connection
    print(f"\nDatabase URL: {engine.url}")
    print(f"Driver: {engine.driver}")
    
    # Test connection
    with engine.connect() as conn:
        print("✓ Database connection successful")
    
    print("\n" + "=" * 70)
    print("✓ DATABASE SETUP TEST PASSED")
    print("=" * 70)
    
except Exception as e:
    print(f"\n✗ DATABASE SETUP TEST FAILED: {e}")
    import traceback
    traceback.print_exc()
