"""Test database models"""
import sys
from pathlib import Path

backend_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(backend_dir))

from app.db.database import init_db, engine
from app.db.models import AttackLog, PerformanceMetric, FeedbackLog

print("=" * 70)
print("DATABASE MODELS TEST")
print("=" * 70)

try:
    # Initialize database (create tables)
    print("\nInitializing database...")
    init_db()
    
    # Check tables exist
    from sqlalchemy import inspect
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    
    print(f"\n✓ Tables created: {tables}")
    
    # Check each model's columns
    for table in tables:
        columns = [col['name'] for col in inspector.get_columns(table)]
        print(f"\n{table}:")
        print(f"  Columns ({len(columns)}): {', '.join(columns)}")
    
    print("\n" + "=" * 70)
    print("✓ DATABASE MODELS TEST PASSED")
    print("=" * 70)
    print("\nYou can now open the database with DB Browser:")
    print(f"File: {engine.url.database}")
    
except Exception as e:
    print(f"\n✗ DATABASE MODELS TEST FAILED: {e}")
    import traceback
    traceback.print_exc()
