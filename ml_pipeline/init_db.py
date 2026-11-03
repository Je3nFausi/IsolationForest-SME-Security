"""
init_db.py — Apply database/schema.sql to create the predictions table.

Usage (from project root):
    python ml_pipeline/init_db.py

Idempotent — safe to run multiple times.
"""
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from database.db import init_schema


if __name__ == "__main__":
    init_schema()
    print("Done.")