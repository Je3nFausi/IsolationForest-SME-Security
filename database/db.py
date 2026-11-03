"""
db.py — PostgreSQL connection helper for BI-Safe.

Loads credentials from .env (gitignored). Provides:
  - get_connection(): returns a psycopg2 connection
  - init_schema(): runs database/schema.sql (idempotent)

All DB credentials live in .env — never hardcode them.
"""
import os
from pathlib import Path

import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = PROJECT_ROOT / ".env"
SCHEMA_PATH = PROJECT_ROOT / "database" / "schema.sql"

# Load .env once at import time
load_dotenv(ENV_PATH)


def get_connection():
    """Return a new psycopg2 connection using credentials from .env."""
    return psycopg2.connect(
        host=os.environ["PGHOST"],
        port=int(os.environ["PGPORT"]),
        dbname=os.environ["PGDATABASE"],
        user=os.environ["PGUSER"],
        password=os.environ["PGPASSWORD"],
        cursor_factory=RealDictCursor,
    )


def init_schema():
    """Run database/schema.sql (idempotent — uses CREATE ... IF NOT EXISTS)."""
    sql = SCHEMA_PATH.read_text()
    conn = get_connection()
    try:
        with conn, conn.cursor() as cur:
            cur.execute(sql)
        print(f"Schema applied from {SCHEMA_PATH.name}")
    finally:
        conn.close()