"""
Database Setup for BI-Safe (Full Schema)
=========================================

Creates all 8 tables from the ERD:
1. users
2. sme
3. traffic_events
4. models
5. predictions
6. alerts
7. feedback
8. drift_log

Run:
    python database/db_setup.py
"""

import os
import sqlite3


# Get the project root directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATABASE_DIR = os.path.join(BASE_DIR, "database")
DB_PATH = os.path.join(DATABASE_DIR, "bi_safe.db")


# SQL statements for each table
CREATE_USERS_TABLE = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    business_name TEXT,
    email TEXT NOT NULL UNIQUE,
    phone TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('owner', 'admin')),
    sme_id INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    FOREIGN KEY (sme_id) REFERENCES sme(id)
);
"""

CREATE_SME_TABLE = """
CREATE TABLE IF NOT EXISTS sme (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sme_name TEXT NOT NULL,
    sme_type TEXT,
    location TEXT,
    email TEXT,
    phone TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    active INTEGER DEFAULT 1
);
"""

CREATE_MODELS_TABLE = """
CREATE TABLE IF NOT EXISTS models (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    model_name TEXT NOT NULL,
    version INTEGER DEFAULT 1,
    contamination REAL DEFAULT 0.05,
    n_estimators INTEGER DEFAULT 100,
    training_data TEXT,
    f1_score REAL,
    precision REAL,
    recall REAL,
    deployed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'Active' CHECK(status IN ('Active', 'Deprecated', 'Drifted'))
);
"""

CREATE_TRAFFIC_EVENTS_TABLE = """
CREATE TABLE IF NOT EXISTS traffic_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sme_id INTEGER,
    timestamp TEXT,
    protocol TEXT,
    source_ip TEXT,
    destination_ip TEXT,
    source_port INTEGER,
    destination_port INTEGER,
    flow_duration REAL,
    total_fwd_packets INTEGER,
    total_backward_packets INTEGER,
    flow_bytes_s REAL,
    flow_packets_s REAL,
    is_attack INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sme_id) REFERENCES sme(id)
);
"""

CREATE_PREDICTIONS_TABLE = """
CREATE TABLE IF NOT EXISTS predictions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER,
    model_id INTEGER,
    offset INTEGER,
    anomaly_score REAL,
    is_anomaly INTEGER,
    processing_time_ms INTEGER,
    actual INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (event_id) REFERENCES traffic_events(id),
    FOREIGN KEY (model_id) REFERENCES models(id)
);
"""

CREATE_ALERTS_TABLE = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER,
    prediction_id INTEGER,
    sme_id INTEGER,
    alert_type TEXT,
    message TEXT,
    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    delivered INTEGER DEFAULT 0,
    status TEXT DEFAULT 'Pending' CHECK(status IN ('Pending', 'Acknowledged', 'Resolved')),
    priority TEXT CHECK(priority IN ('HIGH', 'MEDIUM', 'LOW')),
    timestamp TEXT,
    offset INTEGER,
    anomaly_score REAL,
    actual INTEGER,
    FOREIGN KEY (prediction_id) REFERENCES predictions(id),
    FOREIGN KEY (sme_id) REFERENCES sme(id)
);
"""

CREATE_FEEDBACK_TABLE = """
CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER,
    sme_id INTEGER,
    user_id INTEGER,
    feedback_type TEXT CHECK(feedback_type IN ('True_Positive', 'False_Positive', 'False_Negative')),
    comment TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (alert_id) REFERENCES alerts(id),
    FOREIGN KEY (sme_id) REFERENCES sme(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);
"""

CREATE_DRIFT_LOG_TABLE = """
CREATE TABLE IF NOT EXISTS drift_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    model_id INTEGER,
    batch_number INTEGER,
    drift_score REAL,
    f1_score REAL,
    precision REAL,
    recall REAL,
    triggered_retrain INTEGER DEFAULT 0,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP,
    FOREIGN KEY (model_id) REFERENCES models(id)
);
"""

CREATE_SYSTEM_STATUS_TABLE = """
CREATE TABLE IF NOT EXISTS system_status (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    producer_status TEXT DEFAULT 'stopped' CHECK(producer_status IN ('running', 'paused', 'stopped')),
    traffic_rate REAL DEFAULT 10.0,
    batch_size INTEGER DEFAULT 100,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""

CREATE_NETWORKS_TABLE = """
CREATE TABLE IF NOT EXISTS networks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sme_id INTEGER,
    network_name TEXT NOT NULL,
    ip_range TEXT NOT NULL,
    sensor_key TEXT NOT NULL,
    status TEXT DEFAULT 'connected' CHECK(status IN ('connected', 'disconnected', 'pending')),
    connected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP,
    events_processed INTEGER DEFAULT 0,
    FOREIGN KEY (sme_id) REFERENCES sme(id)
);
"""


TABLES = [
    ("users", CREATE_USERS_TABLE),
    ("sme", CREATE_SME_TABLE),
    ("models", CREATE_MODELS_TABLE),
    ("traffic_events", CREATE_TRAFFIC_EVENTS_TABLE),
    ("predictions", CREATE_PREDICTIONS_TABLE),
    ("alerts", CREATE_ALERTS_TABLE),
    ("feedback", CREATE_FEEDBACK_TABLE),
    ("drift_log", CREATE_DRIFT_LOG_TABLE),
    ("system_status", CREATE_SYSTEM_STATUS_TABLE),
    ("networks", CREATE_NETWORKS_TABLE),
]


def create_database():
    """Create the database and all tables."""
    os.makedirs(DATABASE_DIR, exist_ok=True)

    print(f"Creating database at {DB_PATH}...")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Enable foreign keys
    cursor.execute("PRAGMA foreign_keys = ON")

    for table_name, sql in TABLES:
        cursor.execute(sql)
        print(f"  Created table: {table_name}")

    conn.commit()
    conn.close()
    print("\n  Database setup complete.")


def seed_default_model():
    """Insert a default model record."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM models")
    count = cursor.fetchone()[0]

    if count == 0:
        cursor.execute("""
            INSERT INTO models (model_name, version, contamination, n_estimators,
                               training_data, f1_score, precision, recall, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            "IsolationForest_v1",
            1,
            0.05,
            100,
            "synthetic_small.csv",
            0.85,
            0.85,
            0.85,
            "Active",
        ))
        conn.commit()
        print("  Seeded default model record.")
    else:
        print(f"  Models table already has {count} record(s). Skipping seed.")

    conn.close()


def seed_demo_data():
    """Insert demo SME and User records for testing."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Check if SME already exists
    cursor.execute("SELECT COUNT(*) FROM sme")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
            INSERT INTO sme (sme_name, sme_type, location, email, phone, active)
            VALUES (?, ?, ?, ?, ?, ?)
        """, ("Mama Salons", "Salon", "Nairobi", "mama@salons.co.ke", "+254712345678", 1))
        sme_id = cursor.lastrowid
        print(f"  Seeded demo SME (id={sme_id}).")
    else:
        cursor.execute("SELECT id FROM sme LIMIT 1")
        sme_id = cursor.fetchone()[0]

    conn.commit()
    conn.close()


def verify_tables():
    """Verify all tables exist."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    tables = [row[0] for row in cursor.fetchall()]
    conn.close()

    print(f"\n{'='*60}")
    print(f"Tables in database ({len(tables)}):")
    print(f"{'='*60}")
    for t in tables:
        print(f"  ✅ {t}")
    print(f"{'='*60}")

def seed_system_status():
    """Insert default system status."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM system_status")
    if cursor.fetchone()[0] == 0:
        cursor.execute(
            "INSERT INTO system_status (producer_status, traffic_rate, batch_size) VALUES (?, ?, ?)",
            ("stopped", 10.0, 100)
        )
        conn.commit()
        print("  Seeded system status.")
    conn.close()
    


def main():
    """Main function."""
    create_database()
    seed_default_model()
    seed_demo_data()
    verify_tables()
    seed_system_status()


if __name__ == "__main__":
    main()