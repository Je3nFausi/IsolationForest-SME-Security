"""
Database Setup for BI-Safe
==========================

This script creates the SQLite database and tables for storing
predictions and alerts from the anomaly detection pipeline.

Requirements:
    pip install pandas

Run:
    python database/db_setup.py
"""

import os
import sqlite3
import pandas as pd
import json


# Get the project root directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATABASE_DIR = os.path.join(BASE_DIR, "database")
RESULTS_DIR = os.path.join(BASE_DIR, "results")


# Database path
DB_PATH = os.path.join(DATABASE_DIR, "bi_safe.db")


# SQL statements
CREATE_PREDICTIONS_TABLE = """
CREATE TABLE IF NOT EXISTS predictions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    offset INTEGER,
    prediction INTEGER,
    anomaly_score REAL,
    actual INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""

CREATE_ALERTS_TABLE = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER,
    timestamp TEXT,
    offset INTEGER,
    anomaly_score REAL,
    actual INTEGER,
    priority TEXT,
    message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""


def create_database():
    """Create the database and tables."""
    os.makedirs(DATABASE_DIR, exist_ok=True)

    print(f"Creating database at {DB_PATH}...")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(CREATE_PREDICTIONS_TABLE)
    print("  Created table: predictions")

    cursor.execute(CREATE_ALERTS_TABLE)
    print("  Created table: alerts")

    conn.commit()
    conn.close()
    print("  Database setup complete.")


def insert_predictions():
    """Insert consumer results into the predictions table."""
    results_file = os.path.join(RESULTS_DIR, "consumer_results.csv")
    if not os.path.exists(results_file):
        print(f"WARNING: {results_file} not found. Skipping predictions.")
        return

    print(f"\nLoading {results_file}...")
    df = pd.read_csv(results_file)
    print(f"  Loaded {len(df):,} rows")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Clear existing data
    cursor.execute("DELETE FROM predictions")

    # Insert rows
    for _, row in df.iterrows():
        cursor.execute(
            "INSERT INTO predictions (offset, prediction, anomaly_score, actual) VALUES (?, ?, ?, ?)",
            (
                int(row["offset"]),
                int(row["prediction"]),
                float(row["anomaly_score"]),
                int(row["actual"]) if pd.notna(row["actual"]) else None,
            ),
        )

    conn.commit()
    conn.close()
    print(f"  Inserted {len(df):,} predictions.")


def insert_alerts():
    """Insert alerts into the alerts table."""
    alerts_file = os.path.join(RESULTS_DIR, "alert_history.json")
    if not os.path.exists(alerts_file):
        print(f"WARNING: {alerts_file} not found. Skipping alerts.")
        return

    print(f"\nLoading {alerts_file}...")
    with open(alerts_file, "r") as f:
        alerts = json.load(f)
    print(f"  Loaded {len(alerts):,} alerts")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Clear existing data
    cursor.execute("DELETE FROM alerts")

    # Insert rows
    for alert in alerts:
        cursor.execute(
            "INSERT INTO alerts (alert_id, timestamp, offset, anomaly_score, actual, priority, message) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                int(alert["alert_id"]),
                alert["timestamp"],
                int(alert["offset"]),
                float(alert["anomaly_score"]),
                int(alert["actual"]) if alert["actual"] is not None else None,
                alert["priority"],
                alert["message"],
            ),
        )

    conn.commit()
    conn.close()
    print(f"  Inserted {len(alerts):,} alerts.")


def query_summary():
    """Print a summary of the database contents."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    print(f"\n{'='*60}")
    print("Database Summary")
    print(f"{'='*60}")

    cursor.execute("SELECT COUNT(*) FROM predictions")
    print(f"  Predictions:  {cursor.fetchone()[0]:,}")

    cursor.execute("SELECT COUNT(*) FROM predictions WHERE prediction = 1")
    print(f"  Anomalies:    {cursor.fetchone()[0]:,}")

    cursor.execute("SELECT COUNT(*) FROM alerts")
    print(f"  Alerts:       {cursor.fetchone()[0]:,}")

    cursor.execute("SELECT priority, COUNT(*) FROM alerts GROUP BY priority")
    print(f"\n  Alerts by priority:")
    for priority, count in cursor.fetchall():
        print(f"    {priority}: {count}")

    conn.close()
    print(f"{'='*60}")


def main():
    """Main function to set up and populate the database."""
    create_database()
    insert_predictions()
    insert_alerts()
    query_summary()


if __name__ == "__main__":
    main()