"""
Write BI-Safe alerts to the database so the dashboard shows them.

Reads results/consumer_api_results.csv, keeps rows flagged as anomalies,
assigns a priority from the anomaly score, and saves each one with the
existing insert_alert() from app/db.py.

Score convention (same as the old consumer): HIGHER = MORE NORMAL, so
anomalies have NEGATIVE scores and a MORE NEGATIVE score is more severe.

Thresholds were calibrated on the small dataset (106 flagged events:
median -0.012, minimum -0.066). Re-check them for medium and large.

Run:
    python scripts/alert_to_db.py --dry-run
    python scripts/alert_to_db.py
"""

import argparse
import os
import sqlite3
import sys
from datetime import datetime

import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_FILE = os.path.join(BASE_DIR, "results", "consumer_api_results.csv")
DB_PATH = os.path.join(BASE_DIR, "database", "bi_safe.db")

HIGH_THRESHOLD = -0.05
MEDIUM_THRESHOLD = -0.03


def get_priority(score):
    if score < HIGH_THRESHOLD:
        return "HIGH"
    if score < MEDIUM_THRESHOLD:
        return "MEDIUM"
    return "LOW"


def build_message(priority, score):
    return (
        f"BI-SAFE {priority} PRIORITY ALERT | "
        f"Time: {datetime.now().isoformat(timespec='seconds')} | "
        f"Anomaly score: {score:.4f} | "
        f"Review your dashboard."
    )


def main():
    parser = argparse.ArgumentParser(description="Write alerts to the database.")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if not os.path.exists(RESULTS_FILE):
        print(f"ERROR: {RESULTS_FILE} not found. Run consumer_api.py first.")
        return

    df = pd.read_csv(RESULTS_FILE)
    flagged = df[df["prediction"] == 1].copy()
    flagged["priority"] = flagged["anomaly_score"].apply(get_priority)
    counts = flagged["priority"].value_counts()

    print(f"Flagged events: {len(flagged)}")
    print(f"  HIGH:   {counts.get('HIGH', 0)}")
    print(f"  MEDIUM: {counts.get('MEDIUM', 0)}")
    print(f"  LOW:    {counts.get('LOW', 0)}")

    if args.dry_run:
        print("\nDry run: nothing written.")
        return

    sys.path.insert(0, os.path.join(BASE_DIR, "app"))
    from db import insert_alert

    conn = sqlite3.connect(DB_PATH)
    existing = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    conn.close()
    if existing:
        answer = input(f"alerts table has {existing} rows. Delete them first? (y/n): ")
        if answer.strip().lower() == "y":
            conn = sqlite3.connect(DB_PATH)
            conn.execute("DELETE FROM alerts")
            conn.commit()
            conn.close()
            print("  Cleared alerts table.")

    written = 0
    for i, (_, row) in enumerate(flagged.iterrows(), start=1):
        actual = None if pd.isna(row["actual"]) else int(row["actual"])
        insert_alert(
            alert_id=i,
            offset=int(row["offset"]),
            anomaly_score=float(row["anomaly_score"]),
            priority=row["priority"],
            message=build_message(row["priority"], row["anomaly_score"]),
            actual=actual,
        )
        written += 1

    print(f"\nWrote {written} alerts to the database.")


if __name__ == "__main__":
    main()