"""
Controlled Kafka Producer for BI-Safe
======================================

Reads the system_status row from the database before each event
and obeys the producer_status:
  - running: sends at traffic_rate events per second
  - paused:  sleeps and re-checks
  - stopped: exits cleanly

Requirements:
    pip install pandas kafka-python

Run:
    python scripts/producer_controlled.py
"""

import os
import sys
import json
import time
import sqlite3
import pandas as pd
from kafka import KafkaProducer
from kafka.errors import KafkaError

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(BASE_DIR, "database", "bi_safe.db")

KAFKA_BROKER = "localhost:9092"
KAFKA_TOPIC = "network-traffic"
STATUS_POLL_SECONDS = 0.5


def read_status():
    """Read producer_status, traffic_rate, batch_size from the database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT producer_status, traffic_rate, batch_size "
        "FROM system_status ORDER BY id DESC LIMIT 1"
    )
    row = cursor.fetchone()
    conn.close()
    if not row:
        return "stopped", 10.0, 100
    return row[0], float(row[1]), int(row[2])


def set_status(status):
    """Update producer_status in the database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE system_status SET producer_status = ?, "
        "last_updated = CURRENT_TIMESTAMP "
        "WHERE id = (SELECT MAX(id) FROM system_status)",
        (status,)
    )
    conn.commit()
    conn.close()


def create_producer():
    try:
        return KafkaProducer(
            bootstrap_servers=[KAFKA_BROKER],
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            key_serializer=lambda k: str(k).encode("utf-8") if k is not None else None,
            api_version=(0, 10, 1),
            request_timeout_ms=5000,
        )
    except KafkaError as e:
        print(f"ERROR: Cannot connect to Kafka: {e}")
        return None


def stream(df, producer):
    """Stream rows one by one, obeying the current status."""
    sent = 0
    total = len(df)

    for i, (_, row) in enumerate(df.iterrows()):
        status, rate, batch_size = read_status()

        while status == "paused":
            time.sleep(STATUS_POLL_SECONDS)
            status, rate, batch_size = read_status()

        if status == "stopped":
            print(f"\n[Producer] Stopped by admin after {sent} events.")
            return sent

        if i >= batch_size:
            print(f"\n[Producer] Reached batch size ({batch_size}). Stopping.")
            set_status("stopped")
            return sent

        event = row.to_dict()
        for k, v in event.items():
            if pd.isna(v):
                event[k] = None

        producer.send(KAFKA_TOPIC, key=i, value=event)
        sent += 1

        if sent % 100 == 0:
            print(f"[Producer] Sent {sent} events (rate={rate}/sec)")

        time.sleep(1.0 / rate if rate > 0 else 0.1)

    print(f"\n[Producer] Done. Total sent: {sent}")
    set_status("stopped")
    return sent


def main():
    print("=" * 60)
    print("BI-Safe Controlled Producer")
    print("=" * 60)

    filepath = os.path.join(DATA_DIR, "preprocessed_small_test.csv")
    if not os.path.exists(filepath):
        print(f"ERROR: {filepath} not found.")
        return

    df = pd.read_csv(filepath)
    print(f"Loaded {len(df)} events from {filepath}")

    producer = create_producer()
    if not producer:
        return

    try:
        stream(df, producer)
    except KeyboardInterrupt:
        print("\n[Producer] Interrupted by user.")
    finally:
        producer.flush()
        producer.close()


if __name__ == "__main__":
    main()