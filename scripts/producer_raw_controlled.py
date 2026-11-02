"""
Controlled raw producer for BI-Safe (started by the admin dashboard).

Streams the HELD-OUT 20% test split of data/synthetic/synthetic_<size>.csv
(rows the model never trained on) to the topic 'network-traffic-raw'.
Before every event it reads system_status from the database:
    running -> send at traffic_rate events per second
    paused  -> wait and check again
    stopped -> exit
It also stops by itself after batch_size events.

Test by hand:
    python scripts/producer_raw_controlled.py
"""

import json
import os
import sqlite3
import time

import pandas as pd
from sklearn.model_selection import train_test_split

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "database", "bi_safe.db")
CURSOR_FILE = os.path.join(BASE_DIR, "results", "producer_cursor.txt")
MODEL_SIZE = os.environ.get("BISAFE_MODEL_SIZE", "small")
DATA_FILE = os.path.join(BASE_DIR, "data", "synthetic", f"synthetic_{MODEL_SIZE}.csv")

KAFKA_BROKER = "localhost:9092"
KAFKA_TOPIC = "network-traffic-raw"
POLL_SECONDS = 0.5
RANDOM_STATE = 42  # must match ml_pipeline/train_anomaly_pipeline.py

FEATURES = [
    "protocol", "service", "source_port", "destination_port", "duration",
    "bytes_sent", "bytes_received", "packets_sent", "packets_received",
    "packet_size", "tcp_flags",
]
LABEL = "is_attack"


def read_status():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    row = conn.execute(
        "SELECT producer_status, traffic_rate, batch_size "
        "FROM system_status ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()
    if not row:
        return "stopped", 10.0, 100
    return row[0], float(row[1] or 10.0), int(row[2] or 100)


def set_status(status):
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute(
        "UPDATE system_status SET producer_status = ?, last_updated = CURRENT_TIMESTAMP "
        "WHERE id = (SELECT MAX(id) FROM system_status)",
        (status,),
    )
    conn.commit()
    conn.close()


def read_cursor():
    try:
        with open(CURSOR_FILE) as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return 0


def write_cursor(value):
    os.makedirs(os.path.dirname(CURSOR_FILE), exist_ok=True)
    with open(CURSOR_FILE, "w") as f:
        f.write(str(value))


def load_events():
    """Rebuild the held-out test split used when the model was trained."""
    df = pd.read_csv(DATA_FILE)
    X = df[FEATURES]
    y = df[LABEL]
    _, X_test, _, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=RANDOM_STATE
    )
    test = X_test.copy()
    test[LABEL] = y_test
    events = test.to_dict(orient="records")
    for event in events:
        for key, value in event.items():
            if pd.isna(value):
                event[key] = None
    return events


def main():
    print("=" * 50)
    print(f"BI-Safe controlled producer (model size: {MODEL_SIZE})")
    print("=" * 50)
    events = load_events()
    total = len(events)
    start = read_cursor() % total
    print(f"{total} held-out events available, starting at position {start}")

    from kafka import KafkaProducer

    producer = KafkaProducer(
        bootstrap_servers=[KAFKA_BROKER],
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        api_version=(0, 10, 1),
        request_timeout_ms=5000,
    )

    sent = 0
    try:
        while True:
            status, rate, batch_size = read_status()
            while status == "paused":
                time.sleep(POLL_SECONDS)
                status, rate, batch_size = read_status()
            if status == "stopped":
                print(f"[Producer] Stopped by admin after {sent} events.")
                break
            if sent >= batch_size:
                print(f"[Producer] Batch of {batch_size} complete.")
                set_status("stopped")
                break
            producer.send(KAFKA_TOPIC, value=events[(start + sent) % total])
            sent += 1
            if sent % 25 == 0:
                print(f"[Producer] Sent {sent} events (rate {rate}/sec)")
            time.sleep(1.0 / rate if rate > 0 else 0.1)
    except KeyboardInterrupt:
        print("[Producer] Interrupted.")
    finally:
        producer.flush()
        producer.close()
        write_cursor(start + sent)
        print(f"[Producer] Done. Total sent: {sent}")


if __name__ == "__main__":
    main()
