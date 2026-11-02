"""
Live consumer for BI-Safe (started by the admin dashboard).

Reads RAW events from 'network-traffic-raw', scores each one through the
anomaly API, saves the prediction, and creates an alert for flagged events.
It only reads NEW events (it starts at the end of the topic), never clears
any data, and exits when the producer status is 'stopped' and the topic is
drained.

Test by hand (API and Kafka must be running):
    python scripts/consumer_service.py
"""

import json
import os
import sqlite3
import sys
import time
from datetime import datetime

import requests

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, "app"))
from db import insert_prediction  # noqa: E402

DB_PATH = os.path.join(BASE_DIR, "database", "bi_safe.db")
API_URL = "http://127.0.0.1:5002/api/v1/models/anomaly-detector/predictions"
KAFKA_BROKER = "localhost:9092"
KAFKA_TOPIC = "network-traffic-raw"
SME_ID = 1  # the simulated traffic belongs to this SME

HIGH_THRESHOLD = -0.05
MEDIUM_THRESHOLD = -0.03

FEATURES = [
    "protocol", "service", "source_port", "destination_port", "duration",
    "bytes_sent", "bytes_received", "packets_sent", "packets_received",
    "packet_size", "tcp_flags",
]


def read_status():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    row = conn.execute(
        "SELECT producer_status FROM system_status ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()
    return row[0] if row else "stopped"


def get_priority(score):
    if score < HIGH_THRESHOLD:
        return "HIGH"
    if score < MEDIUM_THRESHOLD:
        return "MEDIUM"
    return "LOW"


def save_alert(offset, score, actual):
    priority = get_priority(score)
    message = (
        f"BI-SAFE {priority} PRIORITY ALERT | Anomaly score: {score:.4f} | "
        f"Review your dashboard."
    )
    conn = sqlite3.connect(DB_PATH, timeout=10)
    cur = conn.execute(
        "INSERT INTO alerts (sme_id, message, priority, timestamp, offset, "
        "anomaly_score, actual, status) VALUES (?, ?, ?, ?, ?, ?, ?, 'Pending')",
        (SME_ID, message, priority, datetime.now().isoformat(timespec="seconds"),
         offset, score, actual),
    )
    conn.execute("UPDATE alerts SET alert_id = ? WHERE id = ?", (cur.lastrowid, cur.lastrowid))
    conn.commit()
    conn.close()
    return priority


def score_event(event):
    payload = {k: event.get(k) for k in FEATURES}
    start = time.time()
    response = requests.post(API_URL, json=payload, timeout=5)
    response.raise_for_status()
    ms = round((time.time() - start) * 1000, 2)
    prediction = response.json()["predictions"][0]
    # The API says higher = more anomalous. The database keeps the old
    # meaning (higher = more normal), so flip the sign.
    return (1 if prediction["is_anomaly"] else 0), -prediction["anomaly_score"], ms


def main():
    from kafka import KafkaConsumer, TopicPartition

    consumer = KafkaConsumer(
        bootstrap_servers=[KAFKA_BROKER],
        enable_auto_commit=False,
        value_deserializer=lambda v: json.loads(v.decode("utf-8")),
        api_version=(0, 10, 1),
    )
    partition = TopicPartition(KAFKA_TOPIC, 0)
    consumer.assign([partition])
    consumer.seek_to_end(partition)
    position = consumer.position(partition)
    print(f"[Consumer] Listening on '{KAFKA_TOPIC}' from offset {position}. Waiting for events...")

    processed = anomalies = skipped = 0
    try:
        while True:
            batch = consumer.poll(timeout_ms=1000, max_records=50)
            records = batch.get(partition, [])
            if not records:
                if read_status() == "stopped":
                    break
                continue
            for message in records:
                event = message.value
                if "protocol" not in event or "service" not in event:
                    skipped += 1
                    print(f"[Consumer] Skipped offset {message.offset}: not a raw event")
                    continue
                try:
                    is_anomaly, score, ms = score_event(event)
                except (requests.RequestException, KeyError, ValueError) as exc:
                    print(f"[Consumer] API problem ({exc}). Retrying in 3 seconds...")
                    consumer.seek(partition, message.offset)
                    time.sleep(3)
                    break
                actual = event.get("is_attack")
                insert_prediction(
                    offset=message.offset, anomaly_score=score, is_anomaly=is_anomaly,
                    actual=actual, processing_time_ms=ms,
                )
                if is_anomaly:
                    anomalies += 1
                    save_alert(message.offset, score, actual)
                processed += 1
                if processed % 25 == 0:
                    print(f"[Consumer] Processed {processed} | flagged {anomalies}")
    except KeyboardInterrupt:
        print("[Consumer] Interrupted.")
    finally:
        consumer.close()
        print(f"[Consumer] Done. Processed {processed}, flagged {anomalies}, skipped {skipped}.")


if __name__ == "__main__":
    main()
