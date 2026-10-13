"""
API-based Kafka consumer for BI-Safe.

Reads RAW events from the topic 'network-traffic-raw', sends each one to
the anomaly API (the fitted Pipeline does all preprocessing), and saves
the result with the same insert_prediction() used by scripts/consumer.py.

The API returns anomaly_score where HIGHER = MORE ANOMALOUS. The old
consumer stored decision_function where HIGHER = MORE NORMAL, so the
sign is flipped before saving to keep the database meaning unchanged.

Run (the API must be running in another terminal):
    python scripts/consumer_api.py --dry-run     (no Kafka, no database)
    python scripts/consumer_api.py               (full run)
"""

import argparse
import json
import os
import sys
import time

import pandas as pd
import requests

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_DIR = os.path.join(BASE_DIR, "results")

API_BASE = "http://127.0.0.1:5002"
API_URL = f"{API_BASE}/api/v1/models/anomaly-detector/predictions"
HEALTH_URL = f"{API_BASE}/health"

KAFKA_BROKER = "localhost:9092"
KAFKA_TOPIC = "network-traffic-raw"
CONSUMER_GROUP = "bi-safe-consumer-api"

TARGET_COLUMN = "is_attack"
FEATURE_COLUMNS = [
    "protocol",
    "service",
    "source_port",
    "destination_port",
    "duration",
    "bytes_sent",
    "bytes_received",
    "packets_sent",
    "packets_received",
    "packet_size",
    "tcp_flags",
]
MAX_CONSECUTIVE_ERRORS = 5


def api_is_up():
    try:
        return requests.get(HEALTH_URL, timeout=3).ok
    except requests.RequestException:
        return False


def score_event(event):
    """Send one raw event to the API. Returns (is_anomaly, db_score, ms)."""
    payload = {k: event.get(k) for k in FEATURE_COLUMNS}
    start = time.time()
    response = requests.post(API_URL, json=payload, timeout=5)
    response.raise_for_status()
    ms = round((time.time() - start) * 1000, 2)

    prediction = response.json()["predictions"][0]
    is_anomaly = 1 if prediction["is_anomaly"] else 0
    db_score = -prediction["anomaly_score"]  # flip to the old meaning
    return is_anomaly, db_score, ms


def dry_run(n=5):
    path = os.path.join(BASE_DIR, "data", "synthetic", "synthetic_small.csv")
    df = pd.read_csv(path).head(n)
    print(f"Scoring {n} events through the API (no Kafka, no database)\n")
    for i, row in df.iterrows():
        event = {k: (None if pd.isna(v) else v) for k, v in row.to_dict().items()}
        # numpy ints/floats -> plain Python so they are JSON-safe
        event = {k: (v.item() if hasattr(v, "item") else v) for k, v in event.items()}
        is_anomaly, db_score, ms = score_event(event)
        print(
            f"event {i}: actual={event[TARGET_COLUMN]} "
            f"predicted={is_anomaly} db_score={db_score:.4f} ({ms} ms)"
        )


def run(max_events, topic=KAFKA_TOPIC):
    from kafka import KafkaConsumer

    sys.path.insert(0, os.path.join(BASE_DIR, "app"))
    from db import clear_predictions_and_alerts, insert_prediction

    clear = input("Clear existing predictions and alerts? (y/n): ").strip().lower()
    if clear == "y":
        clear_predictions_and_alerts()
        print("  Cleared existing data.")

    consumer = KafkaConsumer(
        topic,
        bootstrap_servers=[KAFKA_BROKER],
        group_id=CONSUMER_GROUP,
        auto_offset_reset="earliest",
        enable_auto_commit=True,
        value_deserializer=lambda v: json.loads(v.decode("utf-8")),
        api_version=(0, 10, 1),
        consumer_timeout_ms=10000,
    )
    print(f"Connected to Kafka topic '{topic}'. Ctrl+C to stop.\n")

    results = []
    processed = anomalies = errors_in_a_row = 0
    start = time.time()

    try:
        for message in consumer:
            event = message.value
            try:
                is_anomaly, db_score, ms = score_event(event)
                errors_in_a_row = 0
            except (requests.RequestException, KeyError, ValueError) as exc:
                errors_in_a_row += 1
                print(f"  [API Error] offset {message.offset}: {exc}")
                if errors_in_a_row >= MAX_CONSECUTIVE_ERRORS:
                    print("Too many consecutive API errors. Is the API running? Stopping.")
                    break
                continue

            anomalies += is_anomaly
            try:
                insert_prediction(
                    offset=message.offset,
                    anomaly_score=db_score,
                    is_anomaly=is_anomaly,
                    actual=event.get(TARGET_COLUMN),
                    processing_time_ms=ms,
                )
            except Exception as exc:
                print(f"  [DB Error] Could not save prediction: {exc}")

            results.append(
                {
                    "offset": message.offset,
                    "prediction": is_anomaly,
                    "anomaly_score": db_score,
                    "actual": event.get(TARGET_COLUMN),
                }
            )
            processed += 1
            if processed % 100 == 0:
                rate = processed / (time.time() - start)
                print(f"  Processed {processed:,} | Anomalies: {anomalies:,} | {rate:.1f}/sec")
            if max_events and processed >= max_events:
                break
    except KeyboardInterrupt:
        print("\n  Stopped by user.")
    finally:
        consumer.close()

    print(f"\nDone. Processed {processed:,}, anomalies {anomalies:,}.")
    if results:
        os.makedirs(RESULTS_DIR, exist_ok=True)
        out = os.path.join(RESULTS_DIR, "consumer_api_results.csv")
        pd.DataFrame(results).to_csv(out, index=False)
        print(f"Results saved to: {out}")


def main():
    parser = argparse.ArgumentParser(description="BI-Safe API-based consumer.")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--topic", default=KAFKA_TOPIC)
    parser.add_argument("--max-events", type=int, default=1000)
    args = parser.parse_args()

    if not api_is_up():
        print(f"ERROR: API not reachable at {API_BASE}.")
        print("Start it in another terminal:  python -m api.anomaly_api")
        return

    if args.dry_run:
        dry_run()
    else:
        run(args.max_events, args.topic)


if __name__ == "__main__":
    main()