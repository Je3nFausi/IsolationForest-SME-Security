"""
Raw-data Kafka producer for BI-Safe.

Streams RAW events (unscaled, with protocol/service/tcp_flags) from
data/synthetic/synthetic_<size>.csv to the topic 'network-traffic-raw'.
The original scripts/producer.py is not affected.

Run:
    python scripts/producer_raw.py
    python scripts/producer_raw.py --dry-run     (no Kafka needed)
"""

import argparse
import json
import os
import time

import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data", "synthetic")

KAFKA_BROKER = "localhost:9092"
KAFKA_TOPIC = "network-traffic-raw"

# The 11 fields the API expects, plus the label (kept for evaluation only).
EVENT_COLUMNS = [
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
    "is_attack",
]


def load_events(size):
    path = os.path.join(DATA_DIR, f"synthetic_{size}.csv")
    if not os.path.exists(path):
        raise FileNotFoundError(f"Not found: {path}")
    df = pd.read_csv(path)[EVENT_COLUMNS]
    events = df.to_dict(orient="records")  # plain Python types, JSON-safe
    for event in events:
        for key, value in event.items():
            if pd.isna(value):
                event[key] = None
    return events


def main():
    parser = argparse.ArgumentParser(description="Stream raw events to Kafka.")
    parser.add_argument("--size", choices=["small", "medium", "large"], default="small")
    parser.add_argument("--max-events", type=int, default=1000)
    parser.add_argument("--delay", type=float, default=0.01)
    parser.add_argument("--topic", default=KAFKA_TOPIC)
    parser.add_argument("--dry-run", action="store_true",
                        help="Print the first 2 events and exit (no Kafka).")
    args = parser.parse_args()

    events = load_events(args.size)[: args.max_events]
    print(f"Loaded {len(events):,} raw events")

    if args.dry_run:
        for event in events[:2]:
            print(json.dumps(event))
        return

    from kafka import KafkaProducer

    producer = KafkaProducer(
        bootstrap_servers=[KAFKA_BROKER],
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        api_version=(0, 10, 1),
        request_timeout_ms=5000,
    )
    print(f"Connected to Kafka. Streaming to topic '{args.topic}'...")

    start = time.time()
    for i, event in enumerate(events):
        producer.send(args.topic, value=event)
        if (i + 1) % 100 == 0:
            print(f"  Sent {i + 1:,} events")
        time.sleep(args.delay)

    producer.flush()
    producer.close()
    print(f"Done: {len(events):,} events in {time.time() - start:.1f}s")


if __name__ == "__main__":
    main()