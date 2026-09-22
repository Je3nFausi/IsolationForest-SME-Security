"""
Kafka Producer for BI-Safe
===========================

This script reads network traffic data from CSV files and streams it
to a Kafka topic in real time.

It simulates live network traffic for the consumer to process.

Requirements:
    pip install pandas kafka-python

Run:
    python scripts/producer.py
"""

import os
import json
import time
import pandas as pd
from kafka import KafkaProducer
from kafka.errors import KafkaError


# Get the project root directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")


# Kafka configuration
KAFKA_BROKER = "localhost:9092"
KAFKA_TOPIC = "network-traffic"

# Producer configuration
DEFAULT_DELAY = 0.01       # Seconds between events
MAX_EVENTS = 1000          # Maximum events to stream (set to None for all)


def create_kafka_producer():
    """Create and return a Kafka producer."""
    try:
        producer = KafkaProducer(
            bootstrap_servers=[KAFKA_BROKER],
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            key_serializer=lambda k: str(k).encode("utf-8") if k else None,
            api_version=(0, 10, 1),
            request_timeout_ms=5000,
        )
        print(f"Connected to Kafka broker at {KAFKA_BROKER}")
        return producer
    except KafkaError as e:
        print(f"ERROR: Could not connect to Kafka at {KAFKA_BROKER}")
        print(f"Details: {e}")
        print("Make sure Zookeeper and Kafka are running.")
        return None


def load_data(filepath):
    """Load the dataset to stream."""
    print(f"Loading {filepath}...")
    df = pd.read_csv(filepath)
    print(f"  Loaded {len(df):,} rows")
    return df


def stream_events(producer, df, delay=DEFAULT_DELAY, max_events=MAX_EVENTS):
    """Stream events to Kafka one by one."""
    total = len(df) if max_events is None else min(max_events, len(df))
    print(f"\nStreaming {total:,} events to topic '{KAFKA_TOPIC}'...")
    print(f"  Delay: {delay}s between events")
    print(f"  Press Ctrl+C to stop\n")

    start_time = time.time()
    i = 0

    try:
        for i, (_, row) in enumerate(df.iterrows()):
            if max_events is not None and i >= max_events:
                break

            event = row.to_dict()

            # Ensure all values are JSON-serialisable
            for key, value in event.items():
                if pd.isna(value):
                    event[key] = None

            # Send to Kafka
            producer.send(KAFKA_TOPIC, key=i, value=event)

            # Progress
            if (i + 1) % 100 == 0:
                elapsed = time.time() - start_time
                rate = (i + 1) / elapsed
                print(f"  Sent {i + 1:,} events ({rate:.1f} events/sec)")

            time.sleep(delay)

    except KeyboardInterrupt:
        print("\n  Streaming stopped by user.")

    finally:
        producer.flush()
        elapsed = time.time() - start_time
        print(f"\n  Total events sent: {i + 1:,}")
        print(f"  Total time: {elapsed:.2f} seconds")


def main():
    """Main function to run the producer."""
    # Load data
    filepath = os.path.join(DATA_DIR, "preprocessed_small_test.csv")
    if not os.path.exists(filepath):
        print(f"ERROR: {filepath} not found.")
        print("Make sure Phase 2 (preprocessing) is complete.")
        return

    df = load_data(filepath)

    # Create producer
    producer = create_kafka_producer()
    if not producer:
        return

    # Stream events
    stream_events(producer, df)

    # Close producer
    producer.close()
    print("\n  Producer closed.")


if __name__ == "__main__":
    main()