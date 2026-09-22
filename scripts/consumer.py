"""
Kafka Consumer for BI-Safe
===========================

This script consumes network traffic events from a Kafka topic and
runs real-time anomaly detection using the trained Isolation Forest model.

Requirements:
    pip install pandas numpy scikit-learn joblib kafka-python

Run:
    python scripts/consumer.py
"""

import os
import json
import time
import joblib
import pandas as pd
import numpy as np
from kafka import KafkaConsumer


# Get the project root directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
MODEL_DIR = os.path.join(BASE_DIR, "models")
RESULTS_DIR = os.path.join(BASE_DIR, "results")


# Kafka configuration
KAFKA_BROKER = "localhost:9092"
KAFKA_TOPIC = "network-traffic"
CONSUMER_GROUP = "bi-safe-consumer"


# Target column
TARGET_COLUMN = "is_attack"


def load_model(model_path):
    """Load the trained Isolation Forest model."""
    print(f"Loading model from {model_path}...")
    model = joblib.load(model_path)
    print(f"  Model loaded successfully")
    return model


def create_kafka_consumer():
    """Create and return a Kafka consumer."""
    try:
        consumer = KafkaConsumer(
            KAFKA_TOPIC,
            bootstrap_servers=[KAFKA_BROKER],
            group_id=CONSUMER_GROUP,
            auto_offset_reset="earliest",
            enable_auto_commit=True,
            value_deserializer=lambda v: json.loads(v.decode("utf-8")),
            api_version=(0, 10, 1),
            consumer_timeout_ms=10000,
        )
        print(f"Connected to Kafka topic '{KAFKA_TOPIC}'")
        return consumer
    except Exception as e:
        print(f"ERROR: Could not connect to Kafka.")
        print(f"Details: {e}")
        return None


def detect_anomaly(model, event):
    """Run anomaly detection on a single event."""
    # Extract features (drop target and label columns)
    features = {
        k: v for k, v in event.items()
        if k not in [TARGET_COLUMN, "prediction", "anomaly_score"]
    }
    X = pd.DataFrame([features])

    # Ensure all values are numeric
    X = X.select_dtypes(include=[np.number])

    # Predict
    prediction = model.predict(X)[0]
    score = model.decision_function(X)[0]

    # Convert: Isolation Forest returns 1=normal, -1=anomaly
    is_anomaly = 1 if prediction == -1 else 0

    return is_anomaly, score


def consume_events(consumer, model, max_events=None):
    """Consume events from Kafka and detect anomalies."""
    print(f"\nConsuming events from topic '{KAFKA_TOPIC}'...")
    print(f"  Press Ctrl+C to stop\n")

    results = []
    processed = 0
    anomalies = 0

    start_time = time.time()

    try:
        for message in consumer:
            event = message.value

            # Detect anomaly
            is_anomaly, score = detect_anomaly(model, event)

            if is_anomaly:
                anomalies += 1

            # Save result
            results.append({
                "offset": message.offset,
                "prediction": is_anomaly,
                "anomaly_score": score,
                "actual": event.get(TARGET_COLUMN, None),
            })

            processed += 1

            # Progress
            if processed % 100 == 0:
                elapsed = time.time() - start_time
                rate = processed / elapsed
                print(f"  Processed {processed:,} events | Anomalies: {anomalies:,} | Rate: {rate:.1f}/sec")

            if max_events and processed >= max_events:
                break

    except KeyboardInterrupt:
        print("\n  Consumer stopped by user.")

    finally:
        consumer.close()

    elapsed = time.time() - start_time
    print(f"\n{'='*60}")
    print(f"Consumption complete in {elapsed:.2f} seconds")
    print(f"Total processed: {processed:,}")
    print(f"Total anomalies: {anomalies:,}")
    if elapsed > 0:
        print(f"Throughput: {processed/elapsed:.1f} events/sec")
    print(f"{'='*60}")

    return results


def save_results(results):
    """Save the consumer results to CSV."""
    if not results:
        print("  No results to save.")
        return

    os.makedirs(RESULTS_DIR, exist_ok=True)
    df = pd.DataFrame(results)
    output_file = os.path.join(RESULTS_DIR, "consumer_results.csv")
    df.to_csv(output_file, index=False)
    print(f"\n  Results saved to: {output_file}")


def main():
    """Main function to run the consumer."""
    # Load model
    model_path = os.path.join(MODEL_DIR, "isolation_forest_small.pkl")
    if not os.path.exists(model_path):
        print(f"ERROR: Model not found at {model_path}")
        print("Make sure Phase 3 (model training) is complete.")
        return

    model = load_model(model_path)

    # Create consumer
    consumer = create_kafka_consumer()
    if not consumer:
        return

    # Consume events
    results = consume_events(consumer, model, max_events=1000)

    # Save results
    save_results(results)


if __name__ == "__main__":
    main()