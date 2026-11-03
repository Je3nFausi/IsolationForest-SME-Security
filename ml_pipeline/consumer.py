"""
consumer.py — Reads network events from Kafka, scores them with the trained
Isolation Forest, prints a terminal alert on anomalies, AND inserts each
prediction into PostgreSQL (bi_safe.predictions).

Uses the CALIBRATED threshold from Step 1 (small-tier): +0.1056.
Flags an event as anomaly when decision_function(score) < THRESHOLD.

No email, no feedback, no recommendations yet — those are later steps.
DB write is the ONLY addition vs Step 2.

Usage (from project root):
    python ml_pipeline/consumer.py

Stop with Ctrl+C.
"""
import argparse
import json
import sys
from pathlib import Path

import numpy as np
from joblib import load
from kafka import KafkaConsumer

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from database.db import get_connection

MODEL_DIR = PROJECT_ROOT / "models"
THRESHOLD = 0.1056

INSERT_SQL = """
INSERT INTO predictions (
    event_id, timestamp, score, is_anomaly, ground_truth,
    source_port, destination_port, duration,
    bytes_sent, bytes_received, packets_sent, packets_received, packet_size,
    flow_bytes_per_s, flow_packets_per_s,
    syn_flag_count, ack_flag_count, psh_flag_count,
    fwd_packet_len_std, bwd_packet_len_std,
    avg_packet_size, down_up_ratio,
    init_win_bytes_fwd, flow_iat_mean, flow_iat_std
) VALUES (
    %(event_id)s, %(timestamp)s, %(score)s, %(is_anomaly)s, %(ground_truth)s,
    %(source_port)s, %(destination_port)s, %(duration)s,
    %(bytes_sent)s, %(bytes_received)s, %(packets_sent)s, %(packets_received)s, %(packet_size)s,
    %(flow_bytes_per_s)s, %(flow_packets_per_s)s,
    %(syn_flag_count)s, %(ack_flag_count)s, %(psh_flag_count)s,
    %(fwd_packet_len_std)s, %(bwd_packet_len_std)s,
    %(avg_packet_size)s, %(down_up_ratio)s,
    %(init_win_bytes_fwd)s, %(flow_iat_mean)s, %(flow_iat_std)s
)
"""


def main():
    parser = argparse.ArgumentParser(description="Score Kafka events + persist to DB")
    parser.add_argument("--broker", default="localhost:9092")
    parser.add_argument("--topic", default="network-events")
    parser.add_argument("--group", default="anomaly-scorer-v2")
    args = parser.parse_args()

    print("Loading model, scaler, feature list...")
    with open(MODEL_DIR / "feature_cols.json") as f:
        feature_cols = json.load(f)
    model = load(MODEL_DIR / "if_contam_0_05.joblib")
    scaler = load(MODEL_DIR / "scaler.joblib")
    print(f"Loaded model with {len(feature_cols)} features")
    print(f"Threshold: {THRESHOLD:+.4f}")

    print("Connecting to PostgreSQL...")
    conn = get_connection()
    print("DB connected.")

    print(f"Listening on '{args.topic}' at {args.broker}...\n")

    consumer = KafkaConsumer(
        args.topic,
        bootstrap_servers=[args.broker],
        group_id=args.group,
        value_deserializer=lambda m: json.loads(m.decode("utf-8")),
        auto_offset_reset="latest",
        enable_auto_commit=True,
    )

    seen = 0
    flagged = 0
    db_errors = 0
    try:
        for msg in consumer:
            event = msg.value
            seen += 1
            try:
                X = np.array([[float(event[c]) for c in feature_cols]])
            except (KeyError, TypeError, ValueError) as e:
                print(f"[{seen:5d}] SKIP malformed event: {e}")
                continue

            X_scaled = scaler.transform(X)
            score = float(model.decision_function(X_scaled)[0])
            is_anomaly = score < THRESHOLD
            truth = event.get("ground_truth", None)
            eid = event.get("event_id", "?")[:8]

            # --- DB insert ---
            try:
                row = {
                    "event_id": event.get("event_id"),
                    "timestamp": event.get("timestamp"),
                    "score": score,
                    "is_anomaly": is_anomaly,
                    "ground_truth": truth,
                    **{c: float(event[c]) for c in feature_cols},
                }
                with conn, conn.cursor() as cur:
                    cur.execute(INSERT_SQL, row)
            except Exception as e:
                db_errors += 1
                print(f"[{seen:5d}] DB ERROR: {e}")
                conn.rollback()

            marker = "⚠️  ANOMALY" if is_anomaly else "✅ normal "
            if is_anomaly:
                flagged += 1
            print(
                f"[{seen:5d}] {marker}  id={eid}  "
                f"score={score:+.4f}  truth={truth}"
            )
    except KeyboardInterrupt:
        print("\nStopping consumer...")
    finally:
        consumer.close()
        conn.close()
        print(f"\nScored {seen} events | flagged {flagged} anomalies "
              f"({flagged/max(seen,1)*100:.1f}%) | DB errors: {db_errors}")


if __name__ == "__main__":
    main()