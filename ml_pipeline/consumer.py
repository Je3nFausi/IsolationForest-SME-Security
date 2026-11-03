"""
consumer.py — Reads network events from Kafka, scores them with the trained
Isolation Forest, prints a terminal alert on anomalies, inserts predictions 
into PostgreSQL, and fires EMAIL + DASHBOARD alerts on anomalies.

Usage (from project root):
    python ml_pipeline/consumer.py

Stop with Ctrl+C.
"""
import argparse
import json
import os
import smtplib
import sys
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path

import numpy as np
from joblib import load
from kafka import KafkaConsumer
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from database.db import get_connection

# Load environment variables (Gmail credentials)
load_dotenv(PROJECT_ROOT / ".env")

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
) RETURNING id;
"""

INSERT_ALERT_SQL = """
INSERT INTO alerts (prediction_id, event_id, alert_type, severity, status)
VALUES (%s, %s, 'email+dashboard', 'high', 'sent');
"""


def send_email_alert(event_id, score, truth):
    """Connects to Gmail via SMTP and sends a real alert email."""
    host = os.environ.get("SMTP_HOST", "smtp.gmail.com")
    port = int(os.environ.get("SMTP_PORT", 587))
    user = os.environ.get("SMTP_USER")
    password = os.environ.get("SMTP_PASS")
    sender = os.environ.get("EMAIL_FROM", user)
    recipient = os.environ.get("EMAIL_TO", user)

    if not all([user, password]):
        print("  [EMAIL SKIPPED] Missing SMTP_USER or SMTP_PASS in .env")
        return False

    msg = MIMEMultipart()
    msg['From'] = sender
    msg['To'] = recipient
    msg['Subject'] = f"🚨 BI-Safe Alert: Anomaly Detected ({event_id[:8]})"

    body = f"""
    BI-Safe Security Alert
    ----------------------
    An anomaly has been detected in your network traffic.

    Event ID: {event_id}
    Anomaly Score: {score:.4f} (Threshold: < {THRESHOLD})
    Ground Truth: {truth}

    Please check your BI-Safe Dashboard for more details.
    """
    msg.attach(MIMEText(body, 'plain'))

    try:
        # Using SMTP with explicit ehlo() and a longer timeout for Windows
        with smtplib.SMTP(host, port, timeout=30) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(user, password)
            server.send_message(msg)
        print(f"  [EMAIL SENT] to {recipient}")
        return True
    except Exception as e:
        print(f"  [EMAIL FAILED] {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Score Kafka events + persist to DB")
    parser.add_argument("--broker", default="localhost:9092")
    parser.add_argument("--topic", default="network-events")
    parser.add_argument("--group", default="anomaly-scorer-v3")
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
            eid = event.get("event_id", "?")
            eid_short = eid[:8]

            # --- DB Insert & Alerts ---
            prediction_id = None
            try:
                row = {
                    "event_id": eid,
                    "timestamp": event.get("timestamp"),
                    "score": score,
                    "is_anomaly": is_anomaly,
                    "ground_truth": truth,
                    **{c: float(event[c]) for c in feature_cols},
                }
                with conn, conn.cursor() as cur:
                    cur.execute(INSERT_SQL, row)
                    prediction_id = cur.fetchone()['id']
                    
                    # If anomaly, write to alerts table immediately
                    if is_anomaly:
                        cur.execute(INSERT_ALERT_SQL, (prediction_id, eid))
            except Exception as e:
                db_errors += 1
                print(f"[{seen:5d}] DB ERROR: {e}")
                conn.rollback()

            # --- Fire Email ---
            if is_anomaly and prediction_id is not None:
                print(f"[{seen:5d}] 🚨 ANOMALY - FIRING ALERTS for {eid_short}...")
                send_email_alert(eid, score, truth)

            marker = "⚠️  ANOMALY" if is_anomaly else "✅ normal "
            if is_anomaly:
                flagged += 1
            print(
                f"[{seen:5d}] {marker}  id={eid_short}  "
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