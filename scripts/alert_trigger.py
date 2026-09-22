"""
Alert Trigger for BI-Safe
=========================

This script reads anomaly predictions from the consumer results and
generates alerts for the SME Owner.

Alerts are simulated (logged to a file and printed to console).
In a real deployment, these would be sent via SMS/WhatsApp using Twilio.

Requirements:
    pip install pandas

Run:
    python scripts/alert_trigger.py
"""

import os
import json
from datetime import datetime
import pandas as pd


# Get the project root directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_DIR = os.path.join(BASE_DIR, "results")
DATA_DIR = os.path.join(BASE_DIR, "data")


# Alert configuration
ALERT_PRIORITY_THRESHOLD = 0.0     # Score below this = high priority
SME_OWNER_PHONE = "+254700000000"  # Placeholder phone number
SME_OWNER_NAME = "Mama Salons"


def load_consumer_results(filepath):
    """Load the consumer results CSV."""
    print(f"Loading {filepath}...")
    df = pd.read_csv(filepath)
    print(f"  Loaded {len(df):,} rows")
    return df


def get_alert_priority(anomaly_score):
    """Determine alert priority based on anomaly score."""
    # Isolation Forest decision_function: lower = more anomalous
    if anomaly_score < -0.15:
        return "HIGH"
    elif anomaly_score < -0.05:
        return "MEDIUM"
    else:
        return "LOW"


def format_alert_message(alert):
    """Format an alert message for the SME Owner."""
    priority = alert["priority"]
    score = alert["anomaly_score"]
    timestamp = alert["timestamp"]

    emoji = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}[priority]

    message = (
        f"{emoji} BI-SAFE {priority} PRIORITY ALERT\n"
        f"Time: {timestamp}\n"
        f"Anomaly Score: {score:.4f}\n"
        f"Action Required: Review your dashboard immediately.\n"
        f"Reply YES if this was you, or NO if it was not."
    )
    return message


def simulate_send_sms(phone, message):
    """Simulate sending an SMS (logs to console and file)."""
    print(f"\n--- SMS to {phone} ---")
    print(message)
    print("--- End SMS ---\n")
    return True


def simulate_send_whatsapp(phone, message):
    """Simulate sending a WhatsApp message (logs to console and file)."""
    print(f"\n--- WhatsApp to {phone} ---")
    print(message)
    print("--- End WhatsApp ---\n")
    return True


def process_alerts(df, max_alerts=20):
    """Process anomalies and trigger alerts."""
    # Filter only anomalies
    anomalies = df[df["prediction"] == 1].copy()
    print(f"\nFound {len(anomalies):,} anomalies in the results")

    if len(anomalies) == 0:
        print("  No alerts to send.")
        return []

    # Limit to max_alerts
    anomalies = anomalies.head(max_alerts)

    alerts = []
    current_time = datetime.now().isoformat()

    for i, (_, row) in enumerate(anomalies.iterrows()):
        alert = {
            "alert_id": i + 1,
            "timestamp": current_time,
            "offset": int(row.get("offset", 0)),
            "anomaly_score": float(row["anomaly_score"]),
            "actual": int(row["actual"]) if pd.notna(row["actual"]) else None,
            "priority": get_alert_priority(row["anomaly_score"]),
        }

        # Format message
        message = format_alert_message(alert)
        alert["message"] = message

        # Send via both channels
        simulate_send_sms(SME_OWNER_PHONE, message)
        simulate_send_whatsapp(SME_OWNER_PHONE, message)

        alerts.append(alert)

    return alerts


def save_alert_log(alerts):
    """Save the alert history to a JSON file."""
    if not alerts:
        print("  No alerts to save.")
        return

    os.makedirs(RESULTS_DIR, exist_ok=True)
    output_file = os.path.join(RESULTS_DIR, "alert_history.json")

    with open(output_file, "w") as f:
        json.dump(alerts, f, indent=2)

    print(f"\n  Alert history saved to: {output_file}")


def print_summary(alerts):
    """Print a summary of alerts sent."""
    if not alerts:
        return

    print(f"\n{'='*60}")
    print(f"Alert Summary")
    print(f"{'='*60}")

    priorities = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for alert in alerts:
        priorities[alert["priority"]] += 1

    print(f"  Total alerts:  {len(alerts):,}")
    print(f"  HIGH priority: {priorities['HIGH']}")
    print(f"  MEDIUM:        {priorities['MEDIUM']}")
    print(f"  LOW:           {priorities['LOW']}")
    print(f"{'='*60}")


def main():
    """Main function to run the alert trigger."""
    # Load consumer results
    results_file = os.path.join(RESULTS_DIR, "consumer_results.csv")
    if not os.path.exists(results_file):
        print(f"ERROR: {results_file} not found.")
        print("Make sure Phase 6 (Kafka consumer) is complete.")
        return

    df = load_consumer_results(results_file)

    # Process alerts
    alerts = process_alerts(df, max_alerts=20)

    # Save alert log
    save_alert_log(alerts)

    # Print summary
    print_summary(alerts)


if __name__ == "__main__":
    main()