"""
Send BI-Safe alerts to SME owners by SMS or WhatsApp.

Modes:
    (default)    DRY RUN: prints what would be sent, records nothing
    --simulate   pretend to send: writes results/<channel>_outbox.log and
                 records the message in the alert_deliveries table
    --send       really send (SMS through Africa's Talking only; needs the
                 AT_USERNAME and AT_API_KEY environment variables)

Run:
    python scripts/send_alerts.py
    python scripts/send_alerts.py --simulate --channel both
"""

import argparse
import os
import sqlite3
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "database", "bi_safe.db")
RESULTS_DIR = os.path.join(BASE_DIR, "results")
CHANNELS = ["sms", "whatsapp"]


def ensure_table(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS alert_deliveries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_row_id INTEGER NOT NULL,
            channel TEXT NOT NULL,
            phone TEXT,
            message TEXT,
            mode TEXT,
            sent_at TEXT
        )
        """
    )
    conn.commit()


def build_message(channel, priority, score):
    if channel == "whatsapp":
        return (
            f"*BI-Safe {priority} alert*: unusual network traffic detected "
            f"(score {score:.3f}). Please review your dashboard. "
            f"Reply YES if this was you, or NO if it was not."
        )
    return (
        f"BI-Safe {priority} alert: unusual network traffic detected "
        f"(score {score:.3f}). Please review your dashboard."
    )


def get_pending(conn, channel, priorities, limit):
    marks = ",".join("?" for _ in priorities)
    sql = f"""
        SELECT a.id, a.priority, a.anomaly_score, u.name, u.phone
        FROM alerts a
        JOIN users u ON u.sme_id = a.sme_id AND u.role = 'owner'
        WHERE a.priority IN ({marks})
          AND NOT EXISTS (
              SELECT 1 FROM alert_deliveries d
              WHERE d.alert_row_id = a.id AND d.channel = ?
          )
        ORDER BY CASE a.priority WHEN 'HIGH' THEN 0 WHEN 'MEDIUM' THEN 1 ELSE 2 END,
                 a.anomaly_score ASC
        LIMIT ?
    """
    return conn.execute(sql, [*priorities, channel, limit]).fetchall()


def record_delivery(conn, alert_id, channel, phone, message, mode):
    now = datetime.now().isoformat(timespec="seconds")
    conn.execute(
        "INSERT INTO alert_deliveries "
        "(alert_row_id, channel, phone, message, mode, sent_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (alert_id, channel, phone, message, mode, now),
    )
    conn.execute("UPDATE alerts SET delivered = 1 WHERE id = ?", (alert_id,))
    conn.commit()
    if mode == "simulated":
        os.makedirs(RESULTS_DIR, exist_ok=True)
        path = os.path.join(RESULTS_DIR, f"{channel}_outbox.log")
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"{now} | to {phone} | {message}\n")


def accepted(response):
    recipients = response.get("SMSMessageData", {}).get("Recipients", [])
    return bool(recipients) and all(
        r.get("status") == "Success" or r.get("statusCode") in (100, 101, 102)
        for r in recipients
    )


def main():
    parser = argparse.ArgumentParser(description="Send alerts by SMS or WhatsApp.")
    parser.add_argument("--channel", choices=["sms", "whatsapp", "both"], default="sms")
    parser.add_argument("--send", action="store_true", help="really send (SMS only)")
    parser.add_argument("--simulate", action="store_true", help="log instead of sending")
    parser.add_argument("--priorities", nargs="+", default=["HIGH"])
    parser.add_argument("--limit", type=int, default=3)
    args = parser.parse_args()

    if args.send and args.simulate:
        print("Choose either --send or --simulate, not both.")
        return
    channels = CHANNELS if args.channel == "both" else [args.channel]
    if args.send and "whatsapp" in channels:
        print("Live WhatsApp is not supported. Use --simulate for WhatsApp.")
        return

    conn = sqlite3.connect(DB_PATH)
    ensure_table(conn)

    sms_client = None
    if args.send:
        username = os.environ.get("AT_USERNAME")
        api_key = os.environ.get("AT_API_KEY")
        if not username or not api_key:
            print("ERROR: set AT_USERNAME and AT_API_KEY first.")
            return
        import africastalking

        africastalking.initialize(username, api_key)
        sms_client = africastalking.SMS
        print(f"Sending as '{username}'")
    elif not args.simulate:
        print("DRY RUN: nothing will be sent or recorded.")

    for channel in channels:
        rows = get_pending(conn, channel, args.priorities, args.limit)
        print(f"\n== {channel.upper()}: {len(rows)} pending ==")
        done = 0
        for alert_id, priority, score, name, phone in rows:
            message = build_message(channel, priority, score)
            print(f"Alert #{alert_id} [{priority}] -> {name} {phone}")
            print(f"  {message}")
            if args.simulate:
                record_delivery(conn, alert_id, channel, phone, message, "simulated")
                done += 1
                print(f"  Simulated: written to results/{channel}_outbox.log")
            elif args.send:
                try:
                    response = sms_client.send(message, [phone])
                except Exception as exc:
                    print(f"  FAILED: {exc}")
                    continue
                if accepted(response):
                    record_delivery(conn, alert_id, channel, phone, message, "live")
                    done += 1
                    print("  Accepted by provider.")
                else:
                    print(f"  Not accepted: {response}")
        if args.simulate or args.send:
            print(f"{channel.upper()}: handled {done} of {len(rows)}.")

    conn.close()


if __name__ == "__main__":
    main()