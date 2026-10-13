"""
Send BI-Safe alerts by SMS through Africa's Talking.

Default is a DRY RUN (prints only). Add --send to really call the API.
Credentials come from environment variables AT_USERNAME and AT_API_KEY.
Use AT_USERNAME=sandbox for the free sandbox.

Run:
    python scripts/send_alerts.py
    python scripts/send_alerts.py --send
    python scripts/send_alerts.py --send --priorities HIGH MEDIUM --limit 5
"""

import argparse
import os
import sqlite3

from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "database", "bi_safe.db")


def build_message(priority, score):
    return (
        f"BI-Safe {priority} alert: unusual network traffic detected "
        f"(score {score:.3f}). Please review your dashboard."
    )


def get_pending(conn, priorities, limit):
    marks = ",".join("?" for _ in priorities)
    sql = f"""
        SELECT a.id, a.priority, a.anomaly_score, u.name, u.phone
        FROM alerts a
        JOIN users u ON u.sme_id = a.sme_id AND u.role = 'owner'
        WHERE COALESCE(a.delivered, 0) = 0
          AND a.priority IN ({marks})
        ORDER BY CASE a.priority WHEN 'HIGH' THEN 0 WHEN 'MEDIUM' THEN 1 ELSE 2 END,
                 a.anomaly_score ASC
        LIMIT ?
    """
    return conn.execute(sql, [*priorities, limit]).fetchall()


def accepted(response):
    recipients = response.get("SMSMessageData", {}).get("Recipients", [])
    return bool(recipients) and all(
        r.get("status") == "Success" or r.get("statusCode") in (100, 101, 102)
        for r in recipients
    )


def main():
    parser = argparse.ArgumentParser(description="Send alerts by SMS.")
    parser.add_argument("--send", action="store_true", help="really send")
    parser.add_argument("--priorities", nargs="+", default=["HIGH"])
    parser.add_argument("--limit", type=int, default=3)
    parser.add_argument("--simulate", action="store_true",
                        help="pretend to send: log to results/sms_outbox.log")
    args = parser.parse_args()

    conn = sqlite3.connect(DB_PATH)
    rows = get_pending(conn, args.priorities, args.limit)
    if not rows:
        print("No pending alerts to send (check sme_id links and priorities).")
        return

    sms = None
    if args.send:
        username = os.environ.get("AT_USERNAME")
        api_key = os.environ.get("AT_API_KEY")
        if not username or not api_key:
            print("ERROR: set AT_USERNAME and AT_API_KEY first.")
            return
        import africastalking

        africastalking.initialize(username, api_key)
        sms = africastalking.SMS
        print(f"Sending as '{username}'")
    else:
        if not args.simulate: print("DRY RUN: nothing will be sent. Add --send to send.\n")

    sent = 0
    for alert_id, priority, score, name, phone in rows:
        message = build_message(priority, score)
        print(f"Alert #{alert_id} [{priority}] -> {name} {phone}")
        print(f"  {message}")
        if args.simulate:
            outbox = os.path.join(BASE_DIR, "results", "sms_outbox.log")
            with open(outbox, "a", encoding="utf-8") as f:
                f.write(f"{datetime.now().isoformat(timespec='seconds')} | to {phone} | {message}\n")
            conn.execute("UPDATE alerts SET delivered = 1 WHERE id = ?", (alert_id,))
            conn.commit()
            sent += 1
            print("  Simulated: written to results/sms_outbox.log")
            continue
        if not args.send:
            continue
        try:
            response = sms.send(message, [phone])
        except Exception as exc:
            print(f"  FAILED: {exc}")
            continue
        if accepted(response):
            conn.execute("UPDATE alerts SET delivered = 1 WHERE id = ?", (alert_id,))
            conn.commit()
            sent += 1
            print("  Accepted by provider.")
        else:
            print(f"  Not accepted: {response}")

    if args.send or args.simulate:
        print(f"\nSent {sent} of {len(rows)}.")
    conn.close()


if __name__ == "__main__":
    main()