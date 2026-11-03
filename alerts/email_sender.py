"""
email_sender.py — Sends alert emails via Gmail SMTP.
"""
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from dotenv import load_dotenv

# Load .env from project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

def send_alert_email(event_id, score, ground_truth):
    """Sends a real email when an anomaly is detected."""
    host = os.environ.get("SMTP_HOST")
    port = int(os.environ.get("SMTP_PORT", 587))
    user = os.environ.get("SMTP_USER")
    password = os.environ.get("SMTP_PASS")
    sender = os.environ.get("EMAIL_FROM")
    recipient = os.environ.get("EMAIL_TO")

    # Create the email content
    msg = MIMEMultipart()
    msg['From'] = sender
    msg['To'] = recipient
    msg['Subject'] = f"🚨 BI-Safe Anomaly Detected: {event_id[:8]}"

    body = f"""
    BI-Safe Security Alert
    ----------------------
    An anomaly has been detected in your network traffic.

    Event ID: {event_id}
    Anomaly Score: {score:.4f}
    (Scores below +0.1056 trigger an alert)

    Ground Truth (Simulation): {ground_truth}

    Please check your BI-Safe Dashboard for more details.
    """
    msg.attach(MIMEText(body, 'plain'))

    try:
        # Connect to Gmail SMTP (Port 587 uses STARTTLS)
        with smtplib.SMTP(host, port) as server:
            server.starttls() # Secure the connection
            server.login(user, password)
            server.send_message(msg)
        print(f"  [EMAIL SENT] to {recipient}")
        return True
    except Exception as e:
        print(f"  [EMAIL FAILED] Error: {e}")
        return False