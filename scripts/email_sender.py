import os
import requests
from pathlib import Path
from dotenv import load_dotenv

# Load .env from project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

def send_alert_email(event_id, score, severity, recommendation):
    """Sends a real email using the Resend API (HTTPS, bypasses port blocks)."""
    api_key = os.environ.get("RESEND_API_KEY")
    sender = os.environ.get("EMAIL_FROM", "onboarding@resend.dev")
    recipient = os.environ.get("EMAIL_TO")

    if not api_key or not recipient:
        print("  [EMAIL SKIPPED] Missing RESEND_API_KEY or EMAIL_TO in .env")
        return False

    # The Resend API endpoint
    url = "https://api.resend.com/emails"
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    body = f"""
    BI-Safe Security Alert
    ----------------------
    An anomaly has been detected in your network traffic.

    Event ID: {event_id}
    Anomaly Score: {score:.4f}
    Severity: {severity.upper()}
    
    RECOMMENDED ACTION:
    {recommendation}

    Please check your BI-Safe Dashboard for more details.
    """

    payload = {
        "from": sender,
        "to": [recipient],
        "subject": f"🚨 BI-Safe [{severity.upper()}] Alert: Threat Detected ({event_id[:8]})",
        "text": body
    }

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=10)
        if response.status_code == 200:
            print(f"  [EMAIL SENT] to {recipient}")
            return True
        else:
            print(f"  [EMAIL FAILED] API Error {response.status_code}: {response.text}")
            return False
    except Exception as e:
        print(f"  [EMAIL FAILED] Network Error: {e}")
        return False