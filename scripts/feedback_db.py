"""
feedback_db.py — Handles saving user feedback to the database.
"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from database.db import get_connection

def submit_feedback(alert_id: int, is_correct: bool, comments: str = ""):
    """Saves a user's feedback (True = real threat, False = false alarm)."""
    conn = get_connection()
    try:
        sql = """
            INSERT INTO feedback (alert_id, is_correct, comments)
            VALUES (%s, %s, %s)
        """
        with conn, conn.cursor() as cur:
            cur.execute(sql, (alert_id, is_correct, comments))
        print(f"Feedback saved for alert {alert_id} (Correct: {is_correct})")
        return True
    except Exception as e:
        print(f"Error saving feedback: {e}")
        return False
    finally:
        conn.close()