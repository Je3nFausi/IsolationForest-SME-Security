"""
dashboard_alert.py — Writes alerts to PostgreSQL for the dashboard.
"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
from database.db import get_connection

def write_dashboard_alert(prediction_id, event_id, score):
    """Inserts an alert into the database."""
    conn = get_connection()
    try:
        sql = """
            INSERT INTO alerts (prediction_id, event_id, alert_type, severity, status)
            VALUES (%s, %s, 'dashboard', 'high', 'sent')
        """
        with conn, conn.cursor() as cur:
            cur.execute(sql, (prediction_id, event_id))
        return True
    except Exception as e:
        print(f"  [DASHBOARD ALERT FAILED] {e}")
        return False
    finally:
        conn.close()