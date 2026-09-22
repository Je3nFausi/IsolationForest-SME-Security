"""
Database helper for BI-Safe (Full Schema)
==========================================

Provides functions to query all tables.
"""

import os
import sqlite3


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "database", "bi_safe.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_dashboard_stats():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM predictions")
    total_predictions = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM predictions WHERE is_anomaly = 1")
    total_anomalies = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM alerts")
    total_alerts = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM alerts WHERE priority = 'HIGH'")
    high_alerts = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM alerts WHERE priority = 'MEDIUM'")
    medium_alerts = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM alerts WHERE priority = 'LOW'")
    low_alerts = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM feedback")
    total_feedback = cursor.fetchone()[0]
    conn.close()
    if total_predictions > 0:
        normal = total_predictions - total_anomalies
        security_score = int((normal / total_predictions) * 100)
    else:
        security_score = 100
    return {
        "security_score": security_score,
        "total_predictions": total_predictions,
        "total_anomalies": total_anomalies,
        "total_alerts": total_alerts,
        "high_alerts": high_alerts,
        "medium_alerts": medium_alerts,
        "low_alerts": low_alerts,
        "total_feedback": total_feedback,
    }


def get_recent_alerts(limit=10):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
    alerts = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return alerts


def get_alert_trends():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT priority, COUNT(*) as count FROM alerts GROUP BY priority")
    trends = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return trends


def get_drift_history():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT batch_number, f1_score, precision, recall, drift_score, detected_at FROM drift_log ORDER BY batch_number")
    history = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return history


def get_all_datasets():
    return [
        {"name": "CIC-IDS-2017", "rows": "2.8M", "features": 79, "attack_types": 7, "status": "Loaded"},
        {"name": "UNSW-NB15", "rows": "2.5M", "features": 49, "attack_types": 9, "status": "Loaded"},
        {"name": "NSL-KDD", "rows": "125K", "features": 41, "attack_types": 4, "status": "Loaded"},
    ]


def get_all_models():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM models ORDER BY id DESC")
    models = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return models


def save_feedback(alert_id, sme_id, user_id, feedback_type, comment=""):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO feedback (alert_id, sme_id, user_id, feedback_type, comment) VALUES (?, ?, ?, ?, ?)",
                   (alert_id, sme_id, user_id, feedback_type, comment))
    conn.commit()
    conn.close()
    return True


def get_feedback_for_alert(alert_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM feedback WHERE alert_id = ?", (alert_id,))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def get_system_status():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM system_status ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else {
        "producer_status": "stopped",
        "traffic_rate": 10.0,
        "batch_size": 100,
    }


def update_producer_status(status):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE system_status SET producer_status = ?, last_updated = CURRENT_TIMESTAMP WHERE id = (SELECT MAX(id) FROM system_status)", (status,))
    conn.commit()
    conn.close()
    return True


def update_producer_config(traffic_rate, batch_size):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE system_status SET traffic_rate = ?, batch_size = ?, last_updated = CURRENT_TIMESTAMP WHERE id = (SELECT MAX(id) FROM system_status)", (traffic_rate, batch_size))
    conn.commit()
    conn.close()
    return True


def create_drift_log_entry(batch_number, f1_score, precision, recall, drift_score=0.0):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO drift_log (model_id, batch_number, f1_score, precision, recall, drift_score, triggered_retrain) VALUES (1, ?, ?, ?, ?, ?, 0)",
                   (batch_number, f1_score, precision, recall, drift_score))
    conn.commit()
    conn.close()
    return True


def insert_prediction(offset, anomaly_score, is_anomaly, actual=None, processing_time_ms=None):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO predictions (offset, anomaly_score, is_anomaly, actual, processing_time_ms)
        VALUES (?, ?, ?, ?, ?)
    """, (
        int(offset) if offset is not None else None,
        float(anomaly_score) if anomaly_score is not None else None,
        1 if is_anomaly else 0,
        int(actual) if actual is not None else None,
        int(processing_time_ms) if processing_time_ms is not None else None,
    ))
    conn.commit()
    conn.close()
    return True


def insert_alert(alert_id, offset, anomaly_score, priority, message, actual=None):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO alerts (alert_id, offset, anomaly_score, priority, message, actual, status)
        VALUES (?, ?, ?, ?, ?, ?, 'Pending')
    """, (
        int(alert_id),
        int(offset) if offset is not None else None,
        float(anomaly_score) if anomaly_score is not None else None,
        priority,
        message,
        int(actual) if actual is not None else None,
    ))
    conn.commit()
    conn.close()
    return True


def clear_predictions_and_alerts():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM predictions")
    cursor.execute("DELETE FROM alerts")
    conn.commit()
    conn.close()
    return True