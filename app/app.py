"""
BI-Safe Web Dashboard
=====================

A Flask web application that displays security monitoring data
for Kenyan SME owners.

Run:
    python app/app.py

Then open http://localhost:5000 in your browser.
"""

import os
import sqlite3
from flask import Flask, render_template, jsonify


# Get the project root directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATABASE_DIR = os.path.join(BASE_DIR, "database")
DB_PATH = os.path.join(DATABASE_DIR, "bi_safe.db")


# Create Flask app
app = Flask(__name__)


def get_db_connection():
    """Create a connection to the SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_dashboard_data():
    """Fetch all dashboard data from the database."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Total predictions
    cursor.execute("SELECT COUNT(*) FROM predictions")
    total_predictions = cursor.fetchone()[0]

    # Total anomalies
    cursor.execute("SELECT COUNT(*) FROM predictions WHERE prediction = 1")
    total_anomalies = cursor.fetchone()[0]

    # Security score = percentage of normal traffic
    if total_predictions > 0:
        normal = total_predictions - total_anomalies
        security_score = int((normal / total_predictions) * 100)
    else:
        security_score = 100

    # Alert counts
    cursor.execute("SELECT COUNT(*) FROM alerts")
    total_alerts = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM alerts WHERE priority = 'HIGH'")
    high_alerts = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM alerts WHERE priority = 'MEDIUM'")
    medium_alerts = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM alerts WHERE priority = 'LOW'")
    low_alerts = cursor.fetchone()[0]

    # Recent alerts
    cursor.execute(
        "SELECT alert_id, timestamp, offset, anomaly_score, priority, message "
        "FROM alerts ORDER BY id DESC LIMIT 10"
    )
    recent_alerts = [dict(row) for row in cursor.fetchall()]

    conn.close()

    return {
        "security_score": security_score,
        "total_predictions": total_predictions,
        "total_anomalies": total_anomalies,
        "total_alerts": total_alerts,
        "high_alerts": high_alerts,
        "medium_alerts": medium_alerts,
        "low_alerts": low_alerts,
        "recent_alerts": recent_alerts,
    }


@app.route("/")
def index():
    """Render the main dashboard page."""
    data = get_dashboard_data()
    return render_template("dashboard.html", data=data)


@app.route("/api/data")
def api_data():
    """Return dashboard data as JSON."""
    return jsonify(get_dashboard_data())


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        print(f"ERROR: Database not found at {DB_PATH}")
        print("Make sure Phase 8 (database setup) is complete.")
    else:
        print("Starting BI-Safe Web Dashboard...")
        print("Open http://localhost:5000 in your browser")
        app.run(debug=True, host="0.0.0.0", port=5000)