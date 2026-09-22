"""
BI-Safe Web Dashboard (Full Version)
=====================================

A Flask web application with separate interfaces for SME Owner and Admin.

Run:
    python app/app.py

Then open http://localhost:5000 in your browser.
"""

import os
import sys
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash


# Add the app directory to the path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from auth import (
    authenticate,
    create_user,
    login_required,
    get_current_user,
    logout_user,
    validate_email,
    validate_phone,
)
from db import (
    get_dashboard_stats,
    get_recent_alerts,
    get_alert_trends,
    get_drift_history,
    get_system_status,
    update_producer_status,
    update_producer_config,
    insert_network,
    get_networks_for_sme,
    update_network_activity,
)


# Create Flask app
app = Flask(__name__)
app.secret_key = "bi-safe-secret-key-change-in-production"


# --------------------------------------------------------------------------
# Public routes
# --------------------------------------------------------------------------

@app.route("/")
def index():
    """Redirect to the appropriate dashboard or login."""
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))
    if user["role"] == "admin":
        return redirect(url_for("admin_dashboard"))
    return redirect(url_for("owner_dashboard"))


@app.route("/register", methods=["GET", "POST"])
def register():
    """Registration page for both SME Owners and Admins."""
    if request.method == "POST":
        role = request.form.get("role", "").strip()
        name = request.form.get("name", "").strip()
        business_name = request.form.get("business_name", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if role not in ("owner", "admin"):
            return render_template("register.html", error="Please select a valid role.")

        if not all([name, email, phone, password, confirm_password]):
            return render_template("register.html", error="All fields are required.")

        email_valid, email_error = validate_email(email)
        if not email_valid:
            return render_template("register.html", error=email_error)

        phone_valid, phone_error = validate_phone(phone)
        if not phone_valid:
            return render_template("register.html", error=phone_error)

        if password != confirm_password:
            return render_template("register.html", error="Passwords do not match.")

        if len(password) < 6:
            return render_template("register.html", error="Password must be at least 6 characters.")

        success, error = create_user(
            name=name,
            business_name=business_name if role == "owner" else None,
            email=email,
            phone=phone,
            password=password,
            role=role,
        )

        if not success:
            return render_template("register.html", error=error)

        flash("Account created successfully. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Login page for both SME Owners and Admins."""
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        user = authenticate(email, password)
        if user:
            session["user"] = {
                "id": user["id"],
                "name": user["name"],
                "email": user["email"],
                "phone": user["phone"],
                "role": user["role"],
                "business_name": user.get("business_name"),
            }

            if user["role"] == "admin":
                return redirect(url_for("admin_dashboard"))
            return redirect(url_for("owner_dashboard"))

        flash("Invalid credentials. Please try again.", "error")

    return render_template("login.html")


@app.route("/logout")
def logout():
    """Log out and redirect to login."""
    logout_user()
    return redirect(url_for("login"))


# --------------------------------------------------------------------------
# SME Owner routes
# --------------------------------------------------------------------------

@app.route("/dashboard")
@login_required(role="owner")
def owner_dashboard():
    """SME Owner dashboard."""
    stats = get_dashboard_stats()
    alerts = get_recent_alerts(limit=10)
    trends = get_alert_trends()
    user = get_current_user()

    return render_template(
        "owner_dashboard.html",
        stats=stats,
        alerts=alerts,
        trends=trends,
        user=user,
    )

@app.route("/alerts")
@login_required(role="owner")
def alerts():
    """SME Owner alerts page."""
    alerts_list = get_recent_alerts(limit=50)
    user = get_current_user()
    return render_template("alerts.html", alerts=alerts_list, user=user)


@app.route("/reports")
@login_required(role="owner")
def reports():
    """SME Owner reports page."""
    stats = get_dashboard_stats()
    user = get_current_user()
    return render_template("reports.html", stats=stats, user=user)


@app.route("/connect")
@login_required(role="owner")
def connect():
    """SME Owner network connection page."""
    user = get_current_user()
    return render_template("connect.html", user=user)


@app.route("/settings")
@login_required(role="owner")
def settings():
    """SME Owner settings page."""
    user = get_current_user()
    return render_template("settings.html", user=user)


# --------------------------------------------------------------------------
# Admin routes
# --------------------------------------------------------------------------

@app.route("/admin/dashboard")
@login_required(role="admin")
def admin_dashboard():
    """Admin dashboard."""
    stats = get_dashboard_stats()
    alerts = get_recent_alerts(limit=10)
    trends = get_alert_trends()
    drift = get_drift_history()
    status = get_system_status()
    user = get_current_user()

    return render_template(
        "admin_dashboard.html",
        stats=stats,
        alerts=alerts,
        trends=trends,
        drift=drift,
        status=status,
        user=user,
    )

@app.route("/admin/producer")
@login_required(role="admin")
def admin_producer():
    """Admin producer control page."""
    status = get_system_status()
    user = get_current_user()
    return render_template("admin_producer.html", status=status, user=user)


@app.route("/admin/datasets")
@login_required(role="admin")
def admin_datasets():
    """Admin datasets management page."""
    user = get_current_user()
    return render_template("admin_datasets.html", user=user)


@app.route("/admin/drift")
@login_required(role="admin")
def admin_drift():
    """Admin model drift page."""
    drift = get_drift_history()
    user = get_current_user()
    return render_template("admin_drift.html", drift=drift, user=user)


@app.route("/admin/users")
@login_required(role="admin")
def admin_users():
    """Admin user management page."""
    user = get_current_user()
    return render_template("admin_users.html", user=user)


# --------------------------------------------------------------------------
# API routes
# --------------------------------------------------------------------------

@app.route("/api/stats")
@login_required()
def api_stats():
    return jsonify(get_dashboard_stats())


@app.route("/api/alerts")
@login_required()
def api_alerts():
    return jsonify(get_recent_alerts(limit=20))


@app.route("/api/trends")
@login_required()
def api_trends():
    return jsonify(get_alert_trends())


@app.route("/api/drift")
@login_required(role="admin")
def api_drift():
    return jsonify(get_drift_history())


@app.route("/api/producer/start", methods=["POST"])
@login_required(role="admin")
def producer_start():
    update_producer_status("running")
    return jsonify({"success": True, "status": "running", "message": "Producer started"})


@app.route("/api/producer/pause", methods=["POST"])
@login_required(role="admin")
def producer_pause():
    update_producer_status("paused")
    return jsonify({"success": True, "status": "paused", "message": "Producer paused"})


@app.route("/api/producer/stop", methods=["POST"])
@login_required(role="admin")
def producer_stop():
    update_producer_status("stopped")
    return jsonify({"success": True, "status": "stopped", "message": "Producer stopped"})


@app.route("/api/producer/configure", methods=["POST"])
@login_required(role="admin")
def producer_configure():
    data = request.get_json()
    traffic_rate = float(data.get("traffic_rate", 10.0))
    batch_size = int(data.get("batch_size", 100))
    update_producer_config(traffic_rate, batch_size)
    return jsonify({
        "success": True,
        "traffic_rate": traffic_rate,
        "batch_size": batch_size,
        "message": "Configuration updated",
    })


@app.route("/api/producer/status", methods=["GET"])
@login_required(role="admin")
def producer_status():
    return jsonify(get_system_status())


@app.route("/api/model/retrain", methods=["POST"])
@login_required(role="admin")
def model_retrain():
    return jsonify({
        "success": True,
        "message": "Model retraining started. This may take several minutes.",
    })


@app.route("/api/dataset/upload", methods=["POST"])
@login_required(role="admin")
def dataset_upload():
    return jsonify({
        "success": True,
        "message": "Dataset uploaded successfully.",
    })

@app.route("/connect", methods=["GET", "POST"])
@login_required(role="owner")
def connect():
    """SME Owner network connection page."""
    user = get_current_user()

    if request.method == "POST":
        network_name = request.form.get("network_name", "").strip()
        ip_range = request.form.get("ip_range", "").strip()
        sensor_key = request.form.get("sensor_key", "").strip()

        if not all([network_name, ip_range, sensor_key]):
            flash("All fields are required.", "error")
            return render_template("connect.html", user=user)

        # Use the logged-in user's ID as a stand-in for the SME ID
        sme_id = user.get("id")

        network_id = insert_network(sme_id, network_name, ip_range, sensor_key)
        flash(f"Network '{network_name}' connected successfully!", "success")

        networks = get_networks_for_sme(sme_id)
        return render_template("connect.html", user=user, networks=networks)

    sme_id = user.get("id")
    networks = get_networks_for_sme(sme_id)
    return render_template("connect.html", user=user, networks=networks)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("BI-Safe Dashboard starting...")
    print("=" * 60)

    db_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "database", "bi_safe.db"
    )

    print(f"Looking for database at: {db_path}")
    print(f"Database exists: {os.path.exists(db_path)}")

    if not os.path.exists(db_path):
        print(f"\nERROR: Database not found at {db_path}")
        print("Run this first: python database/db_setup.py")
    else:
        print("\nStarting Flask server...")
        print("Open http://localhost:5000 in your browser")
        app.run(debug=False, host="127.0.0.1", port=5001)