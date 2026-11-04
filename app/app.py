from flask import Flask, render_template, request, redirect, url_for, flash, session, Response
import sys
from pathlib import Path
import psycopg2
import csv
import io
import subprocess
import os

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from database.db import get_connection

app = Flask(__name__, 
            template_folder=str(PROJECT_ROOT / 'app' / 'templates'),
            static_folder=str(PROJECT_ROOT / 'app' / 'static'))
app.secret_key = "bi-safe-secret-key"

# Global variable to track the Kafka Producer subprocess
producer_process = None

# ==========================================
# AUTHENTICATION ROUTES
# ==========================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE LOWER(email) = LOWER(%s)", (email,))
            user = cur.fetchone()
        conn.close()

        if user and user['password'] == password:
            session['user'] = {
                'id': user['id'], 
                'name': user['name'], 
                'role': user['role'], 
                'email': user['email'],
                'sme_type': user.get('sme_type', '')
            }
            if user['role'] == 'owner':
                return redirect(url_for('owner_dashboard'))
            else:
                return redirect(url_for('admin_dashboard'))
        else:
            flash("Invalid email or password. Please try again.", "error")
            
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        role = request.form.get("role")
        name = request.form.get("name")
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone")
        sme_type = request.form.get("sme_type")
        password = request.form.get("password")
        
        conn = get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO users (role, name, email, phone, sme_type, password)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (role, name, email, phone, sme_type, password))
            conn.commit()
            flash("Account created! Please log in.", "success")
            return redirect(url_for("login"))
            
        except psycopg2.errors.UniqueViolation:
            conn.rollback()
            flash("Email already exists. Please log in.", "error")
        except Exception as e:
            conn.rollback()
            print(f"\n--- DATABASE ERROR ---\n{str(e)}\n----------------------\n")
            flash(f"Registration failed.", "error")
        finally:
            conn.close()
            
    return render_template("register.html")

@app.route("/logout")
def logout():
    session.pop('user', None)
    return redirect(url_for("login"))

# ==========================================
# SME OWNER ROUTES
# ==========================================
@app.route("/")
def owner_dashboard():
    if 'user' not in session or session['user']['role'] != 'owner':
        return redirect(url_for('login'))
        
    conn = get_connection()
    with conn.cursor() as cur:
        cur.execute("""
            SELECT a.id, a.event_id, a.severity, a.recommendation, a.created_at, p.score 
            FROM alerts a
            JOIN predictions p ON a.prediction_id = p.id
            LEFT JOIN feedback f ON a.id = f.alert_id
            WHERE f.id IS NULL
            ORDER BY a.created_at DESC
            LIMIT 15;
        """)
        alerts = cur.fetchall()
        
        cur.execute("SELECT COUNT(*) FROM predictions WHERE is_anomaly = true")
        anomalies = cur.fetchone()['count']
        security_score = max(0, 100 - anomalies)
        
    conn.close()
    return render_template("owner_dashboard.html", user=session['user'], alerts=alerts, score=security_score)

@app.route("/connect_network", methods=["POST"])
def connect_network():
    subnet = request.form.get("subnet")
    flash(f"Successfully connected to network {subnet}! Monitoring started.", "success")
    return redirect(url_for("owner_dashboard"))

@app.route("/feedback", methods=["POST"])
def handle_feedback():
    alert_id = request.form.get("alert_id")
    is_correct = request.form.get("is_correct") == "true"
    if alert_id:
        from scripts.feedback_db import submit_feedback
        submit_feedback(int(alert_id), is_correct)
        flash("Threat analysis recorded successfully.", "success")
    return redirect(url_for("owner_dashboard"))

@app.route("/model_feedback", methods=["POST"])
def model_feedback():
    if 'user' not in session: return redirect(url_for('login'))
    
    rating = request.form.get("rating")
    comment = request.form.get("comment")
    
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # We save the rating and comment into the 'comments' column.
            # We ensure 'is_correct' is NULL (since this isn't an alert confirmation).
            cur.execute("""
                INSERT INTO feedback (user_id, comments, is_correct)
                VALUES (%s, %s, NULL)
            """, (session['user']['id'], f"[{rating}] {comment}"))
        conn.commit()
        flash("Thank you! Your feedback was submitted successfully.", "success")
    except Exception as e:
        conn.rollback()
        print(f"Feedback Error: {e}")
        flash("Could not save feedback.", "error")
    finally:
        conn.close()
        
    return redirect(url_for("owner_dashboard"))

@app.route("/reports")
def reports():
    if 'user' not in session: return redirect(url_for('login'))
    return render_template("reports.html")

@app.route("/download_report")
def download_report():
    if 'user' not in session: return redirect(url_for('login'))
    
    conn = get_connection()
    with conn.cursor() as cur:
        cur.execute("""
            SELECT a.event_id, a.severity, a.recommendation, a.created_at, p.score, p.is_anomaly 
            FROM alerts a
            JOIN predictions p ON a.prediction_id = p.id
            ORDER BY a.created_at DESC
        """)
        alerts = cur.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Event ID', 'Severity', 'Recommendation', 'Date', 'Anomaly Score', 'Is Anomaly'])
    
    for alert in alerts:
        writer.writerow([
            alert['event_id'], 
            alert['severity'], 
            alert['recommendation'], 
            alert['created_at'].strftime('%Y-%m-%d %H:%M'),
            round(alert['score'], 4),
            alert['is_anomaly']
        ])
        
    output.seek(0)
    
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=bi_safe_security_report.csv"}
    )

@app.route("/settings")
def settings():
    if 'user' not in session: return redirect(url_for('login'))
    return render_template("settings.html")

# ==========================================
# SYSTEM ADMIN ROUTES
# ==========================================
@app.route("/admin")
def admin_dashboard():
    if 'user' not in session or session['user']['role'] != 'admin':
        return redirect(url_for('login'))
        
    conn = get_connection()
    with conn.cursor() as cur:
        cur.execute("SELECT p.is_anomaly, p.ground_truth FROM alerts a JOIN predictions p ON a.prediction_id = p.id")
        rows = cur.fetchall()
        tp = sum(1 for r in rows if r['is_anomaly'] and r['ground_truth'] == 'anomaly')
        fp = sum(1 for r in rows if r['is_anomaly'] and r['ground_truth'] == 'normal')
        fn = sum(1 for r in rows if not r['is_anomaly'] and r['ground_truth'] == 'anomaly')
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    conn.close()
    
    return render_template("admin_dashboard.html", user=session['user'], precision=precision*100, recall=recall*100, tp=tp, fp=fp, fn=fn)

@app.route("/admin/producer")
def admin_producer():
    if 'user' not in session or session['user']['role'] != 'admin': return redirect(url_for('login'))
    return render_template("admin_producer.html")

@app.route("/admin/users")
def admin_users():
    if 'user' not in session or session['user']['role'] != 'admin': return redirect(url_for('login'))
    
    conn = get_connection()
    with conn.cursor() as cur:
        cur.execute("SELECT id, name, email, role, sme_type, phone FROM users ORDER BY id DESC")
        users = cur.fetchall()
    conn.close()
    
    return render_template("admin_users.html", users=users)

@app.route("/admin/feedback")
def admin_feedback():
    if 'user' not in session or session['user']['role'] != 'admin': return redirect(url_for('login'))
    
    conn = get_connection()
    with conn.cursor() as cur:
        # Only show general model feedback (is_correct IS NULL)
        cur.execute("""
            SELECT f.id, f.comments, f.submitted_at, u.name, u.sme_type
            FROM feedback f
            LEFT JOIN users u ON f.user_id = u.id
            WHERE f.is_correct IS NULL
            ORDER BY f.submitted_at DESC
        """)
        feedbacks = cur.fetchall()
    conn.close()
    
    return render_template("admin_feedback.html", feedbacks=feedbacks)

@app.route("/admin/users/add", methods=["POST"])
def add_user():
    if 'user' not in session or session['user']['role'] != 'admin': return redirect(url_for('login'))
    
    name = request.form.get("name")
    email = request.form.get("email")
    role = request.form.get("role")
    phone = request.form.get("phone")
    sme_type = request.form.get("sme_type")
    password = request.form.get("password")
    
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO users (name, email, role, phone, sme_type, password)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (name, email, role, phone, sme_type, password))
        conn.commit()
        flash("User added successfully.", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Error adding user: {str(e)}", "error")
    finally:
        conn.close()
        
    return redirect(url_for("admin_users"))

@app.route("/admin/users/edit/<int:user_id>", methods=["POST"])
def edit_user(user_id):
    if 'user' not in session or session['user']['role'] != 'admin': return redirect(url_for('login'))
    
    name = request.form.get("name")
    email = request.form.get("email")
    role = request.form.get("role")
    phone = request.form.get("phone")
    sme_type = request.form.get("sme_type")
    
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE users 
                SET name=%s, email=%s, role=%s, phone=%s, sme_type=%s
                WHERE id=%s
            """, (name, email, role, phone, sme_type, user_id))
        conn.commit()
        flash("User updated successfully.", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Error updating user: {str(e)}", "error")
    finally:
        conn.close()
        
    return redirect(url_for("admin_users"))

@app.route("/admin/users/delete/<int:user_id>", methods=["POST"])
def delete_user(user_id):
    if 'user' not in session or session['user']['role'] != 'admin': return redirect(url_for('login'))
    
    if user_id == session['user']['id']:
        flash("You cannot delete your own admin account.", "error")
        return redirect(url_for("admin_users"))
        
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM users WHERE id=%s", (user_id,))
        conn.commit()
        flash("User deleted successfully.", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Error deleting user: {str(e)}", "error")
    finally:
        conn.close()
        
    return redirect(url_for("admin_users"))

# ==========================================
# PRODUCER CONTROL ROUTES
# ==========================================
@app.route("/admin/producer/start", methods=["POST"])
def start_producer():
    global producer_process
    if 'user' not in session or session['user']['role'] != 'admin': return redirect(url_for('login'))
    
    if producer_process is None or producer_process.poll() is not None:
        producer_path = os.path.join(PROJECT_ROOT, "ml_pipeline", "producer.py")
        
        cmd = [
            sys.executable, 
            producer_path, 
            "--rate", "2", 
            "--anomaly-rate", "0.1",
            "--max-events", "0"
        ]
        
        creation_flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0
        
        producer_process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creation_flags
        )
        flash("Producer started successfully! Traffic is now streaming to Kafka.", "success")
    else:
        flash("Producer is already running.", "error")
        
    return redirect(url_for("admin_producer"))

@app.route("/admin/producer/stop", methods=["POST"])
def stop_producer():
    global producer_process
    if 'user' not in session or session['user']['role'] != 'admin': return redirect(url_for('login'))
    
    if producer_process is not None and producer_process.poll() is None:
        if os.name == 'nt':  # Windows
            subprocess.call(['taskkill', '/F', '/T', '/PID', str(producer_process.pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:  # Mac/Linux
            producer_process.terminate()
            
        producer_process = None
        flash("Producer stopped successfully.", "success")
    else:
        flash("Producer is not running.", "error")
        
    return redirect(url_for("admin_producer"))

@app.route("/admin/producer/status")
def producer_status():
    global producer_process
    is_running = producer_process is not None and producer_process.poll() is None
    return {"status": "running" if is_running else "stopped"}

if __name__ == "__main__":
    app.run(debug=True, port=5000)