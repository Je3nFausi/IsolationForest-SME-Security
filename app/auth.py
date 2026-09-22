"""
Authentication helper for BI-Safe
==================================

Database-backed authentication with password hashing.
Supports registration for both SME Owners and Admins.
"""

import os
import re
import sqlite3
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask import session, redirect, url_for, flash


# Database path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "database", "bi_safe.db")


# Allowed email domains
ALLOWED_DOMAINS = [
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "live.com", "icloud.com", "protonmail.com", "bi-safe.com",
]


# --------------------------------------------------------------------------
# Validation functions
# --------------------------------------------------------------------------

def validate_email(email):
    """Validate email format and domain."""
    if not email:
        return False, "Email is required."

    email = email.strip().lower()

    if " " in email:
        return False, "Email cannot contain spaces."

    if "@" not in email:
        return False, "Email must contain '@'."

    parts = email.split("@")
    if len(parts) != 2:
        return False, "Email must have exactly one '@'."

    local, domain = parts

    if not local:
        return False, "Email must have text before '@'."

    if not domain:
        return False, "Email must have a domain after '@'."

    if domain not in ALLOWED_DOMAINS:
        return False, f"Email domain must be one of: {', '.join(ALLOWED_DOMAINS)}"

    if not re.match(r"^[a-zA-Z0-9._+-]+$", local):
        return False, "Email contains invalid characters."

    return True, ""


def validate_phone(phone):
    """Validate Kenyan phone number format."""
    if not phone:
        return False, "Phone number is required."

    phone = phone.strip().replace(" ", "")
    clean = phone.replace("+", "")

    if clean.startswith("254"):
        if len(clean) != 12:
            return False, "Phone must be in format +254XXXXXXXXX (12 digits)."
        digits = clean[3:]
    elif clean.startswith("0"):
        if len(clean) != 10:
            return False, "Phone must be in format 0XXXXXXXXX (10 digits)."
        digits = clean[1:]
    else:
        return False, "Phone must start with +254 or 0."

    if not digits.isdigit():
        return False, "Phone must contain only digits."

    return True, ""


# --------------------------------------------------------------------------
# Database helpers
# --------------------------------------------------------------------------

def get_db():
    """Get a database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_user_by_email(email):
    """Fetch a user from the database by email."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM users WHERE email = ?", (email.lower().strip(),)
    )
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def create_user(name, business_name, email, phone, password, role):
    """Create a new user in the database."""
    conn = get_db()
    cursor = conn.cursor()

    password_hash = generate_password_hash(password)

    try:
        cursor.execute(
            "INSERT INTO users (name, business_name, email, phone, password_hash, role) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (name, business_name, email.lower().strip(), phone, password_hash, role),
        )
        conn.commit()
        return True, None
    except sqlite3.IntegrityError:
        return False, "Email is already registered."
    finally:
        conn.close()


# --------------------------------------------------------------------------
# Authentication
# --------------------------------------------------------------------------

def authenticate(email, password):
    """Check if credentials are valid against the database."""
    user = get_user_by_email(email)
    if not user:
        return None
    if not check_password_hash(user["password_hash"], password):
        return None
    return user


def login_required(role=None):
    """Decorator to protect routes."""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if "user" not in session:
                flash("Please log in first.", "error")
                return redirect(url_for("login"))
            if role and session["user"].get("role") != role:
                flash("Access denied.", "error")
                return redirect(url_for("login"))
            return f(*args, **kwargs)
        return wrapped
    return decorator


def get_current_user():
    """Get the current logged-in user from session."""
    return session.get("user")


def logout_user():
    """Log out the current user."""
    session.pop("user", None)