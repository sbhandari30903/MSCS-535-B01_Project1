"""
Secure Flask HTTPS API w/ MySQL (local)
- mysql-connector-python with connection pooling
- Parameterized queries only (no SQL concatenation) to prevent SQL injection
- bcrypt for password hashing
- JWT for short-lived auth tokens
- Minimal endpoints: /api/health, /api/register, /api/login, /api/user/<username>
"""

import os
import time
import logging
import re
from datetime import datetime, timedelta

from flask import Flask, request, jsonify
from dotenv import load_dotenv
import bcrypt
import jwt

import mysql.connector
from mysql.connector import pooling, Error as MySQLError

# Load .env (dev)
load_dotenv()

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("secure-mysql-api")

# Required env vars (fail fast)
REQUIRED = [
    "DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASS",
    "JWT_SECRET", "JWT_EXPIRY_MINUTES",
    "HTTPS_CERT_PATH", "HTTPS_KEY_PATH", "HTTPS_PORT"
]
missing = [k for k in REQUIRED if not os.getenv(k)]
if missing:
    raise SystemExit(f"Missing environment variables: {missing}")

DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")

JWT_SECRET = os.getenv("JWT_SECRET")
JWT_EXPIRY_MINUTES = int(os.getenv("JWT_EXPIRY_MINUTES", "60"))

HTTPS_CERT_PATH = os.getenv("HTTPS_CERT_PATH")  # ./certs/cert.pem
HTTPS_KEY_PATH = os.getenv("HTTPS_KEY_PATH")    # ./certs/key.pem
HTTPS_PORT = int(os.getenv("HTTPS_PORT", "8443"))

# --- MySQL connection pool ---
# For local MySQL, TLS is optional (enable if you configure SSL on server).
pool_config = {
    "pool_name": "app_pool",
    "pool_size": 10,
    "pool_reset_session": True,
    "host": DB_HOST,
    "port": DB_PORT,
    "database": DB_NAME,
    "user": DB_USER,
    "password": DB_PASS,
    "charset": "utf8mb4",
    "collation": "utf8mb4_unicode_ci",
    "autocommit": False,
    # If you enable TLS on MySQL, add:
    # "ssl_ca": "/path/to/ca.pem",
    # "ssl_verify_cert": True
}
try:
    cnx_pool = pooling.MySQLConnectionPool(**pool_config)
    log.info("MySQL connection pool created")
except MySQLError as e:
    log.exception("Failed to create MySQL pool: %s", e)
    raise

app = Flask(__name__)

# --- Helpers ---
def validate_username(u: str) -> bool:
    return isinstance(u, str) and re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", u) is not None

def create_jwt(sub: str) -> str:
    payload = {
        "sub": sub,
        "iat": int(time.time()),
        "exp": int((datetime.utcnow() + timedelta(minutes=JWT_EXPIRY_MINUTES)).timestamp())
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def db_execute(query, params=(), fetchone=False, fetchall=False, commit=False):
    """Execute parameterized query safely using pool."""
    conn = None
    cursor = None
    try:
        conn = cnx_pool.get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(query, params)
        if commit:
            conn.commit()
        if fetchone:
            return cursor.fetchone()
        if fetchall:
            return cursor.fetchall()
        return None
    except MySQLError as e:
        if conn:
            conn.rollback()
        log.exception("DB error: %s", e)
        raise
    finally:
        try:
            if cursor: cursor.close()
        finally:
            if conn: conn.close()

# --- Routes ---
@app.get("/api/health")
def health():
    return jsonify(status="ok"), 200

@app.post("/api/register")
def register():
    """
    Body: { "username": "...", "password": "...", "email": "..." }
    Stores bcrypt hash. In production, restrict who can register.
    """
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    email = data.get("email") or None

    if not validate_username(username) or len(password) < 8:
        return jsonify(error="invalid input"), 400

    pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")

    try:
        # UNIQUE(username) / UNIQUE(email) protect duplicates
        db_execute(
            "INSERT INTO users (username, email, password_hash, is_active, created_at) "
            "VALUES (%s, %s, %s, 1, NOW())",
            (username, email, pw_hash),
            commit=True
        )
        return jsonify(success=True, username=username), 201
    except MySQLError as e:
        # 1062 is duplicate key error in MySQL
        if getattr(e, "errno", None) == 1062:
            return jsonify(error="user_exists"), 409
        return jsonify(error="internal_error"), 500

@app.post("/api/login")
def login():
    """
    Body: { "username": "...", "password": "..." }
    Returns { token, expires_in_minutes }
    """
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not validate_username(username) or not isinstance(password, str):
        return jsonify(error="invalid credentials"), 400

    try:
        row = db_execute(
            "SELECT password_hash, is_active FROM users WHERE username = %s",
            (username,),
            fetchone=True
        )
        if not row:
            # fake compare to reduce timing side-channel
            bcrypt.checkpw(b"badpassword", bcrypt.hashpw(b"badpassword", bcrypt.gensalt()))
            return jsonify(error="invalid credentials"), 401

        if int(row["is_active"]) != 1:
            return jsonify(error="account_disabled"), 403

        if not bcrypt.checkpw(password.encode("utf-8"), row["password_hash"].encode("utf-8")):
            return jsonify(error="invalid credentials"), 401

        token = create_jwt(username)
        return jsonify(token=token, expires_in_minutes=JWT_EXPIRY_MINUTES), 200
    except Exception:
        return jsonify(error="internal_error"), 500

@app.get("/api/user/<username>")
def get_user(username):
    if not validate_username(username):
        return jsonify(error="invalid username"), 400
    try:
        row = db_execute(
            "SELECT username, email, created_at FROM users WHERE username = %s",
            (username,),
            fetchone=True
        )
        if not row:
            return jsonify(error="not_found"), 404
        # Only safe fields
        created_at = row["created_at"]
        if isinstance(created_at, (datetime,)):
            created_at = created_at.isoformat()
        return jsonify(username=row["username"], email=row["email"], created_at=created_at), 200
    except Exception:
        return jsonify(error="internal_error"), 500

# --- Start HTTPS server (dev/testing) ---
if __name__ == "__main__":
    log.info("Starting HTTPS server on port %s", HTTPS_PORT)
    app.run(host="0.0.0.0", port=HTTPS_PORT, ssl_context=(HTTPS_CERT_PATH, HTTPS_KEY_PATH), threaded=True)
