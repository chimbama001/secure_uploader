import os
import re
import io
import uuid
import sqlite3

import msal
from urllib.parse import urlencode

from datetime import datetime, timedelta, timezone

from pathlib import Path
from functools import wraps

from dotenv import load_dotenv
load_dotenv(override=True)

from flask import Flask, request, redirect, url_for, session, flash, render_template, render_template_string, g

from werkzeug.utils import secure_filename
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from azure.storage.blob import BlobServiceClient
from kv_crypto import encrypt_file_with_keyvault, decrypt_file_with_keyvault

try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
except Exception:
    Limiter = None
    get_remote_address = None

from crypto_utils import load_key_from_env, encrypt_bytes, decrypt_bytes
from backup_utils import BACKUP_ENCRYPTION_METHOD, create_protected_backup, load_backup_key


active_sessions = {}


def log_event(user_id, username, action, target=None, status="SUCCESS", metadata=None):
    import sqlite3
    import json
    from datetime import datetime
    from flask import request as _req

    try:
        ip_address = _req.remote_addr
    except RuntimeError:
        ip_address = None

    details = {}
    if target:
        details["target"] = target
    if status:
        details["status"] = status
    if metadata:
        if isinstance(metadata, dict):
            details.update(metadata)
        else:
            details["metadata"] = str(metadata)

    try:
        conn = sqlite3.connect("files.db")
        conn.row_factory = sqlite3.Row

        conn.execute(
            """
            INSERT INTO audit_logs
            (event_type, username, user_id, ip_address, details, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                action,
                username,
                user_id,
                ip_address,
                json.dumps(details) if details else None,
                datetime.utcnow().isoformat()
            )
        )

        conn.commit()
        conn.close()

    except Exception as e:
        print("Audit logging failed:", e)



# =============================================================================
# Environment / config
# =============================================================================
load_dotenv("/home/secureuploader/secure_uploader/.env")

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", os.urandom(32))

from datetime import timedelta
app.permanent_session_lifetime = timedelta(minutes=15)

ENV = os.environ.get("FLASK_ENV", "development").lower()
secure_cookies = False

from datetime import timedelta

app.config.update(
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=200 * 1024 * 1024,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),  # Maximum session lifetime
    SESSION_PERMANENT=True,
)

MFA_ENABLED = os.getenv("MFA_ENABLED", "false").lower() == "true"

SIGNUP_ENABLED = os.getenv("SIGNUP_ENABLED", "false").lower() == "true"
SIGNUP_CODE = os.getenv("SIGNUP_CODE", "")

DATA_DIR = os.environ.get("DATA_DIR") or str(Path(__file__).resolve().parent)
DATA_DIR = os.path.abspath(DATA_DIR)
DB_PATH = os.path.join(DATA_DIR, "files.db")

ph = PasswordHasher()

@app.before_request
def load_user():
    g.user = None

    if "user_id" in session:
        conn = db_connect()
        user = conn.execute(
            "SELECT id, username FROM users WHERE id=?",
            (session["user_id"],)
        ).fetchone()
        conn.close()

        if user:
            g.user = user

if Limiter and get_remote_address:
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["500 per hour"],
    )
else:
    limiter = None

if limiter:
    login_limit = limiter.limit("5 per 10 seconds")
    signup_limit = limiter.limit("3 per 10 seconds")
else:
    def login_limit(f):
        return f
    def signup_limit(f):
        return f

@app.before_request
def update_activity():
    if 'user_id' in session and 'session_id' in session and session['session_id'] in active_sessions:
        session_data = active_sessions[session['session_id']]
        now = datetime.datetime.utcnow()
        idle_timeout = 600  # 10 minutes of inactivity
        
        # Check for session expiration before updating
        if (now - session_data['last_activity']).total_seconds() > idle_timeout:
            active_sessions.pop(session['session_id'], None)
            session.clear()
            flash("Your session has expired due to inactivity.")
            return redirect(url_for('login'))
        
        # Update last activity if session is still valid
        active_sessions[session['session_id']]['last_activity'] = now

@app.context_processor
def inject_admin():
    return {'is_admin': is_admin()}

# =============================================================================
# Blob Storage
# =============================================================================
AZURE_STORAGE_CONNECTION_STRING = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
AZURE_STORAGE_CONTAINER = os.getenv("AZURE_STORAGE_CONTAINER", "securevault-files")

blob_service_client = None
container_client = None

if AZURE_STORAGE_CONNECTION_STRING:
    blob_service_client = BlobServiceClient.from_connection_string(
        AZURE_STORAGE_CONNECTION_STRING
    )
    container_client = blob_service_client.get_container_client(
        AZURE_STORAGE_CONTAINER
    )


def upload_blob_bytes(blob_name: str, data: bytes) -> None:
    if container_client:
        blob_client = container_client.get_blob_client(blob_name)
        blob_client.upload_blob(data, overwrite=True)
    else:
        with open(os.path.join(UPLOAD_DIR, blob_name), "wb") as f:
            f.write(data)

def download_blob_bytes(blob_name: str) -> bytes:
    # Try Azure Blob first if configured
    if container_client is not None:
        blob_client = container_client.get_blob_client(blob_name)
        return blob_client.download_blob().readall()

    # Local fallback if Blob is not configured
    local_path = os.path.join(UPLOAD_DIR, blob_name)
    if not os.path.exists(local_path):
        raise FileNotFoundError(f"Local file not found: {local_path}")

    with open(local_path, "rb") as f:
        return f.read()

def delete_blob_bytes(blob_name: str) -> None:
    if container_client is not None:
        blob_client = container_client.get_blob_client(blob_name)
        blob_client.delete_blob(delete_snapshots="include")
        return

    local_path = os.path.join(UPLOAD_DIR, blob_name)
    if os.path.exists(local_path):
        os.remove(local_path)

def blob_exists(blob_name):
    if container_client is not None:
        try:
            blob_client = container_client.get_blob_client(blob_name)
            return blob_client.exists()
        except Exception as e:
            app.logger.exception(f"blob_exists failed for {blob_name}: {e}")
            return False

    local_path = os.path.join(UPLOAD_DIR, blob_name)
    return os.path.exists(local_path)

# =============================================================================
# Encryption key
# =============================================================================
ph = PasswordHasher()

# Data directory (persistent)
DATA_DIR = os.environ.get("DATA_DIR") or str(Path(__file__).resolve().parent)
DATA_DIR = os.path.abspath(DATA_DIR)
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
BACKUP_DIR = os.path.join(DATA_DIR, "backups")
DB_PATH = os.path.join(DATA_DIR, "files.db")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(BACKUP_DIR, exist_ok=True)

MAX_CONTENT_LENGTH = 200 * 1024 * 1024
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
app.config["UPLOAD_DIR"] = UPLOAD_DIR
app.config["BACKUP_DIR"] = BACKUP_DIR


# Encryption key for server-side encryption
# ENC_KEY_B64 = load_backup_key()  # disabled after Key Vault migration
  # uses env var or fallback, per your crypto_utils


# =============================================================================
# DB helpers
# =============================================================================
def db_connect():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000;")
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def ensure_column(conn, table: str, column: str, ddl: str):
    cols = [row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()]
    if column not in cols:
        conn.execute(ddl)

def ensure_schema():
    conn = db_connect()
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      created_at TEXT NOT NULL
    );
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS files (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      filename TEXT NOT NULL,
      orig_name TEXT,
      stored_name TEXT NOT NULL,
      mime TEXT,
      size INTEGER NOT NULL DEFAULT 0,
      uploaded_at TEXT NOT NULL,
      owner_id INTEGER NOT NULL DEFAULT 0,
      client_encrypted INTEGER NOT NULL DEFAULT 0
    );
    """)

    conn.execute("""
    CREATE TABLE IF NOT EXISTS file_shares (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_id INTEGER NOT NULL,
        owner_id INTEGER NOT NULL,
        recipient_id INTEGER NOT NULL,
        share_password_hash TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(file_id, recipient_id),
        FOREIGN KEY(file_id) REFERENCES files(id),
        FOREIGN KEY(owner_id) REFERENCES users(id),
        FOREIGN KEY(recipient_id) REFERENCES users(id)
    );
    """)

    # INCIDENT REPORTS
    c.execute("""
    CREATE TABLE IF NOT EXISTS incident_reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      severity TEXT NOT NULL DEFAULT 'medium',
      status TEXT NOT NULL DEFAULT 'open',
      reported_by INTEGER NOT NULL,
      reported_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      reviewed_by INTEGER,
      reviewed_at TEXT
    );
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS incident_actions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      incident_id INTEGER NOT NULL,
      action_note TEXT NOT NULL,
      status_after TEXT NOT NULL,
      action_by INTEGER NOT NULL,
      action_at TEXT NOT NULL
    );
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS backup_records (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      backup_name TEXT NOT NULL,
      stored_name TEXT NOT NULL UNIQUE,
      size INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      created_by INTEGER NOT NULL,
      is_encrypted INTEGER NOT NULL DEFAULT 1,
      encryption_method TEXT NOT NULL DEFAULT 'AES-GCM'
    );
    """)

    ensure_column(
        conn,
        "backup_records",
        "is_encrypted",
        "ALTER TABLE backup_records ADD COLUMN is_encrypted INTEGER NOT NULL DEFAULT 1"
    )
    ensure_column(
        conn,
        "backup_records",
        "encryption_method",
        "ALTER TABLE backup_records ADD COLUMN encryption_method TEXT NOT NULL DEFAULT 'AES-GCM'"
    )

    ensure_column(
    conn,
    "file_access",
    "can_share",
    "ALTER TABLE file_access ADD COLUMN can_share INTEGER NOT NULL DEFAULT 0"
    )

    c.execute("""
    CREATE TABLE IF NOT EXISTS password_reset_requests (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id       INTEGER NOT NULL,
      username      TEXT NOT NULL,
      status        TEXT NOT NULL DEFAULT 'pending',
      requested_at  TEXT NOT NULL,
      resolved_at   TEXT,
      resolved_by   INTEGER
    );
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS maintenance_personnel (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      approved_by INTEGER NOT NULL,
      approved_at TEXT NOT NULL,
      reason TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'active',
      revoked_by INTEGER,
      revoked_at TEXT,
      revoke_reason TEXT,
      FOREIGN KEY (user_id) REFERENCES users(id),
      FOREIGN KEY (approved_by) REFERENCES users(id)
    );
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS maintenance_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      personnel_id INTEGER NOT NULL,
      action TEXT NOT NULL,
      performed_by INTEGER NOT NULL,
      performed_at TEXT NOT NULL,
      notes TEXT,
      FOREIGN KEY (personnel_id) REFERENCES maintenance_personnel(id),
      FOREIGN KEY (performed_by) REFERENCES users(id)
    );
    """)

    conn.commit()
    conn.close()

ensure_schema()

# =============================================================================
# Helpers
# =============================================================================
PASSWORD_REGEX = re.compile(
    r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#^])[A-Za-z\d@$!%*?&#^]{12,}$'
)
INCIDENT_SEVERITIES = ("low", "medium", "high")
INCIDENT_STATUSES = ("open", "investigating", "resolved")

def validate_password_complexity(pw: str) -> bool:
    return bool(PASSWORD_REGEX.match(pw))

def valid_password(pw: str) -> bool:
    return validate_password_complexity(pw)

def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapped

@app.before_request
def load_user():
    g.user = None
    uid = session.get("user_id")
    if not uid:
        return
    conn = db_connect()
    row = conn.execute(
        "SELECT id, username, role FROM users WHERE id=?",
        (uid,)
    ).fetchone()
    conn.close()
    if row:
        g.user = dict(row)

def is_admin():
    return bool(g.user) and g.user.get("role") == "admin"


def get_incident_actions(incident_ids):
    if not incident_ids:
        return {}

    placeholders = ",".join("?" for _ in incident_ids)
    conn = db_connect()
    rows = conn.execute(
        f"""
        SELECT ia.incident_id, ia.action_note, ia.status_after, ia.action_at,
               actor.username AS actor_name
        FROM incident_actions ia
        JOIN users actor ON actor.id = ia.action_by
        WHERE ia.incident_id IN ({placeholders})
        ORDER BY ia.action_at DESC
        """,
        tuple(incident_ids)
    ).fetchall()
    conn.close()

    actions_by_incident = {incident_id: [] for incident_id in incident_ids}
    for row in rows:
        actions_by_incident.setdefault(row["incident_id"], []).append(row)
    return actions_by_incident

def get_shared_files_for_user(user_id):
    conn = db_connect()
    try:
        rows = conn.execute(
            """
            SELECT
                f.id,
                f.filename,
                f.orig_name,
                f.stored_name,
                f.mime,
                f.size,
                f.uploaded_at,
                f.owner_id,
                f.client_encrypted,
                fa.can_read,
                fa.can_delete,
                fa.can_share,
                fa.share_password_hash,
                u.username AS owner_username
            FROM file_access fa
            JOIN files f ON fa.file_id = f.id
            JOIN users u ON u.id = f.owner_id
            WHERE fa.user_id = ? AND fa.can_read = 1
            ORDER BY f.uploaded_at DESC
            """,
            (int(user_id),)
        ).fetchall()
        return rows
    finally:
        conn.close()

def build_msal_app(cache=None):
    return msal.ConfidentialClientApplication(
        os.getenv("ENTRA_CLIENT_ID"),
        authority=f"https://login.microsoftonline.com/{os.getenv('ENTRA_TENANT_ID')}",
        client_credential=os.getenv("ENTRA_CLIENT_SECRET"),
        token_cache=cache,
    )

def build_auth_url(scopes=None, state=None):
    return build_msal_app().get_authorization_request_url(
        scopes=scopes or ["User.Read"],
        state=state,
        redirect_uri=os.getenv("ENTRA_REDIRECT_URI"),
        prompt="select_account",
    )

# =============================================================================
# Templates
# =============================================================================
BASE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>{{ title }}</title>

  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>

<body>

<nav class="navbar navbar-expand-lg navbar-dark bg-primary">
  <div class="container">
    <a class="navbar-brand" href="{{ url_for('login') }}">Secure Uploader</a>

    <div class="ms-auto">
      {% if session.get('user_id') %}
        <a class="btn btn-sm btn-outline-light me-2" href="{{ url_for('files') }}">Files</a>
        <a class="btn btn-sm btn-outline-light me-2" href="{{ url_for('upload') }}">Upload</a>
        <a class="btn btn-sm btn-outline-light me-2" href="{{ url_for('incidents') }}">Incidents</a>
        <a class="btn btn-sm btn-outline-light me-2" href="{{ url_for('maintenance_personnel') }}">Maintenance</a>
        {% if g.user.role == 'admin' %}
        <a class="btn btn-sm btn-outline-light me-2" href="{{ url_for('backups') }}">Backups</a>
        {% endif %}
        <a class="btn btn-sm btn-outline-light" href="{{ url_for('logout') }}">Logout</a>
      {% else %}
        <a class="btn btn-sm btn-outline-light me-2" href="{{ url_for('login') }}">Login</a>
      {% endif %}
    </div>
  </div>
</nav>

<div class="container py-4">

  {% with messages = get_flashed_messages() %}
    {% if messages %}
      <div class="alert alert-info">
        {% for m in messages %}
          <div>{{ m }}</div>
        {% endfor %}
      </div>
    {% endif %}
  {% endwith %}

  {{ body|safe }}

</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>

</body>
</html>
"""


def page(title: str, body: str):
    return render_template_string(BASE, title=title, body=body, signup_enabled=SIGNUP_ENABLED)

# =============================================================================
# Routes
# =============================================================================

SIGNUP_FORM = """
<div class="row justify-content-center">
  <div class="col-md-6">
    <div class="card shadow-sm">
      <div class="card-body">
        <h3 class="card-title">Sign Up</h3>
        <p class="text-muted">Create a standard user account.</p>
        <form method="post">
          <div class="mb-3">
            <label class="form-label">Username</label>
            <input class="form-control" name="username" value="{{ username }}" required>
          </div>
          <div class="mb-3">
            <label class="form-label">Password</label>
            <input class="form-control" type="password" name="password" required>
            <div class="form-text">12+ chars, upper/lower/number/special.</div>
          </div>
          <div class="mb-3">
            <label class="form-label">Confirm Password</label>
            <input class="form-control" type="password" name="confirm" required>
          </div>
          <div class="mb-3">
            <label class="form-label">Signup Code</label>
            <input class="form-control" name="signup_code" value="{{ signup_code }}" required>
          </div>
          <button class="btn btn-primary">Create Account</button>
          <a class="btn btn-link" href="/login">Login</a>
        </form>
      </div>
    </div>
  </div>
</div>
"""

@app.route("/")
def home():
    if not session.get("seen_onboarding"):
        return redirect("/onboarding")

    admin_button = ""
    if g.user and g.user.get("role") == "admin":
        admin_button = "<a class='btn btn-secondary' href='/add-user'>Add User</a> <a class='btn btn-dark' href='/audit-logs'>Audit Logs</a>"

    body = f"""
    <h2>Secure Uploader</h2>
    <p>Authenticated access is required before protected resources are available.</p>
    <a class='btn btn-primary' href='/upload'>Upload</a>
    <a class='btn btn-secondary' href='/files'>View Files</a>
    {admin_button}
    """
    return page("Home", body)

@app.route("/onboarding")
def onboarding():
    if session.get("seen_onboarding"):
        return redirect(url_for("files"))

    body = """
    <style>
    .onboard-card {
        background: rgba(255, 255, 255, 0.15);
        backdrop-filter: blur(12px);
        border-radius: 20px;
        padding: 40px;
        max-width: 700px;
        margin: auto;
        color: #000;
        box-shadow: 0 8px 32px rgba(0,0,0,0.2);
    }
    .carousel-item {
        min-height: 300px;
    }
    </style>

    <div class="d-flex justify-content-center align-items-center" style="height:70vh;">
      <div id="onboardingCarousel" class="carousel slide w-100" data-bs-ride="carousel">
        <div class="carousel-inner text-center">

          <div class="carousel-item active">
            <div class="onboard-card">
              <h2>Welcome to SecureVault 🔐</h2>
              <p>Create an account or log in to begin using the platform securely.</p>
              <p><b>Step 1:</b> Sign up and authenticate to access your workspace.</p>
            </div>
          </div>

          <div class="carousel-item">
            <div class="onboard-card">
              <h2>Upload Files Securely 📤</h2>
              <p>Upload images and files through a protected interface.</p>
              <p><b>Step 2:</b> Files are encrypted before storage.</p>
            </div>
          </div>

          <div class="carousel-item">
            <div class="onboard-card">
              <h2>Share & Download 📥</h2>
              <p>Access your uploaded files securely anytime.</p>
              <p><b>Step 3:</b> Controlled and authorized access only.</p>
              <a href="/finish-onboarding" class="btn btn-primary mt-3">Get Started</a>
            </div>
          </div>

        </div>

        <button class="carousel-control-prev" type="button" data-bs-target="#onboardingCarousel" data-bs-slide="prev">
          <span class="carousel-control-prev-icon"></span>
        </button>

        <button class="carousel-control-next" type="button" data-bs-target="#onboardingCarousel" data-bs-slide="next">
          <span class="carousel-control-next-icon"></span>
        </button>
      </div>
    </div>
    """
    return page("Welcome", body)

@app.route("/finish-onboarding")
def finish_onboarding():
    session["seen_onboarding"] = True
    return redirect("/signup")

def utc_now():
    return datetime.now(timezone.utc)

def parse_iso_dt(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except Exception:
        return None

def get_max_failed_attempts():
    try:
        return int(os.getenv("MAX_FAILED_ATTEMPTS", "3"))
    except ValueError:
        return 3

def get_lockout_minutes():
    try:
        return int(os.getenv("LOCKOUT_MINUTES", "1"))
    except ValueError:
        return 1

def is_account_locked(user_row):
    locked_until = parse_iso_dt(user_row["locked_until"])
    if not locked_until:
        return False
    return locked_until > utc_now()

def clear_lockout_state(conn, user_id):
    conn.execute("""
        UPDATE users
        SET failed_login_count = 0,
            last_failed_login = NULL,
            locked_until = NULL
        WHERE id = ?
    """, (user_id,))
    conn.commit()

def record_failed_login(conn, user_row):
    current_count = int(user_row["failed_login_count"] or 0) + 1
    now = utc_now()
    locked_until = None

    if current_count >= get_max_failed_attempts():
        locked_until = (now + timedelta(minutes=get_lockout_minutes())).isoformat()

    conn.execute("""
        UPDATE users
        SET failed_login_count = ?,
            last_failed_login = ?,
            locked_until = ?
        WHERE id = ?
    """, (
        current_count,
        now.isoformat(),
        locked_until,
        user_row["id"]
    ))
    conn.commit()

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        body = """
        <div class="row justify-content-center">
          <div class="col-md-6">
            <div class="card shadow-sm">
              <div class="card-body">
                <h3 class="card-title">Login</h3>
                <form method="post" action="/login">
                  <div class="mb-3">
                    <label class="form-label">Username</label>
                    <input class="form-control" type="text" name="username" required>
                  </div>
                  <div class="mb-3">
                    <label class="form-label">Password</label>
                    <input class="form-control" type="password" name="password" required>
                  </div>
                  <button class="btn btn-primary" type="submit">Log in</button>
                  <a class="btn btn-link" href="/forgot-password">Forgot Password?</a>
                </form>
              </div>
            </div>
          </div>
        </div>
        """
        return page("Login", body)

        conn = db_connect()
        row = conn.execute(
            "SELECT id, username, password_hash FROM users WHERE username=?",
            (username,)
        ).fetchone()
        conn.close()
        flash("Invalid username or password.")
        return render_template("login.html")

    if is_account_locked(row):
        conn.close()
        flash("Account is temporarily locked due to repeated failed login attempts. Please try again later.")
        return render_template("login.html")

    try:
        ph.verify(row["password_hash"], password)
    except VerifyMismatchError:
        record_failed_login(conn, row)
        conn.close()
        log_event(row["id"], username, "LOGIN", status="FAIL")
        flash("Invalid username or password.")
        return render_template("login.html")

        session["user_id"] = row["id"]
        session['session_id'] = str(uuid.uuid4())
        active_sessions[session['session_id']] = {
            'user_id': row["id"],
            'username': row["username"],
            'login_time': datetime.datetime.utcnow(),
            'last_activity': datetime.datetime.utcnow(),
            'ip': request.remote_addr
        }
        flash("Logged in successfully.")
        if not session.get("seen_onboarding"):
              return redirect(url_for("onboarding"))
        return redirect(url_for("files"))

    session.permanent = True
    session["user_id"] = row["id"]
    flash("Logged in successfully.")

    if not session.get("seen_onboarding"):
        return redirect(url_for("onboarding"))

    return redirect(url_for("files"))


@app.route("/auth/callback")
def auth_callback():
    if request.args.get("state") != session.get("auth_state"):
        abort(400, "State mismatch")

    if "error" in request.args:
        return f"Login failed: {request.args.get('error_description', request.args.get('error'))}", 400

    code = request.args.get("code")
    if not code:
        return "Missing authorization code.", 400

    result = build_msal_app().acquire_token_by_authorization_code(
        code,
        scopes=["User.Read"],
        redirect_uri=os.getenv("ENTRA_REDIRECT_URI"),
    )

    if "error" in result:
        return f"Token error: {result.get('error_description', result.get('error'))}", 400

    claims = result.get("id_token_claims", {})

    session.clear()
    session["user_id"] = claims.get("oid") or claims.get("sub")
    session["username"] = claims.get("preferred_username") or claims.get("email") or claims.get("name")
    session["role"] = "User"

    flash("Logged in successfully.")
    if not session.get("seen_onboarding"):
        return redirect(url_for("onboarding"))
    return redirect(url_for("files"))

@app.route("/signup", methods=["GET", "POST"])
@signup_limit
def signup():
    if not SIGNUP_ENABLED:
        abort(404)

    # Store form values (except passwords)
    form_data = {
        "username": "",
        "signup_code": ""
    }

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm") or ""
        signup_code = (request.form.get("signup_code") or "").strip()

        # Save values to persist in form
        form_data["username"] = username
        form_data["signup_code"] = signup_code

        # --- VALIDATION ---
        if not username or not password or not confirm or not signup_code:
            flash("All fields are required.")
            return page("Sign Up", render_template_string(SIGNUP_FORM, **form_data))

        if password != confirm:
            flash("Passwords do not match. Enter a new password.")
            return page("Sign Up", render_template_string(SIGNUP_FORM, **form_data))

        if not valid_password(password):
            flash("Password must be 12+ chars with upper, lower, number, and special character.")
            return page("Sign Up", render_template_string(SIGNUP_FORM, **form_data))

        if not SIGNUP_CODE or signup_code != SIGNUP_CODE:
            flash("Invalid signup code.")
            return page("Sign Up", render_template_string(SIGNUP_FORM, **form_data))

        # --- CHECK USER ---
        conn = db_connect()
        existing = conn.execute(
            "SELECT id FROM users WHERE username=?",
            (username,)
        ).fetchone()

        if existing:
            conn.close()
            flash("Username already exists.")
            return page("Sign Up", render_template_string(SIGNUP_FORM, **form_data))

        # --- CREATE USER ---
        password_hash = ph.hash(password)
        conn.execute(
            "INSERT INTO users(username, password_hash, role, created_at) VALUES (?,?,?,?)",
            (username, password_hash, "user", datetime.datetime.utcnow().isoformat())
        )
        conn.commit()
        conn.close()

        flash("Account created successfully. Please log in.")
        return redirect(url_for("login"))

    return page("Sign Up", render_template_string(SIGNUP_FORM, **form_data))

@app.route("/logout")
def logout():
    if 'session_id' in session:
        active_sessions.pop(session['session_id'], None)
    session.clear()
    flash("Logged out.")
    return redirect(url_for("home"))

@app.route("/active-sessions")
@login_required
def active_sessions_view():
    if not is_admin():
        abort(403)
    now = datetime.datetime.utcnow()
    # Consider active if last activity within 30 seconds
    active = {k: v for k, v in active_sessions.items() if (now - v['last_activity']).total_seconds() < 30}
    return render_template('active_sessions.html', sessions=list(active.values()), now=now)

@app.route("/audit-logs")
@login_required
def audit_logs():
    if not is_admin():
        abort(403)
    conn = db_connect()
    logs = conn.execute("""
        SELECT timestamp, username, action, target, status, metadata
        FROM audit_log
        ORDER BY timestamp DESC
        LIMIT 1000
    """).fetchall()
    conn.close()
    return render_template('audit_logs.html', logs=logs)

@app.route("/add-user", methods=["GET", "POST"])
def add_user():
    conn = db_connect()
    user_count = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
    conn.close()

    if user_count > 0 and not (g.user and is_admin()):
        flash("Admin required to add users.")
        return redirect(url_for("login"))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        role = (request.form.get("role") or "user").strip().lower()

        if role not in ("user", "admin"):
            role = "user"

        if not valid_password(password):
            flash("Password must be 12+ chars and include upper/lower/number/special.")
            return redirect(url_for("add_user"))

        pw_hash = ph.hash(password)

        conn = db_connect()
        try:
            conn.execute(
                "INSERT INTO users(username, password_hash, role, created_at) VALUES (?,?,?,?)",
                (username, pw_hash, role, datetime.datetime.utcnow().isoformat())
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            flash("Username already exists.")
            return redirect(url_for("add_user"))
        conn.close()

        flash("User created.")
        return redirect(url_for("login"))

    body = """
    <div class="row justify-content-center">
      <div class="col-md-7">
        <div class="card shadow-sm">
          <div class="card-body">
            <h3 class="card-title">Add User</h3>
            <p class="text-muted">First user can be admin. After that, admin only.</p>
            <form method="post">
              <div class="mb-3">
                <label class="form-label">Username</label>
                <input class="form-control" name="username" required>
              </div>
              <div class="mb-3">
                <label class="form-label">Password</label>
                <input class="form-control" type="password" name="password" required>
                <div class="form-text">12+ chars, upper/lower/number/special.</div>
              </div>
              <div class="mb-3">
                <label class="form-label">Role</label>
                <select class="form-select" name="role">
                  <option value="admin">admin</option>
                  <option value="user" selected>user</option>
                </select>
              </div>
              <button class="btn btn-primary">Create</button>
              <a class="btn btn-link" href="/">Home</a>
            </form>
          </div>
        </div>
      </div>
    </div>
    """
    return page("Add User", body)

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        f = request.files.get("file")
        if not f or not f.filename:
            flash("No file selected.")
            return redirect(url_for("upload"))

        orig_name = secure_filename(f.filename)
        mime = f.mimetype or "application/octet-stream"
        file_bytes = f.read()

        if not file_bytes:
            flash("Empty upload.")
            return redirect(url_for("upload"))

        client_encrypted = bool(request.form.get("client_encrypted"))
        blob_data = file_bytes if client_encrypted else encrypt_bytes(file_bytes, ENC_KEY_B64)

        stored_name = f"{uuid.uuid4().hex}.bin"

        try:
            upload_blob_bytes(stored_name, blob_data)
        except Exception as e:
            flash(f"Blob upload failed: {e}")
            return redirect(url_for("upload"))

        conn = db_connect()
        conn.execute(
            """
            INSERT INTO files(filename, orig_name, stored_name, mime, size, uploaded_at, owner_id, client_encrypted)
            VALUES (?,?,?,?,?,?,?,?)
            """,
            (
                orig_name,
                orig_name,
                stored_name,
                mime,
                len(file_bytes),
                datetime.utcnow().isoformat(),
                int(g.user["id"]),
                1 if client_encrypted else 0,
            )
        )
        conn.commit()
        conn.close()

        flash("Uploaded successfully.")
        return redirect(url_for("files"))

    body = """
    <div class="row justify-content-center">
      <div class="col-md-8">
        <div class="card shadow-sm">
          <div class="card-body">
            <h3 class="card-title">Upload a file</h3>
            <p class="text-muted">Server-side encryption is applied unless you choose browser encryption.</p>
            <form method="post" enctype="multipart/form-data">
              <div class="mb-3">
                <input class="form-control" type="file" name="file" required>
              </div>
              <button class="btn btn-primary">Upload</button>
              <a class="btn btn-link" href="/files">View Files</a>
            </form>
          </div>
        </div>
      </div>
    </div>
    """
    return page("Upload", body)


@app.route("/files")
@login_required
def files():
    uid = int(g.user["id"])
    conn = db_connect()

    if is_admin():
        owned_rows = conn.execute(
            """
            SELECT id, filename, orig_name, stored_name, mime, size, uploaded_at, owner_id, client_encrypted
            FROM files
            ORDER BY uploaded_at DESC
            """
        ).fetchall()
        shared_rows = []
    else:
        owned_rows = conn.execute(
            """
            SELECT id, filename, orig_name, stored_name, mime, size, uploaded_at, owner_id, client_encrypted
            FROM files
            WHERE owner_id=?
            ORDER BY uploaded_at DESC
            """,
            (uid,)
        ).fetchall()

        shared_rows = conn.execute(
            """
            SELECT
                f.id,
                f.filename,
                f.orig_name,
                f.stored_name,
                f.mime,
                f.size,
                f.uploaded_at,
                f.owner_id,
                f.client_encrypted,
                fa.can_read,
                fa.can_delete,
                fa.can_share,
                u.username AS owner_username
            FROM file_access fa
            JOIN files f ON fa.file_id = f.id
            JOIN users u ON u.id = f.owner_id
            WHERE fa.user_id=? AND fa.can_read=1
            ORDER BY f.uploaded_at DESC
            """,
            (uid,)
        ).fetchall()

    conn.close()

    body = render_template_string(
        """
        <div class="d-flex justify-content-between align-items-center mb-3">
          <div>
            <h3 class="mb-1">Files</h3>
            <p class="text-muted mb-0">View your uploaded files and files shared with you.</p>
          </div>
          <a class="btn btn-primary" href="{{ url_for('upload') }}">Upload File</a>
        </div>

        <div class="card shadow-sm mb-4">
          <div class="card-body">
            <h4 class="h5">My Uploaded Files</h4>
            {% if owned_rows %}
              <div class="table-responsive">
                <table class="table table-striped align-middle">
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>Size</th>
                      <th>Uploaded</th>
                      <th>Encryption</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {% for r in owned_rows %}
                      <tr>
                        <td>{{ r["orig_name"] or r["filename"] or "unknown" }}</td>
                        <td>{{ r["size"] }} bytes</td>
                        <td>{{ r["uploaded_at"] }}</td>
                        <td>{{ "Client" if r["client_encrypted"] == 1 else "Server" }}</td>
                        <td>
                          <a class="btn btn-sm btn-outline-primary me-2" href="{{ url_for('download', file_id=r['id']) }}">Download</a>
                          <a class="btn btn-sm btn-outline-danger me-2" href="{{ url_for('delete', file_id=r['id']) }}">Delete</a>

                          <form method="post" action="{{ url_for('share_file', file_id=r['id']) }}" class="d-inline-flex gap-1 align-items-center flex-wrap">
                            <input class="form-control form-control-sm" name="username" placeholder="username" style="width:130px;" required>
                            <input class="form-control form-control-sm" name="share_password" type="password" placeholder="share password" style="width:150px;" required>
                            <button class="btn btn-sm btn-outline-secondary">Share</button>
                          </form>
                        </td>
                      </tr>
                    {% endfor %}
                  </tbody>
                </table>
              </div>
            {% else %}
              <p class="text-muted mb-0">You have not uploaded any files yet.</p>
            {% endif %}
          </div>
        </div>

        {% if not is_admin_user %}
        <div class="card shadow-sm">
          <div class="card-body">
            <h4 class="h5">Files Shared With Me</h4>
            {% if shared_rows %}
              <div class="table-responsive">
                <table class="table table-striped align-middle">
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>Shared By</th>
                      <th>Size</th>
                      <th>Uploaded</th>
                      <th>Encryption</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {% for r in shared_rows %}
                      <tr>
                        <td>{{ r["orig_name"] or r["filename"] or "unknown" }}</td>
                        <td>{{ r["owner_username"] }}</td>
                        <td>{{ r["size"] }} bytes</td>
                        <td>{{ r["uploaded_at"] }}</td>
                        <td>{{ "Client" if r["client_encrypted"] == 1 else "Server" }}</td>
                        <td>
                          <a class="btn btn-sm btn-outline-primary" href="{{ url_for('download', file_id=r['id']) }}">Download</a>
                        </td>
                      </tr>
                    {% endfor %}
                  </tbody>
                </table>
              </div>
            {% else %}
              <p class="text-muted mb-0">No files have been shared with you yet.</p>
            {% endif %}
          </div>
        </div>
        {% endif %}
        """,
        owned_rows=owned_rows,
        shared_rows=shared_rows,
        is_admin_user=is_admin(),
    )

    return page("Files", body)

@app.route("/incidents", methods=["GET", "POST"])
@login_required
def incidents():
    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        description = (request.form.get("description") or "").strip()
        severity = (request.form.get("severity") or "medium").strip().lower()

        if severity not in INCIDENT_SEVERITIES:
            severity = "medium"

        if not title or not description:
            flash("Title and description are required.")
            return redirect(url_for("incidents"))

        now = datetime.utcnow().isoformat()
        conn = db_connect()
        conn.execute(
            """
            INSERT INTO incident_reports(title, description, severity, status, reported_by, reported_at, updated_at)
            VALUES (?,?,?,?,?,?,?)
            """,
            (title, description, severity, "open", int(g.user["id"]), now, now)
        )
        conn.commit()
        conn.close()

        flash("Incident report submitted.")
        return redirect(url_for("incidents"))

    conn = db_connect()
    if is_admin():
        rows = conn.execute(
            """
            SELECT ir.id, ir.title, ir.description, ir.severity, ir.status,
                   ir.reported_at, ir.updated_at, ir.reviewed_at,
                   reporter.username AS reporter_name,
                   reviewer.username AS reviewer_name
            FROM incident_reports ir
            JOIN users reporter ON reporter.id = ir.reported_by
            LEFT JOIN users reviewer ON reviewer.id = ir.reviewed_by
            ORDER BY ir.reported_at DESC
            """
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT ir.id, ir.title, ir.description, ir.severity, ir.status,
                   ir.reported_at, ir.updated_at, ir.reviewed_at,
                   reporter.username AS reporter_name,
                   reviewer.username AS reviewer_name
            FROM incident_reports ir
            JOIN users reporter ON reporter.id = ir.reported_by
            LEFT JOIN users reviewer ON reviewer.id = ir.reviewed_by
            WHERE ir.reported_by=?
            ORDER BY ir.reported_at DESC
            """,
            (int(g.user["id"]),)
        ).fetchall()
    conn.close()
    actions_by_incident = get_incident_actions([row["id"] for row in rows])

    body = render_template_string(
        """
        <div class="d-flex justify-content-between align-items-center mb-3">
          <div>
            <h3 class="mb-1">Incident Handling</h3>
            <p class="text-muted mb-0">Document incidents, track response actions, and follow them through resolution.</p>
          </div>
        </div>

        <div class="row g-4">
          <div class="col-lg-5">
            <div class="card shadow-sm">
              <div class="card-body">
                <h4 class="h5">Report an Incident</h4>
                <form method="post">
                  <div class="mb-3">
                    <label class="form-label">Title</label>
                    <input class="form-control" name="title" maxlength="120" required>
                  </div>
                  <div class="mb-3">
                    <label class="form-label">Severity</label>
                    <select class="form-select" name="severity">
                      {% for severity in severities %}
                        <option value="{{ severity }}">{{ severity.title() }}</option>
                      {% endfor %}
                    </select>
                  </div>
                  <div class="mb-3">
                    <label class="form-label">Description</label>
                    <textarea class="form-control" name="description" rows="5" required></textarea>
                  </div>
                  <button class="btn btn-primary">Submit Report</button>
                </form>
              </div>
            </div>
          </div>

          <div class="col-lg-7">
            <div class="card shadow-sm">
              <div class="card-body">
                <div class="d-flex justify-content-between align-items-center mb-3">
                  <h4 class="h5 mb-0">{{ "All Reports" if can_manage else "My Reports" }}</h4>
                  {% if can_manage %}
                    <span class="badge bg-secondary">Admin review enabled</span>
                  {% endif %}
                </div>

                {% if incidents %}
                  <div class="accordion" id="incidentList">
                    {% for incident in incidents %}
                      <div class="accordion-item">
                        <h2 class="accordion-header" id="incident-heading-{{ incident['id'] }}">
                          <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#incident-{{ incident['id'] }}" aria-expanded="false">
                            <span class="me-3 fw-semibold">{{ incident["title"] }}</span>
                            <span class="badge bg-danger-subtle text-danger border me-2">{{ incident["severity"].title() }}</span>
                            <span class="badge bg-light text-dark border">{{ incident["status"].replace("_", " ").title() }}</span>
                          </button>
                        </h2>
                        <div id="incident-{{ incident['id'] }}" class="accordion-collapse collapse" data-bs-parent="#incidentList">
                          <div class="accordion-body">
                            <p class="mb-2">{{ incident["description"] }}</p>
                            <p class="small text-muted mb-2">
                              Reported by {{ incident["reporter_name"] }} on {{ incident["reported_at"] }}
                            </p>
                            {% if incident["reviewer_name"] %}
                              <p class="small text-muted">Last reviewed by {{ incident["reviewer_name"] }} on {{ incident["reviewed_at"] }}</p>
                            {% endif %}
                            <hr>
                            <h5 class="h6">Response Actions</h5>
                            {% set incident_actions = actions.get(incident["id"], []) %}
                            {% if incident_actions %}
                              <div class="mb-3">
                                {% for action in incident_actions %}
                                  <div class="border rounded p-2 mb-2">
                                    <div class="d-flex justify-content-between align-items-center">
                                      <strong>{{ action["status_after"].replace("_", " ").title() }}</strong>
                                      <span class="small text-muted">{{ action["action_at"] }}</span>
                                    </div>
                                    <div>{{ action["action_note"] }}</div>
                                    <div class="small text-muted">Handled by {{ action["actor_name"] }}</div>
                                  </div>
                                {% endfor %}
                              </div>
                            {% else %}
                              <p class="text-muted">No response actions logged yet.</p>
                            {% endif %}
                            {% if can_manage %}
                              <form method="post" action="{{ url_for('handle_incident', incident_id=incident['id']) }}">
                                <div class="mb-2">
                                  <label class="form-label">Response Action</label>
                                  <textarea class="form-control" name="action_note" rows="3" placeholder="Describe the investigation, containment step, or resolution action." required></textarea>
                                </div>
                                <div class="d-flex gap-2 align-items-center">
                                  <select class="form-select" name="status" style="max-width: 220px;">
                                    {% for status in statuses %}
                                      <option value="{{ status }}" {% if status == incident["status"] %}selected{% endif %}>{{ status.replace("_", " ").title() }}</option>
                                    {% endfor %}
                                  </select>
                                  <button class="btn btn-outline-primary btn-sm">Log Action</button>
                                </div>
                              </form>
                            {% endif %}
                          </div>
                        </div>
                      </div>
                    {% endfor %}
                  </div>
                {% else %}
                  <p class="text-muted mb-0">No incident reports yet.</p>
                {% endif %}
              </div>
            </div>
          </div>
        </div>
        """,
        incidents=rows,
        actions=actions_by_incident,
        severities=INCIDENT_SEVERITIES,
        statuses=INCIDENT_STATUSES,
        can_manage=is_admin(),
    )
    return render_template_string(BASE, title="Incident Handling", body=body)


@app.route("/incidents/<int:incident_id>/handle", methods=["POST"])
@login_required
def handle_incident(incident_id: int):
    if not is_admin():
        abort(403)

    action_note = (request.form.get("action_note") or "").strip()
    status = (request.form.get("status") or "").strip().lower()
    if not action_note:
        flash("A response action note is required.")
        return redirect(url_for("incidents"))

    if status not in INCIDENT_STATUSES:
        flash("Invalid incident status.")
        return redirect(url_for("incidents"))

    conn = db_connect()
    row = conn.execute("SELECT id FROM incident_reports WHERE id=?", (incident_id,)).fetchone()
    if not row:
        conn.close()
        abort(404)

    now = datetime.utcnow().isoformat()
    conn.execute(
        """
        INSERT INTO incident_actions(incident_id, action_note, status_after, action_by, action_at)
        VALUES (?,?,?,?,?)
        """,
        (incident_id, action_note, status, int(g.user["id"]), now)
    )
    conn.execute(
        """
        UPDATE incident_reports
        SET status=?, updated_at=?, reviewed_by=?, reviewed_at=?
        WHERE id=?
        """,
        (status, now, int(g.user["id"]), now, incident_id)
    )
    conn.commit()
    conn.close()

    flash("Incident response action logged.")
    return redirect(url_for("incidents"))


@app.route("/backups", methods=["GET", "POST"])
@login_required
def backups():
    if not is_admin():
        abort(403)

    if request.method == "POST":
        try:
            backup_info = create_protected_backup(
                DB_PATH,
                app.config["UPLOAD_DIR"],
                app.config["BACKUP_DIR"],
                ENC_KEY_B64,
            )
            conn = db_connect()
            conn.execute(
                """
                INSERT INTO backup_records(backup_name, stored_name, size, created_at, created_by, is_encrypted, encryption_method)
                VALUES (?,?,?,?,?,?,?)
                """,
                (
                    backup_info["name"],
                    backup_info["path"].name,
                    int(backup_info["size"]),
                    datetime.utcnow().isoformat(),
                    int(g.user["id"]),
                    1 if backup_info["is_encrypted"] else 0,
                    backup_info["encryption_method"],
                )
            )
            conn.commit()
            conn.close()
            flash("Protected backup created.")
        except Exception as exc:
            flash(f"Backup failed: {exc}")
        return redirect(url_for("backups"))

    conn = db_connect()
    rows = conn.execute(
        """
        SELECT br.id, br.backup_name, br.size, br.created_at, br.stored_name,
               br.is_encrypted, br.encryption_method,
               u.username AS created_by_name
        FROM backup_records br
        JOIN users u ON u.id = br.created_by
        ORDER BY br.created_at DESC
        """
    ).fetchall()
    conn.close()

    body = render_template_string(
        """
        <div class="d-flex justify-content-between align-items-center mb-3">
          <div>
            <h3 class="mb-1">Encrypted Backups</h3>
            <p class="text-muted mb-0">Create encrypted backups of the database and uploaded files for recovery.</p>
          </div>
          <form method="post">
            <button class="btn btn-primary">Create Encrypted Backup</button>
          </form>
        </div>

        <div class="alert alert-success mb-3">
          <strong>Encryption is required for every backup.</strong> This app does not create plain-text backups.
        </div>

        <div class="card shadow-sm mb-3">
          <div class="card-body">
            <p class="mb-2">Each backup contains:</p>
            <ul class="mb-2">
              <li>The current <code>files.db</code> database</li>
              <li>All files from the <code>uploads/</code> folder</li>
              <li>An encrypted archive stored in <code>backups/</code></li>
            </ul>
            <p class="small text-muted mb-1">Backups are protected with {{ encryption_method }} before they are stored or downloaded.</p>
            <p class="small text-muted mb-0">Recovery support remains available through the existing import script using the same protected backup format.</p>
          </div>
        </div>

        {% if backups %}
          <div class="card shadow-sm">
            <div class="table-responsive">
              <table class="table table-striped mb-0">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Created</th>
                    <th>Created By</th>
                    <th>Size</th>
                    <th>Protection</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {% for backup in backups %}
                    <tr>
                      <td>{{ backup["backup_name"] }}</td>
                      <td>{{ backup["created_at"] }}</td>
                      <td>{{ backup["created_by_name"] }}</td>
                      <td>{{ backup["size"] }} bytes</td>
                      <td>
                        {% if backup["is_encrypted"] %}
                          <span class="badge bg-success">{{ backup["encryption_method"] }}</span>
                        {% else %}
                          Not encrypted
                        {% endif %}
                      </td>
                      <td>
                        <a class="btn btn-sm btn-outline-primary" href="{{ url_for('download_backup', backup_id=backup['id']) }}">Download Encrypted Backup</a>
                      </td>
                    </tr>
                  {% endfor %}
                </tbody>
              </table>
            </div>
          </div>
        {% else %}
          <p class="text-muted">No backups created yet.</p>
        {% endif %}
        """,
        backups=rows,
        encryption_method=BACKUP_ENCRYPTION_METHOD,
    )
    return render_template_string(BASE, title="Encrypted Backups", body=body)


@app.route("/backups/<int:backup_id>/download")
@login_required
def download_backup(backup_id: int):
    if not is_admin():
        abort(403)

    conn = db_connect()
    row = conn.execute(
        "SELECT backup_name, stored_name FROM backup_records WHERE id=?",
        (backup_id,)
    ).fetchone()
    conn.close()
    if not row:
        abort(404)

    path = os.path.join(app.config["BACKUP_DIR"], row["stored_name"])
    if not os.path.exists(path):
        abort(404)

    return send_file(
        path,
        as_attachment=True,
        download_name=row["backup_name"],
        mimetype="application/octet-stream",
    )
@app.route("/download/<int:file_id>", methods=["GET", "POST"])
@login_required
def download(file_id: int):
    conn = db_connect()

    row = conn.execute(
        "SELECT * FROM files WHERE id=?",
        (file_id,)
    ).fetchone()

    if not row:
        conn.close()
        abort(404)

    uid = int(g.user["id"])
    is_owner_or_admin = is_admin() or int(row["owner_id"]) == uid

    shared_access = None
    if not is_owner_or_admin:
        shared_access = conn.execute(
            """
            SELECT can_read, can_delete, can_share, share_password_hash
            FROM file_access
            WHERE file_id=? AND user_id=?
            """,
            (file_id, uid)
        ).fetchone()

        if not shared_access or int(shared_access["can_read"]) != 1:
            conn.close()
            abort(403)

    if not is_owner_or_admin:
        session_key = f"shared_download_ok_{file_id}"

        if request.method == "POST":
            entered_password = request.form.get("share_password") or ""
            if not entered_password:
                conn.close()
                flash("Share password is required.")
                return redirect(url_for("download", file_id=file_id))

            try:
                ph.verify(shared_access["share_password_hash"], entered_password)
                session[session_key] = True
            except VerifyMismatchError:
                conn.close()
                flash("Incorrect share password.")
                return redirect(url_for("download", file_id=file_id))

        elif not session.get(session_key):
            orig_name = row["orig_name"] or row["filename"] or "download.bin"
            conn.close()
            body = render_template_string(
                """
                <div class="row justify-content-center">
                  <div class="col-md-6">
                    <div class="card shadow-sm">
                      <div class="card-body">
                        <h3 class="card-title">Shared File Access</h3>
                        <p class="text-muted">Enter the share password to download <strong>{{ filename }}</strong>.</p>
                        <form method="post">
                          <div class="mb-3">
                            <label class="form-label">Share Password</label>
                            <input class="form-control" type="password" name="share_password" required>
                          </div>
                          <button class="btn btn-primary">Verify & Download</button>
                          <a class="btn btn-link" href="{{ url_for('files') }}">Back</a>
                        </form>
                      </div>
                    </div>
                  </div>
                </div>
                """,
                filename=orig_name
            )
            return page("Enter Share Password", body)

    conn.close()

    stored_name = row["stored_name"]
    orig_name = row["orig_name"] or row["filename"] or "download.bin"
    mime = row["mime"] or "application/octet-stream"
    client_encrypted = int(row["client_encrypted"]) == 1

    try:
        data = download_blob_bytes(stored_name)
    except FileNotFoundError:
        app.logger.error(f"Download failed: file not found for stored_name={stored_name}")
        abort(404)
    except Exception as e:
        app.logger.exception(f"Download failed for stored_name={stored_name}: {e}")
        abort(500)

    if not client_encrypted:
        try:
            data = decrypt_bytes(data, ENC_KEY_B64)
        except Exception as e:
            app.logger.exception(f"Decryption failed for file_id={file_id}: {e}")
            abort(500)

    session.pop(f"shared_download_ok_{file_id}", None)

    return send_file(
        io.BytesIO(data),
        as_attachment=True,
        download_name=orig_name,
        mimetype=mime,
    )

@app.route("/delete/<int:file_id>")
@login_required
def delete(file_id: int):
    conn = db_connect()
    row = conn.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()

    if not row:
        conn.close()
        abort(404)

    uid = int(g.user["id"])
    if not is_admin() and int(row["owner_id"]) != uid:
        conn.close()
        abort(403)

    stored_name = row["stored_name"]

    try:
        if blob_exists(stored_name):
            delete_blob_bytes(stored_name)
    except Exception:
        pass

    conn.execute("DELETE FROM file_access WHERE file_id=?", (file_id,))
    conn.execute("DELETE FROM files WHERE id=?", (file_id,))
    conn.commit()
    conn.close()

    flash("Deleted.")
    return redirect(url_for("files"))

def user_can_share_file(user_id, file_id, is_admin=False):
    if is_admin:
        return True

    conn = db_connect()
    try:
        row = conn.execute(
            "SELECT id, owner_id FROM files WHERE id = ?",
            (file_id,)
        ).fetchone()

        if not row:
            return False

        return int(row["owner_id"]) == int(user_id)
    finally:
        conn.close()


@app.route("/share/<int:file_id>", methods=["POST"])
@login_required
def share_file(file_id):
    is_admin_user = (g.user.get("role") == "admin")

    if not user_can_share_file(g.user["id"], file_id, is_admin=is_admin_user):
        log_event(g.user["id"], g.user["username"], "share", str(file_id), "DENY")
        abort(403)

    target_username = (request.form.get("username") or "").strip()
    share_password = request.form.get("share_password") or ""
    can_delete = 1 if (request.form.get("can_delete") == "1") else 0
    can_share = 1 if (request.form.get("can_share") == "1") else 0

    if not target_username:
        flash("Username is required to share.")
        return redirect(url_for("files"))

    if not share_password:
        flash("A share password is required.")
        return redirect(url_for("files"))

    if len(share_password) < 8:
        flash("Share password must be at least 8 characters.")
        return redirect(url_for("files"))

    conn = db_connect()
    c = conn.cursor()

    file_row = c.execute(
        "SELECT id, owner_id FROM files WHERE id=?",
        (file_id,)
    ).fetchone()

    if not file_row:
        conn.close()
        flash("File not found.")
        return redirect(url_for("files"))

    c.execute("SELECT id FROM users WHERE username=?", (target_username,))
    dest = c.fetchone()

    if not dest:
        conn.close()
        flash("Target user not found.")
        return redirect(url_for("files"))

    target_id = int(dest["id"] if isinstance(dest, sqlite3.Row) else dest[0])

    if target_id == int(g.user["id"]):
        conn.close()
        flash("You cannot share a file with yourself.")
        return redirect(url_for("files"))

    share_password_hash = ph.hash(share_password)

    c.execute(
        """
        INSERT OR REPLACE INTO file_access(file_id, user_id, can_read, can_delete, can_share, share_password_hash)
        VALUES (?,?,?,?,?,?)
        """,
        (file_id, target_id, 1, can_delete, can_share, share_password_hash)
    )

    conn.commit()
    conn.close()

    log_event(
        g.user["id"],
        g.user["username"],
        "share",
        str(file_id),
        "SUCCESS",
        {"to": target_username, "password_protected": True}
    )

    flash(f"File shared securely with {target_username}. They will need the share password to download it.")
    return redirect(url_for("files"))


# =============================================================================
# MA.L2-3.7.6 — Maintenance Personnel
# =============================================================================

def is_maintenance_personnel(user_id: int) -> bool:
    conn = db_connect()
    row = conn.execute(
        "SELECT id FROM maintenance_personnel WHERE user_id=? AND status='active'",
        (user_id,)
    ).fetchone()
    conn.close()
    return row is not None


@app.route("/maintenance-personnel", methods=["GET"])
@login_required
def maintenance_personnel():
    if not is_admin():
        abort(403)

    conn = db_connect()
    records = conn.execute("""
        SELECT mp.id, mp.approved_at, mp.reason, mp.status,
               mp.revoked_at, mp.revoke_reason,
               u.username AS personnel_name,
               approver.username AS approver_name,
               revoker.username AS revoker_name
        FROM maintenance_personnel mp
        JOIN users u ON u.id = mp.user_id
        JOIN users approver ON approver.id = mp.approved_by
        LEFT JOIN users revoker ON revoker.id = mp.revoked_by
        ORDER BY mp.approved_at DESC
    """).fetchall()

    all_users = conn.execute(
        "SELECT id, username FROM users ORDER BY username"
    ).fetchall()
    conn.close()

    body = render_template_string("""
    <div class="d-flex justify-content-between align-items-center mb-3">
      <div>
        <h3 class="mb-1">Maintenance Personnel</h3>
        <p class="text-muted mb-0">
          MA.L2-3.7.6 — Only vetted and authorized personnel may perform system maintenance.
          All authorizations and revocations are logged.
        </p>
      </div>
      <button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#authorizeModal">
        Authorize Personnel
      </button>
    </div>

    <!-- Authorization modal -->
    <div class="modal fade" id="authorizeModal" tabindex="-1">
      <div class="modal-dialog">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title">Authorize Maintenance Personnel</h5>
            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
          </div>
          <form method="post" action="{{ url_for('maintenance_personnel_authorize') }}">
            <div class="modal-body">
              <div class="mb-3">
                <label class="form-label fw-semibold">Select User</label>
                <select class="form-select" name="user_id" required>
                  <option value="">— choose user —</option>
                  {% for u in all_users %}
                    <option value="{{ u['id'] }}">{{ u['username'] }}</option>
                  {% endfor %}
                </select>
              </div>
              <div class="mb-3">
                <label class="form-label fw-semibold">Reason / Justification</label>
                <textarea class="form-control" name="reason" rows="3" required
                  placeholder="Why is this person authorized to perform maintenance?"></textarea>
              </div>
            </div>
            <div class="modal-footer">
              <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
              <button type="submit" class="btn btn-primary">Authorize</button>
            </div>
          </form>
        </div>
      </div>
    </div>

    {% if records %}
    <div class="card shadow-sm">
      <div class="table-responsive">
        <table class="table table-striped mb-0">
          <thead>
            <tr>
              <th>Personnel</th>
              <th>Status</th>
              <th>Authorized By</th>
              <th>Authorized At</th>
              <th>Reason</th>
              <th>Revocation</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {% for r in records %}
            <tr>
              <td><strong>{{ r['personnel_name'] }}</strong></td>
              <td>
                {% if r['status'] == 'active' %}
                  <span class="badge bg-success">Active</span>
                {% else %}
                  <span class="badge bg-secondary">Revoked</span>
                {% endif %}
              </td>
              <td>{{ r['approver_name'] }}</td>
              <td>{{ r['approved_at'][:19] }}</td>
              <td><small>{{ r['reason'] }}</small></td>
              <td>
                {% if r['status'] == 'revoked' %}
                  <small class="text-muted">
                    By {{ r['revoker_name'] }} at {{ r['revoked_at'][:19] }}<br>
                    {{ r['revoke_reason'] }}
                  </small>
                {% else %}
                  —
                {% endif %}
              </td>
              <td>
                {% if r['status'] == 'active' %}
                <button class="btn btn-sm btn-outline-danger"
                        data-bs-toggle="modal"
                        data-bs-target="#revokeModal{{ r['id'] }}">
                  Revoke
                </button>

                <!-- Revoke modal per record -->
                <div class="modal fade" id="revokeModal{{ r['id'] }}" tabindex="-1">
                  <div class="modal-dialog">
                    <div class="modal-content">
                      <div class="modal-header">
                        <h5 class="modal-title">Revoke Maintenance Access — {{ r['personnel_name'] }}</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                      </div>
                      <form method="post" action="{{ url_for('maintenance_personnel_revoke', record_id=r['id']) }}">
                        <div class="modal-body">
                          <div class="mb-3">
                            <label class="form-label fw-semibold">Reason for Revocation</label>
                            <textarea class="form-control" name="revoke_reason" rows="3" required
                              placeholder="Why is maintenance access being revoked?"></textarea>
                          </div>
                        </div>
                        <div class="modal-footer">
                          <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                          <button type="submit" class="btn btn-danger">Revoke Access</button>
                        </div>
                      </form>
                    </div>
                  </div>
                </div>
                {% else %}
                  —
                {% endif %}
              </td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
    </div>
    {% else %}
    <div class="alert alert-warning">
      No maintenance personnel have been authorized yet. Use the button above to authorize a vetted user.
    </div>
    {% endif %}
    """, records=records, all_users=all_users)

    return render_template_string(BASE, title="Maintenance Personnel", body=body, signup_enabled=SIGNUP_ENABLED)


@app.route("/maintenance-personnel/authorize", methods=["POST"])
@login_required
def maintenance_personnel_authorize():
    if not is_admin():
        abort(403)

    user_id = request.form.get("user_id", "").strip()
    reason = request.form.get("reason", "").strip()

    if not user_id or not reason:
        flash("User and reason are required.")
        return redirect(url_for("maintenance_personnel"))

    try:
        user_id = int(user_id)
    except ValueError:
        flash("Invalid user.")
        return redirect(url_for("maintenance_personnel"))

    conn = db_connect()

    # Verify target user exists
    target = conn.execute("SELECT id, username FROM users WHERE id=?", (user_id,)).fetchone()
    if not target:
        conn.close()
        flash("User not found.")
        return redirect(url_for("maintenance_personnel"))

    # Check if already active
    existing = conn.execute(
        "SELECT id FROM maintenance_personnel WHERE user_id=? AND status='active'",
        (user_id,)
    ).fetchone()
    if existing:
        conn.close()
        flash(f"{target['username']} already has active maintenance authorization.")
        return redirect(url_for("maintenance_personnel"))

    now = datetime.datetime.utcnow().isoformat()
    cur = conn.execute(
        """INSERT INTO maintenance_personnel(user_id, approved_by, approved_at, reason, status)
           VALUES (?, ?, ?, ?, 'active')""",
        (user_id, g.user["id"], now, reason)
    )
    record_id = cur.lastrowid

    conn.execute(
        """INSERT INTO maintenance_log(personnel_id, action, performed_by, performed_at, notes)
           VALUES (?, 'authorized', ?, ?, ?)""",
        (record_id, g.user["id"], now, reason)
    )
    conn.commit()
    conn.close()

    log_event(
        g.user["id"], g.user["username"],
        "maintenance_authorize",
        target["username"],
        "SUCCESS",
        {"reason": reason}
    )

    flash(f"{target['username']} authorized as maintenance personnel.")
    return redirect(url_for("maintenance_personnel"))


@app.route("/maintenance-personnel/<int:record_id>/revoke", methods=["POST"])
@login_required
def maintenance_personnel_revoke(record_id: int):
    if not is_admin():
        abort(403)

    revoke_reason = request.form.get("revoke_reason", "").strip()
    if not revoke_reason:
        flash("A reason is required to revoke access.")
        return redirect(url_for("maintenance_personnel"))

    conn = db_connect()
    record = conn.execute(
        """SELECT mp.id, mp.user_id, mp.status, u.username
           FROM maintenance_personnel mp
           JOIN users u ON u.id = mp.user_id
           WHERE mp.id=?""",
        (record_id,)
    ).fetchone()

    if not record:
        conn.close()
        abort(404)

    if record["status"] != "active":
        conn.close()
        flash("This authorization is already revoked.")
        return redirect(url_for("maintenance_personnel"))

    now = datetime.datetime.utcnow().isoformat()
    conn.execute(
        """UPDATE maintenance_personnel
           SET status='revoked', revoked_by=?, revoked_at=?, revoke_reason=?
           WHERE id=?""",
        (g.user["id"], now, revoke_reason, record_id)
    )
    conn.execute(
        """INSERT INTO maintenance_log(personnel_id, action, performed_by, performed_at, notes)
           VALUES (?, 'revoked', ?, ?, ?)""",
        (record_id, g.user["id"], now, revoke_reason)
    )
    conn.commit()
    conn.close()

    log_event(
        g.user["id"], g.user["username"],
        "maintenance_revoke",
        record["username"],
        "SUCCESS",
        {"reason": revoke_reason}
    )

    flash(f"Maintenance access revoked for {record['username']}.")
    return redirect(url_for("maintenance_personnel"))


@app.route("/maintenance-personnel/log")
@login_required
def maintenance_personnel_log():
    if not is_admin():
        abort(403)

    conn = db_connect()
    entries = conn.execute("""
        SELECT ml.action, ml.performed_at, ml.notes,
               actor.username AS actor_name,
               u.username AS personnel_name
        FROM maintenance_log ml
        JOIN maintenance_personnel mp ON mp.id = ml.personnel_id
        JOIN users u ON u.id = mp.user_id
        JOIN users actor ON actor.id = ml.performed_by
        ORDER BY ml.performed_at DESC
        LIMIT 500
    """).fetchall()
    conn.close()

    body = render_template_string("""
    <div class="d-flex justify-content-between align-items-center mb-3">
      <div>
        <h3 class="mb-1">Maintenance Personnel Log</h3>
        <p class="text-muted mb-0">Full audit trail of all authorization and revocation events.</p>
      </div>
      <a class="btn btn-outline-secondary" href="{{ url_for('maintenance_personnel') }}">← Back</a>
    </div>
    {% if entries %}
    <div class="card shadow-sm">
      <div class="table-responsive">
        <table class="table table-striped mb-0">
          <thead>
            <tr><th>Time</th><th>Action</th><th>Personnel</th><th>By</th><th>Notes</th></tr>
          </thead>
          <tbody>
          {% for e in entries %}
            <tr>
              <td><small>{{ e['performed_at'][:19] }}</small></td>
              <td>
                {% if e['action'] == 'authorized' %}
                  <span class="badge bg-success">Authorized</span>
                {% else %}
                  <span class="badge bg-danger">Revoked</span>
                {% endif %}
              </td>
              <td>{{ e['personnel_name'] }}</td>
              <td>{{ e['actor_name'] }}</td>
              <td><small>{{ e['notes'] }}</small></td>
            </tr>
          {% endfor %}
          </tbody>
        </table>
      </div>
    </div>
    {% else %}
    <p class="text-muted">No log entries yet.</p>
    {% endif %}
    """, entries=entries)

    return render_template_string(BASE, title="Maintenance Log", body=body, signup_enabled=SIGNUP_ENABLED)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=(ENV != "production"))