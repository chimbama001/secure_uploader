import os
import re
import io
import uuid
import sqlite3
import datetime
from pathlib import Path
from functools import wraps

from dotenv import load_dotenv
from flask import (
    Flask,
    request,
    redirect,
    url_for,
    render_template_string,
    flash,
    session,
    g,
    send_file,
    abort,
)
from werkzeug.utils import secure_filename
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from azure.storage.blob import BlobServiceClient

try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
except Exception:
    Limiter = None
    get_remote_address = None

from crypto_utils import load_key_from_env, encrypt_bytes, decrypt_bytes
# ---- crypto utils (your existing module) ----
from crypto_utils import encrypt_bytes, decrypt_bytes
from backup_utils import BACKUP_ENCRYPTION_METHOD, create_protected_backup, load_backup_key


# =============================================================================
# Environment / config
# =============================================================================
load_dotenv("/home/secureuploader/secure_uploader/.env")

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", os.urandom(32))

ENV = os.environ.get("FLASK_ENV", "development").lower()
secure_cookies = ENV == "production"

app.config.update(
    SESSION_COOKIE_SECURE=secure_cookies,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=200 * 1024 * 1024,
)

SIGNUP_ENABLED = os.getenv("SIGNUP_ENABLED", "false").lower() == "true"
SIGNUP_CODE = os.getenv("SIGNUP_CODE", "")

DATA_DIR = os.environ.get("DATA_DIR") or "/home/secureuploader/secure_uploader"
DATA_DIR = os.path.abspath(DATA_DIR)
DB_PATH = os.path.join(DATA_DIR, "files.db")

ph = PasswordHasher()

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

# =============================================================================
# Blob Storage
# =============================================================================
AZURE_STORAGE_CONNECTION_STRING = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
AZURE_STORAGE_CONTAINER = os.getenv("AZURE_STORAGE_CONTAINER", "securevault-files")

if not AZURE_STORAGE_CONNECTION_STRING:
    raise RuntimeError("AZURE_STORAGE_CONNECTION_STRING is not set")

blob_service_client = BlobServiceClient.from_connection_string(
    AZURE_STORAGE_CONNECTION_STRING
)
container_client = blob_service_client.get_container_client(AZURE_STORAGE_CONTAINER)

def upload_blob_bytes(blob_name: str, data: bytes) -> None:
    blob_client = container_client.get_blob_client(blob_name)
    blob_client.upload_blob(data, overwrite=True)

def download_blob_bytes(blob_name: str) -> bytes:
    blob_client = container_client.get_blob_client(blob_name)
    return blob_client.download_blob().readall()

def delete_blob_bytes(blob_name: str) -> None:
    blob_client = container_client.get_blob_client(blob_name)
    blob_client.delete_blob(delete_snapshots="include")

def blob_exists(blob_name: str) -> bool:
    blob_client = container_client.get_blob_client(blob_name)
    return blob_client.exists()

# =============================================================================
# Encryption key
# =============================================================================
ENC_KEY_B64 = load_key_from_env(os.environ.get("UPLOAD_ENC_KEY"))
ph = PasswordHasher()

# Data directory (persistent)
DATA_DIR = os.environ.get("DATA_DIR") or str(Path.cwd())
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
ENC_KEY_B64 = load_backup_key()
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

    c.execute("""
    CREATE TABLE IF NOT EXISTS file_access (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      file_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      can_read INTEGER NOT NULL DEFAULT 1,
      can_delete INTEGER NOT NULL DEFAULT 0,
      UNIQUE(file_id, user_id)
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


# =============================================================================
# Templates
# =============================================================================
BASE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>{{title}}</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<nav class="navbar navbar-expand-lg navbar-dark bg-primary">
  <div class="container">
    <a class="navbar-brand" href="{{ url_for('home') }}">Secure Uploader</a>
    <div class="ms-auto">
      {% if g.user %}
        <span class="text-white me-3">Hi, {{g.user.username}}</span>
        <a class="btn btn-sm btn-outline-light me-2" href="{{ url_for('files') }}">Files</a>
        <a class="btn btn-sm btn-outline-light me-2" href="{{ url_for('upload') }}">Upload</a>
        {% if g.user.role == 'admin' %}
        <a class="btn btn-sm btn-outline-light me-2" href="{{ url_for('incidents') }}">Incidents</a>
        {% if g.user.role == 'admin' %}
        <a class="btn btn-sm btn-outline-light me-2" href="{{ url_for('backups') }}">Backups</a>
        {% endif %}
        <a class="btn btn-sm btn-outline-light me-2" href="{{ url_for('add_user') }}">Add User</a>
        {% endif %}
        <a class="btn btn-sm btn-warning" href="{{ url_for('logout') }}">Logout</a>
      {% else %}
        <a class="btn btn-sm btn-outline-light me-2" href="{{ url_for('login') }}">Login</a>
        {% if signup_enabled %}
        <a class="btn btn-sm btn-light" href="{{ url_for('signup') }}">Sign Up</a>
        {% endif %}
      {% endif %}
    </div>
  </div>
</nav>

<div class="container py-4">
  {% with messages = get_flashed_messages() %}
    {% if messages %}
      <div class="alert alert-info">
        {% for m in messages %}<div>{{m}}</div>{% endfor %}
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
@app.route("/")
def home():
    body = """
    <div class="text-center">
      <h1 class="h3">Secure Uploader</h1>
      <p class="text-muted">Encrypt files on upload and store them securely in Azure Blob Storage.</p>
      <div class="d-flex justify-content-center gap-2">
        <a class="btn btn-primary" href="/upload">Upload</a>
        <a class="btn btn-outline-primary" href="/files">View Files</a>
        {% if g.user and g.user.role == 'admin' %}
        <a class="btn btn-outline-secondary" href="/add-user">Add User</a>
        {% endif %}
      </div>
    </div>
    """
    return page("Home", body)

@app.route("/login", methods=["GET", "POST"])
@login_limit
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        conn = db_connect()
        row = conn.execute(
            "SELECT id, password_hash FROM users WHERE username=?",
            (username,)
        ).fetchone()
        conn.close()

        if not row:
            flash("Invalid username or password.")
            return redirect(url_for("login"))

        try:
            ph.verify(row["password_hash"], password)
        except VerifyMismatchError:
            flash("Invalid username or password.")
            return redirect(url_for("login"))

        session["user_id"] = row["id"]
        flash("Logged in successfully.")
        return redirect(url_for("files"))

    body = """
    <div class="row justify-content-center">
      <div class="col-md-6">
        <div class="card shadow-sm">
          <div class="card-body">
            <h3 class="card-title">Login</h3>
            <form method="post">
              <div class="mb-3">
                <label class="form-label">Username</label>
                <input class="form-control" name="username" required>
              </div>
              <div class="mb-3">
                <label class="form-label">Password</label>
                <input class="form-control" type="password" name="password" required>
              </div>
              <button class="btn btn-primary">Log in</button>
              <a class="btn btn-link" href="/">Home</a>
              {% if signup_enabled %}
              <a class="btn btn-link" href="/signup">Sign Up</a>
              {% endif %}
            </form>
          </div>
        </div>
      </div>
    </div>
    """
    return render_template_string(BASE, title="Login", body=body, signup_enabled=SIGNUP_ENABLED)

@app.route("/signup", methods=["GET", "POST"])
@signup_limit
def signup():
    if not SIGNUP_ENABLED:
        abort(404)

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm") or ""
        signup_code = (request.form.get("signup_code") or "").strip()

        if not username or not password or not confirm or not signup_code:
            flash("All fields are required.")
            return redirect(url_for("signup"))

        if password != confirm:
            flash("Passwords do not match.")
            return redirect(url_for("signup"))

        if not valid_password(password):
            flash("Password must be 12+ chars with upper, lower, number, and special character.")
            return redirect(url_for("signup"))

        if not SIGNUP_CODE or signup_code != SIGNUP_CODE:
            flash("Invalid signup code.")
            return redirect(url_for("signup"))

        conn = db_connect()
        existing = conn.execute(
            "SELECT id FROM users WHERE username=?",
            (username,)
        ).fetchone()

        if existing:
            conn.close()
            flash("Username already exists.")
            return redirect(url_for("signup"))

        password_hash = ph.hash(password)
        conn.execute(
            "INSERT INTO users(username, password_hash, role, created_at) VALUES (?,?,?,?)",
            (username, password_hash, "user", datetime.datetime.utcnow().isoformat())
        )
        conn.commit()
        conn.close()

        flash("Account created successfully. Please log in.")
        return redirect(url_for("login"))

    body = """
    <div class="row justify-content-center">
      <div class="col-md-6">
        <div class="card shadow-sm">
          <div class="card-body">
            <h3 class="card-title">Sign Up</h3>
            <p class="text-muted">Create a standard user account.</p>
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
                <label class="form-label">Confirm Password</label>
                <input class="form-control" type="password" name="confirm" required>
              </div>
              <div class="mb-3">
                <label class="form-label">Signup Code</label>
                <input class="form-control" name="signup_code" required>
              </div>
              <button class="btn btn-primary">Create Account</button>
              <a class="btn btn-link" href="/login">Login</a>
            </form>
          </div>
        </div>
      </div>
    </div>
    """
    return page("Sign Up", body)

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for("home"))

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
        blob_data = file_bytes if client_encrypted else encrypt_bytes(file_bytes)

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
                datetime.datetime.utcnow().isoformat(),
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
              <div class="form-check mb-3">
                <input class="form-check-input" type="checkbox" value="1" id="client_encrypted" name="client_encrypted">
                <label class="form-check-label" for="client_encrypted">
                  Encrypt in browser before upload (store ciphertext only)
                </label>
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
        rows = conn.execute(
            "SELECT id, filename, orig_name, stored_name, mime, size, uploaded_at, owner_id, client_encrypted FROM files ORDER BY uploaded_at DESC"
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT id, filename, orig_name, stored_name, mime, size, uploaded_at, owner_id, client_encrypted FROM files WHERE owner_id=? ORDER BY uploaded_at DESC",
            (uid,)
        ).fetchall()

    conn.close()

    lines = []
    lines.append("<h3>Your Files</h3>")
    lines.append("<div class='table-responsive'><table class='table table-striped'>")
    lines.append("<thead><tr><th>Name</th><th>Size</th><th>Uploaded</th><th>Encrypted</th><th>Actions</th></tr></thead><tbody>")

    for r in rows:
        name = r["orig_name"] or r["filename"] or "unknown"
        enc = "Client" if int(r["client_encrypted"]) == 1 else "Server"
        lines.append(
            "<tr>"
            f"<td>{name}</td>"
            f"<td>{int(r['size'])} bytes</td>"
            f"<td>{r['uploaded_at']}</td>"
            f"<td>{enc}</td>"
            f"<td>"
            f"<a class='btn btn-sm btn-outline-primary me-2' href='/download/{r['id']}'>Download</a>"
            f"<a class='btn btn-sm btn-outline-danger' href='/delete/{r['id']}'>Delete</a>"
            f"</td>"
            "</tr>"
        )

    lines.append("</tbody></table></div>")
    body = "\n".join(lines)
    return page("Files", body)
    return render_template_string(BASE, title="Files", body=body)


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

        now = datetime.datetime.utcnow().isoformat()
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

    now = datetime.datetime.utcnow().isoformat()
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
                    datetime.datetime.utcnow().isoformat(),
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


@app.route("/download/<int:file_id>")
@login_required
def download(file_id: int):
    conn = db_connect()
    row = conn.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()
    conn.close()

    if not row:
        abort(404)

    uid = int(g.user["id"])
    if not is_admin() and int(row["owner_id"]) != uid:
        abort(403)

    stored_name = row["stored_name"]
    orig_name = row["orig_name"] or row["filename"] or "download.bin"
    client_encrypted = int(row["client_encrypted"]) == 1

    if not blob_exists(stored_name):
        abort(404)

    try:
        data = download_blob_bytes(stored_name)
    except Exception:
        abort(404)

    if not client_encrypted:
        data = decrypt_bytes(data)

    return send_file(
        io.BytesIO(data),
        as_attachment=True,
        download_name=orig_name,
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

    conn.execute("DELETE FROM files WHERE id=?", (file_id,))
    conn.commit()
    conn.close()

    flash("Deleted.")
    return redirect(url_for("files"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=(ENV != "production"))
 
