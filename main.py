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

# =============================================================================
# DB helpers
# =============================================================================
def db_connect():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000;")
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn

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

    conn.commit()
    conn.close()

ensure_schema()

# =============================================================================
# Helpers
# =============================================================================
PASSWORD_REGEX = re.compile(
    r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#^])[A-Za-z\d@$!%*?&#^]{12,}$'
)

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
 
