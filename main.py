import os
import re
import io
import uuid
import sqlite3
import datetime
from functools import wraps

from dotenv import load_dotenv
from flask import (
    Flask, request, redirect, url_for,
    render_template_string, flash, session, g,
    send_file, abort
)
from werkzeug.utils import secure_filename
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from azure.storage.blob import BlobServiceClient

from crypto_utils import load_key_from_env, encrypt_bytes, decrypt_bytes

# =============================================================================
# ENV / CONFIG
# =============================================================================
load_dotenv("/home/secureuploader/secure_uploader/.env")

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "change-this")

SIGNUP_ENABLED = os.getenv("SIGNUP_ENABLED", "false").lower() == "true"
SIGNUP_CODE = os.getenv("SIGNUP_CODE", "")

DB_PATH = "/home/secureuploader/secure_uploader/files.db"

ph = PasswordHasher()

# =============================================================================
# AZURE BLOB
# =============================================================================
conn_str = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
container_name = os.getenv("AZURE_STORAGE_CONTAINER", "securevault-files")

if not conn_str:
    raise RuntimeError("Missing Azure Storage connection string")

blob_service = BlobServiceClient.from_connection_string(conn_str)
container = blob_service.get_container_client(container_name)

def upload_blob(name, data):
    container.get_blob_client(name).upload_blob(data, overwrite=True)

def download_blob(name):
    return container.get_blob_client(name).download_blob().readall()

def delete_blob(name):
    container.get_blob_client(name).delete_blob(delete_snapshots="include")

def blob_exists(name):
    return container.get_blob_client(name).exists()

# =============================================================================
# ENCRYPTION
# =============================================================================
load_key_from_env(os.getenv("UPLOAD_ENC_KEY"))

# =============================================================================
# DATABASE
# =============================================================================
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    c = db()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password_hash TEXT,
        role TEXT,
        created_at TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY,
        filename TEXT,
        stored_name TEXT,
        size INTEGER,
        uploaded_at TEXT,
        owner_id INTEGER,
        client_encrypted INTEGER
    )""")
    c.commit()
    c.close()

init_db()

# =============================================================================
# AUTH
# =============================================================================
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login")
        return f(*args, **kwargs)
    return wrapper

@app.before_request
def load_user():
    g.user = None
    if "user_id" in session:
        c = db()
        user = c.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
        c.close()
        if user:
            g.user = dict(user)

def is_admin():
    return g.user and g.user.get("role") == "admin"

# =============================================================================
# TEMPLATE
# =============================================================================
BASE = """
<!doctype html>
<html>
<head>
  <title>{{title}}</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>

<nav class="navbar navbar-dark bg-primary p-2">
<div class="container">

<a class="navbar-brand" href="/">Secure Uploader</a>

<div>

{% if g.user %}
  <span class="text-white">Hi {{g.user.username}}</span>

  <a class="btn btn-sm btn-light" href="/files">Files</a>
  <a class="btn btn-sm btn-light" href="/upload">Upload</a>

  {% if g.user.role == 'admin' %}
    <a class="btn btn-sm btn-warning" href="/add-user">Add User</a>
  {% endif %}

  <a class="btn btn-sm btn-danger" href="/logout">Logout</a>

{% else %}

  <a class="btn btn-sm btn-light" href="/login">Login</a>

  {% if signup_enabled %}
    <a class="btn btn-sm btn-success" href="/signup">Sign Up</a>
  {% endif %}

{% endif %}

</div>
</div>
</nav>

<div class="container mt-4">

{% with messages = get_flashed_messages() %}
  {% if messages %}
    <div class="alert alert-info">
      {% for m in messages %}
        <div>{{m}}</div>
      {% endfor %}
    </div>
  {% endif %}
{% endwith %}

{{body|safe}}

</div>
</body>
</html>
"""

def page(title, body):
    return render_template_string(BASE, title=title, body=body, signup_enabled=SIGNUP_ENABLED)

# =============================================================================
# ROUTES
# =============================================================================
@app.route("/")
def home():
    body = """
    <h2>Secure Uploader</h2>
    <a class='btn btn-primary' href='/upload'>Upload</a>
    <a class='btn btn-secondary' href='/files'>View Files</a>
    """
    return page("Home", body)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form["username"]
        p = request.form["password"]

        c = db()
        user = c.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
        c.close()

        if user:
            try:
                ph.verify(user["password_hash"], p)
                session["user_id"] = user["id"]
                return redirect("/files")
            except:
                pass

        flash("Invalid login")
        return redirect("/login")

    return page("Login", """
    <form method=post>
    <input name=username placeholder=username required><br>
    <input name=password type=password required><br>
    <button>Login</button>
    </form>
    """)

@app.route("/add-user", methods=["GET","POST"])
def add_user():
    c = db()
    count = c.execute("SELECT COUNT(*) as c FROM users").fetchone()["c"]
    c.close()

    if count > 0 and not is_admin():
        return redirect("/login")

    if request.method == "POST":
        u = request.form["username"]
        p = request.form["password"]

        c = db()
        c.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES (?,?,?,?)",
                  (u, ph.hash(p), "admin" if count==0 else "user", datetime.datetime.utcnow().isoformat()))
        c.commit()
        c.close()
        return redirect("/login")

    return page("Add User", """
    <form method=post>
    <input name=username required><br>
    <input name=password required><br>
    <button>Create</button>
    </form>
    """)

@app.route("/upload", methods=["GET","POST"])
@login_required
def upload():
    if request.method == "POST":
        f = request.files["file"]
        data = f.read()

        encrypted = encrypt_bytes(data)
        name = uuid.uuid4().hex

        upload_blob(name, encrypted)

        c = db()
        c.execute("INSERT INTO files(filename,stored_name,size,uploaded_at,owner_id,client_encrypted) VALUES (?,?,?,?,?,0)",
                  (f.filename, name, len(data), datetime.datetime.utcnow().isoformat(), g.user["id"]))
        c.commit()
        c.close()

        return redirect("/files")

    return page("Upload", """
    <form method=post enctype=multipart/form-data>
    <input type=file name=file required>
    <button>Upload</button>
    </form>
    """)

@app.route("/files")
@login_required
def files():
    c = db()
    rows = c.execute("SELECT * FROM files WHERE owner_id=?", (g.user["id"],)).fetchall()
    c.close()

    html = "<h3>Your Files</h3>"
    for r in rows:
        html += f"<div>{r['filename']} - <a href='/download/{r['id']}'>Download</a></div>"

    return page("Files", html)

@app.route("/download/<int:id>")
@login_required
def download(id):
    c = db()
    f = c.execute("SELECT * FROM files WHERE id=?", (id,)).fetchone()
    c.close()

    data = download_blob(f["stored_name"])
    data = decrypt_bytes(data)

    return send_file(io.BytesIO(data), download_name=f["filename"], as_attachment=True)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
