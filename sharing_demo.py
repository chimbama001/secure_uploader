import os, sqlite3, datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, send_file, abort, current_app

demo = Blueprint("demo", __name__, template_folder="templates", url_prefix="/demo")

DB_PATH = "files.db"

def ensure_shares_table():
    conn = sqlite3.connect(DB_PATH); c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS shares(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      file_id INTEGER NOT NULL,
      from_email TEXT NOT NULL,
      to_email TEXT NOT NULL,
      can_download INTEGER DEFAULT 1,
      expires_at TEXT,
      created_at TEXT
    )""")
    conn.commit(); conn.close()

def add_share(file_id, from_email, to_email, days_valid=7):
    expires = (datetime.datetime.utcnow() + datetime.timedelta(days=days_valid)).isoformat() + "Z"
    conn = sqlite3.connect(DB_PATH); c = conn.cursor()
    c.execute("""INSERT INTO shares(file_id, from_email, to_email, can_download, expires_at, created_at)
                 VALUES (?,?,?,?,?,?)""",
              (file_id, from_email.lower(), to_email.lower(), 1, expires, datetime.datetime.utcnow().isoformat()+"Z"))
    conn.commit(); conn.close()

def list_shared_to(email):
    conn = sqlite3.connect(DB_PATH); c = conn.cursor()
    c.execute("""SELECT s.id, f.id, f.orig_name, f.size, s.from_email, s.expires_at
                 FROM shares s JOIN files f ON s.file_id=f.id
                 WHERE s.to_email=? AND s.can_download=1""", (email.lower(),))
    rows = c.fetchall(); conn.close()
    out, now = [], datetime.datetime.utcnow()
    for r in rows:
        try:
            if datetime.datetime.fromisoformat(r[5].replace("Z","")) >= now:
                out.append(r)
        except Exception:
            out.append(r)
    return out

def is_share_allowed(file_id, email):
    conn = sqlite3.connect(DB_PATH); c = conn.cursor()
    c.execute("""SELECT expires_at FROM shares
                 WHERE file_id=? AND to_email=? AND can_download=1""",
              (file_id, email.lower()))
    rows = c.fetchall(); conn.close()
    now = datetime.datetime.utcnow()
    for (exp,) in rows:
        try:
            if datetime.datetime.fromisoformat(exp.replace("Z","")) >= now:
                return True
        except Exception:
            return True
    return False

def me(): return session.get("user_email")

@demo.before_app_request
def _boot(): ensure_shares_table()

@demo.route("/")
def home():
    conn = sqlite3.connect(DB_PATH); c = conn.cursor()
    c.execute("SELECT id, orig_name, size, uploaded_at FROM files ORDER BY id DESC")
    files = c.fetchall(); conn.close()
    return render_template("demo_files.html", files=files, me=me())

@demo.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email","").strip()
        if email:
            session["user_email"] = email
            flash(f"Logged in as {email}")
            return redirect(url_for("demo.home"))
        flash("Enter an email.")
    return render_template("demo_login.html")

@demo.route("/logout")
def logout():
    session.clear(); flash("Logged out.")
    return redirect(url_for("demo.home"))

@demo.route("/share/<int:file_id>", methods=["GET","POST"])
def share(file_id):
    if not me():
        flash("Please log in first."); return redirect(url_for("demo.login"))
    conn = sqlite3.connect(DB_PATH); c = conn.cursor()
    c.execute("SELECT id, orig_name FROM files WHERE id=?", (file_id,)); f = c.fetchone()
    conn.close()
    if not f: abort(404)
    if request.method == "POST":
        to_email = request.form.get("to_email","").strip()
        days = int(request.form.get("days","7") or "7")
        if not to_email:
            flash("Enter a recipient email."); return redirect(url_for("demo.share", file_id=file_id))
        add_share(file_id, me(), to_email, days_valid=days)
        flash(f"Shared '{f[1]}' with {to_email} for {days} days.")
        return redirect(url_for("demo.home"))
    return render_template("demo_share.html", file=f)

@demo.route("/shared")
def shared_with_me():
    if not me():
        flash("Please log in first."); return redirect(url_for("demo.login"))
    shares = list_shared_to(me())
    return render_template("demo_shared_with_me.html", shares=shares)

@demo.route("/download/<int:file_id>")
def download(file_id):
    if not me():
        flash("Please log in first."); return redirect(url_for("demo.login"))
    if not is_share_allowed(file_id, me()):
        flash("You don't have access to this file."); return redirect(url_for("demo.home"))
    conn = sqlite3.connect(DB_PATH); c = conn.cursor()
    c.execute("SELECT stored_name, orig_name FROM files WHERE id=?", (file_id,))
    row = c.fetchone(); conn.close()
    if not row: abort(404)
    stored_name, display_name = row
    uploads_dir = current_app.config.get("UPLOAD_FOLDER","uploads")
    path = os.path.join(uploads_dir, stored_name)
    if not os.path.exists(path): abort(404)
    return send_file(path, as_attachment=True, download_name=display_name)
