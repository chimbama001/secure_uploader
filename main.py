# main.py
import os
import sqlite3
import datetime
import io
import base64
import enum
from pathlib import Path
from io import BytesIO

from dotenv import load_dotenv
load_dotenv()

from flask import (
    Flask, request, redirect, url_for, render_template, render_template_string,
    send_file, abort, flash, jsonify
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash
from crypto_utils import load_key_from_env, encrypt_bytes, decrypt_bytes

# =========================================
# SHARED APP
# =========================================
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", os.urandom(24))

# ------------------ user roles ------------------
class UserRole(enum.Enum):
    USER = "user"
    ADMIN = "admin"

USERS = {}

# ------------------ config ------------------
UPLOAD_FOLDER = "uploads"
DB_PATH = "files.db"
ALLOWED_EXTENSIONS = None
MAX_CONTENT_LENGTH = 200 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ------------------ encryption (original app.py) ------------------
ENC_KEY_B64 = os.environ.get("UPLOAD_ENC_KEY")
# uncomment in real run:
# if not ENC_KEY_B64:
#     raise RuntimeError("Set UPLOAD_ENC_KEY")
# ENCKEY = load_key_from_env(ENC_KEY_B64)
ENCKEY = load_key_from_env(ENC_KEY_B64) if ENC_KEY_B64 else None

# ------------------ temp files (original app.py) ------------------
TEMP_FILES = {}

# =========================================
# DB HELPERS (original app.py)
# =========================================
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
    CREATE TABLE IF NOT EXISTS files(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        orig_name TEXT,
        stored_name TEXT,
        mime TEXT,
        size INTEGER,
        uploaded_at TEXT
    )
    ''')
    conn.commit()
    conn.close()

def add_file_record(orig_name, stored_name, mime, size):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        'INSERT INTO files(orig_name, stored_name, mime, size, uploaded_at) VALUES (?,?,?,?,?)',
        (orig_name, stored_name, mime, size, datetime.datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()

def list_files():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, orig_name, stored_name, mime, size, uploaded_at FROM files ORDER BY id DESC')
    rows = c.fetchall()
    conn.close()
    return rows

def get_file_record(file_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, orig_name, stored_name, mime, size, uploaded_at FROM files WHERE id=?', (file_id,))
    row = c.fetchone()
    conn.close()
    return row

def delete_file_record(file_id):
    rec = get_file_record(file_id)
    if not rec:
        return False
    stored_name = rec[2]
    path = os.path.join(UPLOAD_FOLDER, stored_name)
    if os.path.exists(path):
        try:
            os.remove(path)
        except Exception:
            pass
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('DELETE FROM files WHERE id=?', (file_id,))
    conn.commit()
    conn.close()
    return True

def guess_mime(filename, filebytes):
    try:
        import magic
        m = magic.Magic(mime=True)
        return m.from_buffer(filebytes)
    except Exception:
        return "application/octet-stream"

# =========================================
# ROUTES: ORIGINAL BIG APP (from app.py)
# =========================================
@app.route('/')
def index():
    # main UI
    roles = [role.value for role in UserRole]
    return render_template('index.html', roles=roles)

@app.route('/upload', methods=['GET','POST'])
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash("No file part")
            return redirect(request.url)
        f = request.files['file']
        if f.filename == '':
            flash("No selected file")
            return redirect(request.url)

        orig_name = secure_filename(f.filename)
        file_bytes = f.read()
        mime = guess_mime(orig_name, file_bytes)

        if ENCKEY is None:
            abort(500, description="Server encryption key not set.")
        enc_blob = encrypt_bytes(file_bytes, ENCKEY)

        stored_name = base64.urlsafe_b64encode(os.urandom(9)).decode().rstrip('=') + ".bin"
        path = os.path.join(app.config['UPLOAD_FOLDER'], stored_name)
        with open(path, 'wb') as fh:
            fh.write(enc_blob)

        add_file_record(orig_name, stored_name, mime, len(file_bytes))
        flash("Uploaded and encrypted successfully.")
        return redirect(url_for('files'))
    return render_template('upload.html')

@app.route('/files')
def files():
    rows = list_files()
    return render_template('files.html', files=rows)

@app.route('/download/<int:file_id>')
def download(file_id):
    rec = get_file_record(file_id)
    if not rec:
        abort(404)
    path = os.path.join(app.config['UPLOAD_FOLDER'], rec[2])
    if not os.path.exists(path):
        abort(404)
    with open(path, 'rb') as fh:
        enc_blob = fh.read()
    if ENCKEY is None:
        abort(500, description="Server encryption key not set.")
    plaintext = decrypt_bytes(enc_blob, ENCKEY)
    return send_file(
        io.BytesIO(plaintext),
        download_name=rec[1] or "download",
        mimetype=rec[3] or "application/octet-stream",
        as_attachment=True
    )

@app.route('/preview/<int:file_id>')
def preview(file_id):
    rec = get_file_record(file_id)
    if not rec:
        abort(404)
    if not (rec[3] or "").startswith("image/"):
        return redirect(url_for('files'))
    path = os.path.join(app.config['UPLOAD_FOLDER'], rec[2])
    with open(path, 'rb') as fh:
        enc_blob = fh.read()
    if ENCKEY is None:
        abort(500, description="Server encryption key not set.")
    plaintext = decrypt_bytes(enc_blob, ENCKEY)
    return send_file(io.BytesIO(plaintext), mimetype=rec[3])

@app.route('/delete/<int:file_id>', methods=['POST'])
def delete(file_id):
    ok = delete_file_record(file_id)
    flash("File deleted." if ok else "File not found.")
    return redirect(url_for('files'))

# ---- temp file APIs ----
@app.route('/temp-upload', methods=['POST'])
def temp_upload():
    if 'file' not in request.files:
        return {'error': 'No file part'}, 400
    file = request.files['file']
    if file.filename == '':
        return {'error': 'No selected file'}, 400
    filename = secure_filename(file.filename)
    file_content = file.read()
    import uuid
    file_id = str(uuid.uuid4())
    TEMP_FILES[file_id] = {
        'filename': filename,
        'content': file_content,
        'mime': guess_mime(filename, file_content),
        'timestamp': datetime.datetime.utcnow().isoformat()
    }
    return {
        'file_id': file_id,
        'filename': filename,
        'size': len(file_content),
        'mime': TEMP_FILES[file_id]['mime']
    }

@app.route('/temp-file/<file_id>')
def get_temp_file(file_id):
    if file_id not in TEMP_FILES:
        return {'error': 'File not found'}, 404
    f = TEMP_FILES[file_id]
    return send_file(io.BytesIO(f['content']),
                     download_name=f['filename'],
                     mimetype=f['mime'])

@app.route('/temp-file/<file_id>', methods=['DELETE'])
def delete_temp_file(file_id):
    if file_id not in TEMP_FILES:
        return {'error': 'File not found'}, 404
    del TEMP_FILES[file_id]
    return {'message': 'File deleted successfully'}

# ---- users ----
@app.route('/add-user')
def add_user_form():
    roles = [role.value for role in UserRole]
    return render_template('add_user.html', roles=roles)

@app.route('/users', methods=['GET','POST'])
def users():
    if request.method == 'POST':
        data = request.json
        if not data:
            return {'error': 'No data provided'}, 400
        username = data.get('username')
        password = data.get('password')
        role = data.get('role', 'user')
        if not username or not password:
            return {'error': 'Username and password are required'}, 400
        if username in USERS:
            return {'error': 'Username already exists'}, 400
        try:
            user_role = UserRole(role.lower())
        except ValueError:
            return {'error': 'Invalid role'}, 400
        USERS[username] = {
            'username': username,
            'password_hash': generate_password_hash(password),
            'role': user_role.value,
            'created_at': datetime.datetime.utcnow().isoformat()
        }
        user_copy = USERS[username].copy()
        del user_copy['password_hash']
        return jsonify(user_copy), 201
    return jsonify({
        'users': [
            {
                'username': u,
                'role': data['role'],
                'created_at': data['created_at']
            }
            for u, data in USERS.items()
        ]
    })

@app.route('/users/<username>')
def get_user(username):
    user = USERS.get(username)
    if not user:
        return {'error': 'User not found'}, 404
    user_copy = user.copy()
    del user_copy['password_hash']
    return jsonify(user_copy)

# =========================================
# SECOND (simple) uploader NAMESPACED
# from app_simple.py, but under /simple/*
# =========================================
# crypto parts
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import mimetypes, secrets

SIMPLE_UPLOAD_DIR = Path("uploads")
SIMPLE_UPLOAD_DIR.mkdir(exist_ok=True)

PASSPHRASE = os.environ.get("FILESTORE_PASSPHRASE")
# if you want it optional, comment this out:
# if not PASSPHRASE:
#     raise RuntimeError("Set FILESTORE_PASSPHRASE")

SALT_PATH = Path("kdf_salt.bin")
if not SALT_PATH.exists():
    SALT_PATH.write_bytes(secrets.token_bytes(16))
SALT = SALT_PATH.read_bytes()

def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(passphrase.encode())

SIMPLE_KEY = _derive_key(PASSPHRASE, SALT) if PASSPHRASE else None

def simple_encrypt(plaintext: bytes) -> bytes:
    aes = AESGCM(SIMPLE_KEY)
    nonce = secrets.token_bytes(12)
    ct = aes.encrypt(nonce, plaintext, None)
    return nonce + ct

def simple_decrypt(blob: bytes) -> bytes:
    aes = AESGCM(SIMPLE_KEY)
    nonce, ct = blob[:12], blob[12:]
    return aes.decrypt(nonce, ct, None)

def simple_is_image(filename: str) -> bool:
    mtype, _ = mimetypes.guess_type(filename)
    return (mtype or "").startswith("image/")

SIMPLE_INDEX_HTML = """
<!doctype html>
<title>Simple AES-GCM uploader</title>
<h1>Simple uploader (/simple)</h1>
<form method="post" enctype="multipart/form-data" action="/simple/upload">
  <input type="file" name="file" />
  <button type="submit">Upload</button>
</form>
<hr>
<ul>
{% for f in files %}
  <li>
    <a href="/simple/download/{{f.name}}">{{f.name}}</a>
    {% if f.is_image %}
      <img src="/simple/preview/{{f.name}}" style="max-width:200px;">
    {% endif %}
  </li>
{% endfor %}
</ul>
"""

@app.route("/simple")
def simple_index():
    items = []
    for p in sorted([p for p in SIMPLE_UPLOAD_DIR.iterdir() if p.is_file() and p.suffix == ".enc"],
                    key=lambda x: x.name.lower()):
        original = p.stem
        items.append({"name": original, "is_image": simple_is_image(original)})
    return render_template_string(SIMPLE_INDEX_HTML, files=items)

@app.route("/simple/upload", methods=["POST"])
def simple_upload():
    if SIMPLE_KEY is None:
        abort(500, description="FILESTORE_PASSPHRASE not set.")
    f = request.files.get("file")
    if not f or f.filename == "":
        return "No file selected", 400
    original_name = secure_filename(f.filename)
    data = f.read()
    blob = simple_encrypt(data)
    enc_path = SIMPLE_UPLOAD_DIR / (original_name + ".enc")
    if enc_path.exists():
        i = 1
        base, ext = os.path.splitext(original_name)
        while True:
            candidate = SIMPLE_UPLOAD_DIR / f"{base}({i}){ext}.enc"
            if not candidate.exists():
                enc_path = candidate
                break
            i += 1
    enc_path.write_bytes(blob)
    return redirect(url_for("simple_index"))

@app.route("/simple/download/<path:filename>")
def simple_download(filename):
    if SIMPLE_KEY is None:
        abort(500, description="FILESTORE_PASSPHRASE not set.")
    safe_name = secure_filename(filename)
    enc_path = SIMPLE_UPLOAD_DIR / (safe_name + ".enc")
    if not enc_path.exists():
        abort(404)
    blob = enc_path.read_bytes()
    plaintext = simple_decrypt(blob)
    mtype, _ = mimetypes.guess_type(safe_name)
    bio = BytesIO(plaintext); bio.seek(0)
    return send_file(bio, as_attachment=True, download_name=safe_name, mimetype=mtype or "application/octet-stream")

@app.route("/simple/preview/<path:filename>")
def simple_preview(filename):
    if SIMPLE_KEY is None:
        abort(500, description="FILESTORE_PASSPHRASE not set.")
    safe_name = secure_filename(filename)
    if not simple_is_image(safe_name):
        abort(400, description="Preview only supports images.")
    enc_path = SIMPLE_UPLOAD_DIR / (safe_name + ".enc")
    if not enc_path.exists():
        abort(404)
    blob = enc_path.read_bytes()
    plaintext = simple_decrypt(blob)
    mtype, _ = mimetypes.guess_type(safe_name)
    bio = BytesIO(plaintext); bio.seek(0)
    return send_file(bio, mimetype=mtype or "application/octet-stream")

# =========================================
if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)
