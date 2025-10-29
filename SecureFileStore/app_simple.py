from flask import Flask, request, redirect, url_for, render_template_string, send_file, abort
from werkzeug.utils import secure_filename
from pathlib import Path
from io import BytesIO
import mimetypes, os, secrets

# --- Key derivation (scrypt) + AES-GCM ---
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)
UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # ~50MB

# Load passphrase from env
PASSPHRASE = os.environ.get("FILESTORE_PASSPHRASE")
if not PASSPHRASE:
    raise RuntimeError("Set FILESTORE_PASSPHRASE environment variable before running.")

SALT_PATH = Path("kdf_salt.bin")
if not SALT_PATH.exists():
    SALT_PATH.write_bytes(secrets.token_bytes(16))
SALT = SALT_PATH.read_bytes()

def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(passphrase.encode())

KEY = derive_key(PASSPHRASE, SALT)  # 32 bytes (AES-256)

def encrypt_bytes(plaintext: bytes) -> bytes:
    nonce = secrets.token_bytes(12)           # 96-bit nonce for GCM
    aes = AESGCM(KEY)
    ct = aes.encrypt(nonce, plaintext, None)  # AAD=None
    return nonce + ct                          # store nonce || ciphertext(tag+data)

def decrypt_blob(blob: bytes) -> bytes:
    nonce, ct = blob[:12], blob[12:]
    aes = AESGCM(KEY)
    return aes.decrypt(nonce, ct, None)

def is_image(filename: str) -> bool:
    mtype, _ = mimetypes.guess_type(filename)
    return (mtype or "").startswith("image/")

INDEX_HTML = """
<!doctype html>
<title>Secure Uploader (AES-256-GCM)</title>
<h1>Upload any file (encrypted on disk)</h1>
<form method="post" enctype="multipart/form-data" action="/upload">
  <input type="file" name="file" />
  <button type="submit">Upload</button>
</form>
<hr>
<h2>Files (stored as .enc)</h2>
<ul>
{% for f in files %}
  <li style="margin-bottom:14px;">
    <a href="/download/{{f.name}}">{{f.name}}</a>
    {% if f.is_image %}
      <div>
        <img src="/preview/{{f.name}}" alt="{{f.name}}" style="max-width:320px; height:auto; margin-top:6px; border:1px solid #ddd; padding:2px; border-radius:6px;">
      </div>
    {% endif %}
  </li>
{% endfor %}
</ul>
"""

@app.route("/")
def index():
    items = []
    # list *.enc files and show original names (strip .enc)
    for p in sorted([p for p in UPLOAD_DIR.iterdir() if p.is_file() and p.suffix == ".enc"], key=lambda x: x.name.lower()):
        original = p.stem  # filename without .enc
        items.append({"name": original, "is_image": is_image(original)})
    return render_template_string(INDEX_HTML, files=items)

@app.route("/upload", methods=["POST"])
def upload():
    f = request.files.get("file")
    if not f or f.filename == "":
        return "No file selected", 400
    original_name = secure_filename(f.filename)
    if not original_name:
        return "Invalid filename", 400

    data = f.read()
    blob = encrypt_bytes(data)
    # save as "<original>.enc"
    enc_path = UPLOAD_DIR / (original_name + ".enc")
    # avoid accidental overwrite: if exists, add a suffix
    if enc_path.exists():
        base, ext = original_name, ""
        if "." in original_name:
            base = ".".join(original_name.split(".")[:-1])
            ext = "." + original_name.split(".")[-1]
        i = 1
        while True:
            candidate = UPLOAD_DIR / (f"{base}({i}){ext}.enc")
            if not candidate.exists():
                enc_path = candidate
                break
            i += 1

    enc_path.write_bytes(blob)
    return redirect(url_for("index"))

@app.route("/download/<path:filename>")
def download(filename):
    # encrypted file is stored as "<filename>.enc"
    safe_name = secure_filename(filename)
    enc_path = UPLOAD_DIR / (safe_name + ".enc")
    if not enc_path.exists():
        abort(404)
    blob = enc_path.read_bytes()
    try:
        plaintext = decrypt_blob(blob)
    except Exception as e:
        abort(500, description=f"Decryption failed: {e}")

    mtype, _ = mimetypes.guess_type(safe_name)
    bio = BytesIO(plaintext); bio.seek(0)
    return send_file(bio, as_attachment=True, download_name=safe_name, mimetype=mtype or "application/octet-stream")

@app.route("/preview/<path:filename>")
def preview(filename):
    # only for images; decrypted inline
    safe_name = secure_filename(filename)
    if not is_image(safe_name):
        abort(400, description="Preview only supports images.")
    enc_path = UPLOAD_DIR / (safe_name + ".enc")
    if not enc_path.exists():
        abort(404)
    blob = enc_path.read_bytes()
    try:
        plaintext = decrypt_blob(blob)
    except Exception as e:
        abort(500, description=f"Decryption failed: {e}")

    mtype, _ = mimetypes.guess_type(safe_name)
    bio = BytesIO(plaintext); bio.seek(0)
    return send_file(bio, mimetype=mtype or "application/octet-stream")

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
