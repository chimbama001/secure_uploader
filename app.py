# app.py
import os
import sqlite3
import datetime
import io
import base64
import enum
from dotenv import load_dotenv
load_dotenv()
from flask import Flask, request, redirect, url_for, render_template, send_file, abort, flash, jsonify
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from crypto_utils import load_key_from_env, encrypt_bytes, decrypt_bytes

# User role enum
class UserRole(enum.Enum):
    USER = "user"
    ADMIN = "admin"

# In-memory user storage
USERS = {}

# Configuration
UPLOAD_FOLDER = "uploads"
DB_PATH = "files.db"
ALLOWED_EXTENSIONS = None  # allow all
MAX_CONTENT_LENGTH = 200 * 1024 * 1024  # 200 MB limit (adjustable)

# In-memory storage for temporary files
TEMP_FILES = {}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
app.secret_key = os.environ.get("FLASK_SECRET", os.urandom(24))

# Load encryption key from environment
ENC_KEY_B64 = os.environ.get("UPLOAD_ENC_KEY")
# if not ENC_KEY_B64:
#     raise RuntimeError("Set the UPLOAD_ENC_KEY env variable (base64-encoded 32 bytes).")
# ENCKEY = load_key_from_env(ENC_KEY_B64)

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- Database helpers ---
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
    c.execute('INSERT INTO files(orig_name, stored_name, mime, size, uploaded_at) VALUES (?,?,?,?,?)',
              (orig_name, stored_name, mime, size, datetime.datetime.utcnow().isoformat()))
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
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('DELETE FROM files WHERE id=?', (file_id,))
    conn.commit()
    conn.close()
    return True

# Helper to detect mime
def guess_mime(filename, filebytes):
    try:
        import magic
        m = magic.Magic(mime=True)
        return m.from_buffer(filebytes)
    except Exception:
        # fallback
        return "application/octet-stream"

# Routes
@app.route('/')
def index():
    roles = [role.value for role in UserRole]  # Pass roles to template
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
        enc_blob = encrypt_bytes(file_bytes, ENCKEY)
        # create stored file name
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
    stored_name = rec[2]
    mime = rec[3] or "application/octet-stream"
    orig_name = rec[1] or "download"
    path = os.path.join(app.config['UPLOAD_FOLDER'], stored_name)
    if not os.path.exists(path):
        abort(404)
    with open(path, 'rb') as fh:
        enc_blob = fh.read()
    try:
        plaintext = decrypt_bytes(enc_blob, ENCKEY)
    except Exception as e:
        abort(500, description=f"Decryption failed: {e}")
    return send_file(io.BytesIO(plaintext), download_name=orig_name, mimetype=mime, as_attachment=True)

@app.route('/preview/<int:file_id>')
def preview(file_id):
    # Use for browser image previewing (content-type set)
    rec = get_file_record(file_id)
    if not rec:
        abort(404)
    mime = rec[3] or "application/octet-stream"
    if not mime.startswith('image/'):
        return redirect(url_for('files'))
    path = os.path.join(app.config['UPLOAD_FOLDER'], rec[2])
    with open(path, 'rb') as fh:
        enc_blob = fh.read()
    try:
        plaintext = decrypt_bytes(enc_blob, ENCKEY)
    except Exception:
        abort(500)
    return send_file(io.BytesIO(plaintext), mimetype=mime)

@app.route('/delete/<int:file_id>', methods=['POST'])
def delete(file_id):
    ok = delete_file_record(file_id)
    if not ok:
        flash("File not found.")
    else:
        flash("File deleted.")
    return redirect(url_for('files'))

@app.route('/temp-upload', methods=['POST'])
def temp_upload():
    if 'file' not in request.files:
        return {'error': 'No file part'}, 400
    
    file = request.files['file']
    if file.filename == '':
        return {'error': 'No selected file'}, 400

    filename = secure_filename(file.filename)
    file_content = file.read()
    
    # Generate a unique identifier for the file
    import uuid
    file_id = str(uuid.uuid4())
    
    # Store file in memory
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
    
    file_data = TEMP_FILES[file_id]
    return send_file(
        io.BytesIO(file_data['content']),
        download_name=file_data['filename'],
        mimetype=file_data['mime']
    )

@app.route('/temp-file/<file_id>', methods=['DELETE'])
def delete_temp_file(file_id):
    if file_id not in TEMP_FILES:
        return {'error': 'File not found'}, 404
    
    del TEMP_FILES[file_id]
    return {'message': 'File deleted successfully'}

@app.route('/add-user')
def add_user_form():
    roles = [role.value for role in UserRole]
    return render_template('add_user.html', roles=roles)

@app.route('/users', methods=['GET', 'POST'])
def users():
    if request.method == 'POST':
        # Get user data from request
        data = request.json
        if not data:
            return {'error': 'No data provided'}, 400
        
        username = data.get('username')
        password = data.get('password')
        role = data.get('role', 'user')  # Default to user role if not specified
        
        # Validate required fields
        if not username or not password:
            return {'error': 'Username and password are required'}, 400
            
        # Check if username already exists
        if username in USERS:
            return {'error': 'Username already exists'}, 400
            
        # Validate role
        try:
            user_role = UserRole(role.lower())
        except ValueError:
            return {'error': 'Invalid role. Must be either "user" or "admin"'}, 400
        
        # Create user object
        user = {
            'username': username,
            'password_hash': generate_password_hash(password),
            'role': user_role.value,
            'created_at': datetime.datetime.utcnow().isoformat()
        }
        
        # Store user in memory
        USERS[username] = user
        
        # Return success response (without password hash)
        response_user = user.copy()
        del response_user['password_hash']
        return jsonify(response_user), 201
        
    # GET method - return list of users
    return jsonify({
        'users': [
            {
                'username': username,
                'role': user_data['role'],
                'created_at': user_data['created_at']
            }
            for username, user_data in USERS.items()
        ]
    })

@app.route('/users/<username>', methods=['GET'])
def get_user(username):
    user = USERS.get(username)
    if not user:
        return {'error': 'User not found'}, 404
        
    # Return user info without password hash
    response_user = user.copy()
    del response_user['password_hash']
    return jsonify(response_user)

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='127.0.0.1', port=5000)

