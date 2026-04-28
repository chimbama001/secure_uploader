import sqlite3
import os
from pathlib import Path
from argon2 import PasswordHasher
import datetime

# Set up paths like in main.py
DATA_DIR = os.environ.get("DATA_DIR") or str(Path.cwd())
DATA_DIR = os.path.abspath(DATA_DIR)
DB_PATH = os.path.join(DATA_DIR, "files.db")

# Password hasher
ph = PasswordHasher()

# Create admin user
username = "admin"
password = "AdminPass123!"  # You can change this
role = "admin"

pw_hash = ph.hash(password)

conn = sqlite3.connect(DB_PATH)
conn.execute("PRAGMA busy_timeout=30000;")
conn.execute("PRAGMA journal_mode=WAL;")

try:
    conn.execute(
        "INSERT INTO users(username, password_hash, role, created_at) VALUES (?,?,?,?)",
        (username, pw_hash, role, datetime.datetime.utcnow().isoformat())
    )
    conn.commit()
    print("Admin user created successfully.")
    print(f"Username: {username}")
    print(f"Password: {password}")
except sqlite3.IntegrityError:
    print("Username already exists.")
finally:
    conn.close()