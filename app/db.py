import hashlib
import os
import secrets
import sqlite3
from flask import current_app

SCHEMA = '''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    role TEXT DEFAULT 'candidate'
);

CREATE TABLE IF NOT EXISTS personal_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    aes_data BLOB NOT NULL,
    des_data BLOB NOT NULL,
    rc4_data BLOB NOT NULL,
    aes_iv BLOB NOT NULL,
    des_iv BLOB NOT NULL,
    aes_key BLOB,
    des_key BLOB,
    rc4_key BLOB,
    passphrase_salt BLOB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    original_name TEXT NOT NULL,
    mime_type TEXT,
    aes_path TEXT NOT NULL,
    des_path TEXT NOT NULL,
    rc4_path TEXT NOT NULL,
    aes_iv BLOB NOT NULL,
    des_iv BLOB NOT NULL,
    aes_key BLOB,
    des_key BLOB,
    rc4_key BLOB,
    passphrase_salt BLOB,
    original_size INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
'''

def get_db():
    db = sqlite3.connect(current_app.config["DATABASE"])
    db.row_factory = sqlite3.Row
    return db

def init_db():
    from .crypto import DEFAULT_AES_KEY, DEFAULT_DES_KEY, DEFAULT_RC4_KEY
    db = get_db()
    db.executescript(SCHEMA)

    # Migrate columns if missing in existing tables
    user_cols = [row["name"] for row in db.execute("PRAGMA table_info(users)").fetchall()]
    if "role" not in user_cols:
        db.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'candidate'")
    db.execute("UPDATE users SET role = 'candidate' WHERE role IS NULL")

    for table in ("personal_data", "files"):
        columns = [row["name"] for row in db.execute(f"PRAGMA table_info({table})").fetchall()]
        for col in ("aes_key", "des_key", "rc4_key", "passphrase_salt"):
            if col not in columns:
                db.execute(f"ALTER TABLE {table} ADD COLUMN {col} BLOB")
        db.execute(f"UPDATE {table} SET aes_key = ? WHERE aes_key IS NULL", (DEFAULT_AES_KEY,))
        db.execute(f"UPDATE {table} SET des_key = ? WHERE des_key IS NULL", (DEFAULT_DES_KEY,))
        db.execute(f"UPDATE {table} SET rc4_key = ? WHERE rc4_key IS NULL", (DEFAULT_RC4_KEY,))

    # Seed demo HRD account if not exists
    existing_hrd = db.execute("SELECT id FROM users WHERE username = 'hrd_recruiter'").fetchone()
    if not existing_hrd:
        salt = secrets.token_bytes(16)
        pwd_hash = hashlib.pbkdf2_hmac("sha256", b"hrd12345", salt, 200_000)
        db.execute(
            "INSERT INTO users (username, password_hash, password_salt, role) VALUES (?, ?, ?, ?)",
            ("hrd_recruiter", pwd_hash.hex(), salt.hex(), "hrd")
        )

    db.commit()
    db.close()
