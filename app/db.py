import os
import sqlite3
from flask import current_app

SCHEMA = '''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS personal_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    aes_data BLOB NOT NULL,
    des_data BLOB NOT NULL,
    rc4_data BLOB NOT NULL,
    aes_iv BLOB NOT NULL,
    des_iv BLOB NOT NULL,
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
    db = get_db()
    db.executescript(SCHEMA)
    db.commit()
    db.close()
