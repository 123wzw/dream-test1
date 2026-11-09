"""SQLite 访问层。"""

import hashlib
import os
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def db_path() -> str:
    return os.environ.get("VAULT_DB", str(BASE_DIR / "vault.db"))


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(db_path())
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = connect()
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user'
            );

            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                body TEXT NOT NULL,
                classification TEXT NOT NULL DEFAULT 'internal'
            );
            """
        )
        if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            conn.execute(
                "INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)",
                ("alice@example.com", hash_password("alice-pass"), "admin"),
            )
            conn.execute(
                "INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)",
                ("bob@example.com", hash_password("bob-pass"), "user"),
            )
            conn.execute(
                "INSERT INTO documents (owner_id, title, body, classification) VALUES (?, ?, ?, ?)",
                (1, "Q4 Roadmap", "internal roadmap, do not share", "internal"),
            )
            conn.execute(
                "INSERT INTO documents (owner_id, title, body, classification) VALUES (?, ?, ?, ?)",
                (2, "Bob notes", "bob private notes", "private"),
            )
            conn.commit()
    finally:
        conn.close()


def get_user_by_email(email: str):
    conn = connect()
    try:
        return conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    finally:
        conn.close()


def create_document(owner_id: int, title: str, body: str, classification: str) -> int:
    conn = connect()
    try:
        cur = conn.execute(
            "INSERT INTO documents (owner_id, title, body, classification) VALUES (?, ?, ?, ?)",
            (owner_id, title, body, classification),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def get_document(doc_id: int):
    conn = connect()
    try:
        return conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
    finally:
        conn.close()


def search_documents(term: str):
    conn = connect()
    try:
        query = (
            "SELECT id, owner_id, title, body FROM documents "
            f"WHERE title LIKE '%{term}%' OR body LIKE '%{term}%'"
        )
        return conn.execute(query).fetchall()
    finally:
        conn.close()
