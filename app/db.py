"""SQLite 访问层。"""

import hashlib
import hmac
import os
import secrets
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

_PBKDF2_ITERATIONS = 200_000


def hash_password(password: str) -> str:
    """带随机盐的 PBKDF2-HMAC-SHA256，格式 pbkdf2$iterations$salt$digest。"""
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt), _PBKDF2_ITERATIONS
    ).hex()
    return f"pbkdf2${_PBKDF2_ITERATIONS}${salt}${digest}"


def verify_password(password: str, stored: str) -> bool:
    if stored.startswith("pbkdf2$"):
        try:
            _, iterations, salt, digest = stored.split("$")
            candidate = hashlib.pbkdf2_hmac(
                "sha256", password.encode("utf-8"), bytes.fromhex(salt), int(iterations)
            ).hex()
        except (ValueError, TypeError):
            return False
        return hmac.compare_digest(candidate, digest)
    # 兼容旧库里的无盐 SHA-256 记录（仅用于校验，新口令一律走 PBKDF2）
    legacy = hashlib.sha256(password.encode("utf-8")).hexdigest()
    return hmac.compare_digest(legacy, stored)


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


def search_documents(term: str, owner_id: int, is_admin: bool = False):
    """关键词检索。普通用户只能搜到自己的文档，管理员可见全部。"""
    like = f"%{term}%"
    conn = connect()
    try:
        if is_admin:
            return conn.execute(
                "SELECT id, owner_id, title, body FROM documents "
                "WHERE title LIKE ? OR body LIKE ?",
                (like, like),
            ).fetchall()
        return conn.execute(
            "SELECT id, owner_id, title, body FROM documents "
            "WHERE (title LIKE ? OR body LIKE ?) AND owner_id = ?",
            (like, like, owner_id),
        ).fetchall()
    finally:
        conn.close()
