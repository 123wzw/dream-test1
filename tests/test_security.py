"""VaultDocs 安全攻击复现测试。

每个用例对应一个已确认的漏洞：修复前必须失败，修复后必须通过。
不修改任何公开接口（路由、请求/响应字段名）。
"""

import base64
import json
import os
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix="vaultdocs-sec-test-")
# 与 test_functional.py 同进程运行时复用其环境；单独运行时自建环境。
os.environ.setdefault("VAULT_DB", os.path.join(_TMP, "vault.db"))
os.environ.setdefault("VAULT_UPLOAD_DIR", os.path.join(_TMP, "uploads"))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import db, storage  # noqa: E402
from app.main import app  # noqa: E402

client = TestClient(app)


def _login(email: str, password: str) -> str:
    resp = client.post("/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()["token"]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


# ---------- 1. JWT alg=none 签名绕过 ----------


def test_jwt_alg_none_forgery_rejected():
    """伪造 alg=none 的 admin token，不应通过鉴权。"""
    header = _b64e(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = _b64e(
        json.dumps(
            {
                "sub": 1,
                "email": "alice@example.com",
                "role": "admin",
                "exp": int(time.time()) + 3600,
            }
        ).encode()
    )
    forged = f"{header}.{payload}."  # 空签名
    resp = client.get("/documents/1", headers=_auth(forged))
    assert resp.status_code == 401


def test_jwt_tampered_payload_rejected():
    """合法 token 篡改 payload（提权为 admin）后必须失效。"""
    token = _login("bob@example.com", "bob-pass")
    head, _, sig = token.split(".")
    payload = _b64e(
        json.dumps(
            {
                "sub": 2,
                "email": "bob@example.com",
                "role": "admin",
                "exp": int(time.time()) + 3600,
            }
        ).encode()
    )
    forged = f"{head}.{payload}.{sig}"
    resp = client.get("/documents/1", headers=_auth(forged))
    assert resp.status_code == 401


# ---------- 2. 搜索接口 SQL 注入 ----------


def test_search_sql_injection_blocked():
    """布尔盲注 payload 不应被当作 SQL 执行。"""
    token = _login("alice@example.com", "alice-pass")
    resp = client.get(
        "/documents/search", params={"q": "' OR '1'='1"}, headers=_auth(token)
    )
    assert resp.status_code == 200
    # 注入成功时会返回全部文档；修复后该字面量匹配不到任何文档
    assert resp.json()["items"] == []


def test_search_sql_injection_union_blocked():
    """UNION 注入不应把 users 表的口令哈希带出来。"""
    token = _login("alice@example.com", "alice-pass")
    payload = "' UNION SELECT id, email, password_hash, role FROM users--"
    resp = client.get("/documents/search", params={"q": payload}, headers=_auth(token))
    assert resp.status_code == 200
    assert resp.json()["items"] == []


# ---------- 3. 附件上传路径穿越（任意文件写） ----------


def test_upload_path_traversal_blocked():
    token = _login("alice@example.com", "alice-pass")
    outside = Path(storage.upload_dir()).parent / "pwned-upload.txt"
    if outside.exists():
        outside.unlink()
    resp = client.post(
        "/files",
        json={"name": "../pwned-upload.txt", "content": "pwned"},
        headers=_auth(token),
    )
    assert resp.status_code == 400
    assert not outside.exists()


# ---------- 4. 附件下载路径穿越（任意文件读） ----------


def test_download_path_traversal_blocked():
    token = _login("alice@example.com", "alice-pass")
    secret = Path(storage.upload_dir()).parent / "topsecret.txt"
    secret.write_text("TOP-SECRET-DATA", encoding="utf-8")
    try:
        # 客户端会规范化裸 ".."，攻击者实际使用百分号编码绕过
        resp = client.get(f"/files/%2e%2e%2f{secret.name}", headers=_auth(token))
        assert resp.status_code in (400, 404)
        assert "TOP-SECRET-DATA" not in resp.text
    finally:
        secret.unlink()


def test_storage_read_file_traversal_blocked():
    """存储层直接调用也必须拒绝逃逸 upload 目录的名字。"""
    secret = Path(storage.upload_dir()).parent / "topsecret2.txt"
    secret.write_text("TOP-SECRET-DATA-2", encoding="utf-8")
    try:
        with pytest.raises(ValueError):
            storage.read_file(f"../{secret.name}")
    finally:
        secret.unlink()


# ---------- 5. Webhook 预览 SSRF ----------


def test_preview_rejects_file_scheme(tmp_path):
    """file:// 不应可读本地文件。"""
    secret = tmp_path / "local-secret.txt"
    secret.write_text("INTERNAL-SECRET", encoding="utf-8")
    token = _login("alice@example.com", "alice-pass")
    resp = client.post(
        "/webhooks/preview", json={"url": secret.as_uri()}, headers=_auth(token)
    )
    assert resp.status_code == 502
    assert "INTERNAL-SECRET" not in resp.text


def test_preview_rejects_loopback_target():
    """内网/回环地址不应被访问（本地起服务验证）。"""
    secret_body = b"INTERNAL-SECRET"

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(secret_body)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/"
        token = _login("alice@example.com", "alice-pass")
        resp = client.post("/webhooks/preview", json={"url": url}, headers=_auth(token))
        assert resp.status_code == 502
        assert "INTERNAL-SECRET" not in resp.text
    finally:
        server.shutdown()
        thread.join()


# ---------- 6. 文档读取越权（IDOR） ----------


def test_document_read_idor_blocked():
    """bob 不应读到 alice 的文档（seed 文档 id=1 属于 alice）。"""
    bob = _login("bob@example.com", "bob-pass")
    resp = client.get("/documents/1", headers=_auth(bob))
    assert resp.status_code == 403


def test_document_read_owner_and_admin_allowed():
    """属主与管理员读取不受影响。"""
    bob = _login("bob@example.com", "bob-pass")
    resp = client.get("/documents/2", headers=_auth(bob))  # bob 自己的文档
    assert resp.status_code == 200
    assert resp.json()["title"] == "Bob notes"

    alice = _login("alice@example.com", "alice-pass")
    resp = client.get("/documents/2", headers=_auth(alice))  # admin 可读
    assert resp.status_code == 200


# ---------- 7. 搜索接口越权返回他人文档 ----------


def test_search_hides_other_users_documents():
    """普通用户搜索不应看到他人文档；admin 仍可见全部。"""
    bob = _login("bob@example.com", "bob-pass")
    resp = client.get("/documents/search", params={"q": ""}, headers=_auth(bob))
    assert resp.status_code == 200
    titles = [item["title"] for item in resp.json()["items"]]
    assert "Q4 Roadmap" not in titles
    assert "Bob notes" in titles

    alice = _login("alice@example.com", "alice-pass")
    resp = client.get("/documents/search", params={"q": ""}, headers=_auth(alice))
    titles = [item["title"] for item in resp.json()["items"]]
    assert "Q4 Roadmap" in titles


# ---------- 8. 口令弱哈希（无盐 SHA-256） ----------


def test_passwords_stored_with_salted_kdf():
    """数据库中的口令哈希必须是带盐的 KDF 输出，而非裸 SHA-256。"""
    conn = db.connect()
    try:
        rows = conn.execute("SELECT password_hash FROM users").fetchall()
    finally:
        conn.close()
    assert rows, "users 表不应为空"
    for row in rows:
        stored = row["password_hash"]
        assert stored.startswith("pbkdf2$"), f"弱口令哈希: {stored}"
        # 裸 SHA-256 是 64 位十六进制；salt 必须存在且两条记录不同
    salts = {row["password_hash"].split("$")[2] for row in rows}
    assert len(salts) == len(rows), "每个用户必须使用独立的随机盐"
